# Executa a bateria completa de testes do experimento em um único fluxo:
#
#   3 cenários × 5 ataques × N repetições × DURATION s
#     ├── baseline     (sem segurança)              → cenario1-baseline/run_scenario1.sh
#     ├── cenário 2    (Firewall/Allowlist)         → cenario2-firewall/run_scenario2.sh
#     └── cenário 3    (SecOC simplificado)         → cenario3-secoc/run_scenario3.sh
#

set -euo pipefail
export LC_NUMERIC=C

DURATION=30                                      # s por rodada
REPS=20                                          # repetições por (cenário, ataque)
COOLDOWN=5                                       # s entre rodadas
ATTACKS_BASELINE="dos-py dos-cangen fuzzing replay spoofing"
ATTACKS_GATEWAY="dos-py dos-cangen fuzzing replay spoofing"   # nomes aceitos pelos run_scenarioN.sh
SCENARIOS="baseline cen2 cen3"                   # cenários a rodar
USE_ICSIM=1                                      # 1=sim, 0=não
REPLAY_RECORD_TIME=30                            # s de captura prévia para replay

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ATAQUES_DIR="$HERE/../scripts-attacks"
CEN1_DIR="$HERE/../scenario1-baseline"
CEN2_DIR="$HERE/../scenario2-firewall"
CEN3_DIR="$HERE/../scenario3-secoc"
ICSIM_DIR="$HERE/../" 

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
RESULTS_ROOT="$HERE/master_results/$TIMESTAMP"
MASTER_LOG="$RESULTS_ROOT/master_log.txt"
SYSINFO="$RESULTS_ROOT/sysinfo.txt"
REPLAY_LOG="$RESULTS_ROOT/replay_capture.log"
export REPLAY_LOG
REPLAY_LOG_CEN3="$RESULTS_ROOT/replay_capture_cen3.log"
export REPLAY_LOG_CEN3

# CSV unificado da bateria
PERF_DATA_CSV="$RESULTS_ROOT/perf_data.csv"
export PERF_DATA_CSV

# Helper compartilhado
. "$HERE/../lib/perf_csv.sh"
. "$HERE/../lib/governor.sh"

# PIDs de processos em background (preenchidos durante a execução)
ICSIM_PID=""
CONTROLS_PID=""

# HELPERS
usage() {
    cat <<EOF
Uso: sudo $0 [opções]

Opções:
  -n NUM         Número de repetições por ataque/cenário (default: $REPS)
  -d SEC         Duração de cada rodada em segundos (default: $DURATION)
  -c SEC         Cooldown entre rodadas em segundos (default: $COOLDOWN)
  -s LISTA       Cenários a rodar, separados por vírgula
                 (opções: baseline, cen2, cen3 — default: todos)
  -a LISTA       Ataques baseline (default: $ATTACKS_BASELINE)
                 (para cen2/cen3, a lista equivalente é derivada)
  --no-icsim     Não inicia ICSim/controls (modo headless / sem display)
EOF
    exit 0
}

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $*"
    echo "$msg"
    [[ -n "${MASTER_LOG:-}" && -d "$(dirname "$MASTER_LOG")" ]] \
        && echo "$msg" >> "$MASTER_LOG"
}

die() {
    log "[ERRO] $*"
    exit 1
}

# PARSING DE ARGUMENTOS
while [[ $# -gt 0 ]]; do
    case "$1" in
        -n) REPS="$2"; shift 2 ;;
        -d) DURATION="$2"; shift 2 ;;
        -c) COOLDOWN="$2"; shift 2 ;;
        -s) SCENARIOS="${2//,/ }"; shift 2 ;;
        -a) ATTACKS_BASELINE="${2//,/ }"; shift 2 ;;
        --no-icsim) USE_ICSIM=0; shift ;;
        *) echo "[erro] opção desconhecida: $1" >&2; usage ;;
    esac
done

# VALIDAÇÕES
require_root() {
    [[ "$EUID" -eq 0 ]] || die "este script precisa de sudo (perf + ip link)."
}

check_prereqs() {
    local missing=()
    command -v perf    >/dev/null 2>&1 || missing+=("perf")
    command -v python3 >/dev/null 2>&1 || missing+=("python3")
    command -v cangen  >/dev/null 2>&1 || missing+=("cangen (can-utils)")
    command -v candump >/dev/null 2>&1 || missing+=("candump (can-utils)")
    [[ ${#missing[@]} -eq 0 ]] || die "dependências ausentes: ${missing[*]}"

    [[ -x "$CEN1_DIR/run_passthrough.sh" ]] \
        || die "$CEN1_DIR/run_passthrough.sh não é executável"
    [[ -x "$CEN2_DIR/run_scenario2.sh" ]] \
        || die "$CEN2_DIR/run_scenario2.sh não é executável"
    [[ -x "$CEN3_DIR/run_scenario3.sh" ]] \
        || die "$CEN3_DIR/run_scenario3.sh não é executável"

    for s in $SCENARIOS; do
        case "$s" in
            baseline)
                [[ -x "$CEN1_DIR/passthrough" ]] \
                    || die "binário ausente: $CEN1_DIR/passthrough (rode 'make -f experiments.mk cen1')"
                ;;
            cen2)
                [[ -x "$CEN2_DIR/gateway" ]] \
                    || die "binário ausente: $CEN2_DIR/gateway (rode 'make' em $CEN2_DIR)"
                ;;
            cen3)
                [[ -x "$CEN3_DIR/secoc_sender"  ]] \
                    || die "binário ausente: $CEN3_DIR/secoc_sender"
                [[ -x "$CEN3_DIR/secoc_gateway" ]] \
                    || die "binário ausente: $CEN3_DIR/secoc_gateway"
                ;;
            *) die "cenário desconhecido: $s (use baseline, cen2 ou cen3)" ;;
        esac
    done

    if [[ "$USE_ICSIM" -eq 1 ]]; then
        if [[ ! -x "$ICSIM_DIR/icsim" || ! -x "$ICSIM_DIR/controls" ]]; then
            log "[AVISO] ICSim/controls não compilados em $ICSIM_DIR — continuando sem ICSim."
            USE_ICSIM=0
        fi
        if [[ -z "${DISPLAY:-}" && "$USE_ICSIM" -eq 1 ]]; then
            log "[AVISO] DISPLAY não definido — ICSim é gráfico. Forçando --no-icsim."
            USE_ICSIM=0
        fi
    fi
}

# SYSINFO
collect_sysinfo() {
    {
        echo "===================================================================="
        echo " Análise do Custo Computacional de Segurança em CAN: Bateria Completa de Testes"
        echo "===================================================================="
        echo
        echo "=== Tempo ==="
        echo "Início: $(date -Iseconds)"
        echo
        echo "=== Sistema ==="
        echo "Hostname : $(hostname)"
        echo "Kernel   : $(uname -srm)"
        echo "Distro   : $(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || echo 'N/A')"
        echo "CPU      : $(lscpu | awk -F: '/Model name/{gsub(/^ +/,"",$2); print $2; exit}')"
        echo "Cores    : $(nproc)"
        echo "Frequência : $(lscpu | awk -F: '/CPU max MHz/{gsub(/^ +/,"",$2); print $2 " MHz"; exit}')"
        echo "RAM      : $(free -h | awk '/^Mem:/ {print $2}')"
        echo "Governor : $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo 'N/A')"
        echo
        echo "=== Versões ==="
        echo "perf       : $(perf --version 2>&1)"
        echo "python3    : $(python3 --version 2>&1)"
        echo "python-can : $(python3 -c 'import can; print(can.__version__)' 2>&1 || echo 'N/A')"
        echo "can-utils  : $(dpkg -l can-utils 2>/dev/null | awk '/^ii/ {print $3}' || echo 'N/A')"
        echo "gcc        : $(gcc --version | head -1 2>&1 || echo 'N/A')"
        echo
        echo "=== Parâmetros da Bateria ==="
        echo "Repetições por (cenário, ataque) : $REPS"
        echo "Duração por rodada              : ${DURATION}s"
        echo "Cooldown entre rodadas          : ${COOLDOWN}s"
        echo "Cenários                        : $SCENARIOS"
        echo "Ataques (baseline)              : $ATTACKS_BASELINE"
        echo "Ataques (gateway)               : $ATTACKS_GATEWAY"
        echo "ICSim em background             : $([[ $USE_ICSIM -eq 1 ]] && echo sim || echo não)"
        echo "Replay record-time              : ${REPLAY_RECORD_TIME}s"
        echo
        echo "=== Custo total estimado ==="
        local n_attacks
        n_attacks=$(echo "$ATTACKS_BASELINE" | wc -w)
        local n_scen
        n_scen=$(echo "$SCENARIOS" | wc -w)
        local total_runs=$(( n_scen * n_attacks * REPS ))
        local total_time=$(( total_runs * (DURATION + COOLDOWN) ))
        printf "Rodadas totais : %d\n" "$total_runs"
        printf "Tempo bruto    : %d s ≈ %.1f min ≈ %.2f h\n" \
            "$total_time" "$(echo "$total_time/60" | bc -l)" \
            "$(echo "$total_time/3600" | bc -l)"
    } > "$SYSINFO"
    log "Sysinfo salvo em $SYSINFO"
}

# ICSIM (tráfego legítimo de fundo)
# Topologia por cenário — apples-to-apples entre os três:
#   baseline : icsim em vcan1          ; controls em vcan0   (atrás do passthrough)
#   cen2     : icsim em vcan1          ; controls em vcan0   (atrás do gateway)
#   cen3     : icsim em vcan1          ; controls em vcan_trust (atrás do sender+gateway)
#
# A escolha do baseline aqui mudou em relação à versão antiga (icsim+controls
# em vcan0): o forwarder transparente (passthrough) precisa enxergar tráfego
# em vcan0 e entregar em vcan1, replicando o caminho lógico dos cenários 2 e 3.
start_icsim_for() {
    local scenario="$1"
    [[ "$USE_ICSIM" -eq 1 ]] || return 0

    local icsim_iface controls_iface
    case "$scenario" in
        baseline) icsim_iface="vcan1" ; controls_iface="vcan0" ;;
        cen2)     icsim_iface="vcan1" ; controls_iface="vcan0" ;;
        cen3)     icsim_iface="vcan1" ; controls_iface="vcan_trust" ;;
        *) return 0 ;;
    esac

    log "  [icsim] iniciando icsim($icsim_iface) + controls($controls_iface)"
    ( cd "$ICSIM_DIR" && exec ./icsim "$icsim_iface" ) >/dev/null 2>&1 &
    ICSIM_PID=$!
    sleep 0.3
    ( cd "$ICSIM_DIR" && exec ./controls "$controls_iface" ) >/dev/null 2>&1 &
    CONTROLS_PID=$!
    sleep 0.5

    if ! kill -0 "$ICSIM_PID" 2>/dev/null; then
        log "  [AVISO] icsim morreu — seguindo sem tráfego de fundo."
        ICSIM_PID=""
    fi
    if ! kill -0 "$CONTROLS_PID" 2>/dev/null; then
        log "  [AVISO] controls morreu — seguindo sem tráfego de fundo."
        CONTROLS_PID=""
    fi
}

stop_icsim() {
    [[ -n "${CONTROLS_PID:-}" ]] && kill "$CONTROLS_PID" 2>/dev/null || true
    [[ -n "${ICSIM_PID:-}"    ]] && kill "$ICSIM_PID"    2>/dev/null || true
    wait "${CONTROLS_PID:-}" 2>/dev/null || true
    wait "${ICSIM_PID:-}"    2>/dev/null || true
    CONTROLS_PID=""
    ICSIM_PID=""
}

# SETUP DE INTERFACES CAN
# Sobe vcan0, vcan1 e vcan_trust uma única vez (suficiente para os 3 cenários).
setup_vcans() {
    log "Preparando interfaces virtuais (vcan0, vcan1, vcan_trust)…"
    modprobe can  2>/dev/null || true
    modprobe vcan
    for iface in vcan0 vcan1 vcan_trust; do
        if ip link show "$iface" >/dev/null 2>&1; then
            ip link set up "$iface" 2>/dev/null || true
        else
            ip link add dev "$iface" type vcan
            ip link set up "$iface"
        fi
    done
    ip -br link show type vcan | tee -a "$MASTER_LOG" >/dev/null
}

# CAPTURA DO REPLAY
# Captura uma única vez tráfego legítimo (com ICSim+controls ativos) em vcan0.
# Esse log é reutilizado pelos três cenários para o ataque de replay
ensure_replay_capture() {
    if echo "$ATTACKS_BASELINE" | grep -qw replay; then
        if [[ ! -s "$REPLAY_LOG" ]]; then
            log "Capturando ${REPLAY_RECORD_TIME}s de tráfego legítimo em vcan0 para o replay…"
            start_icsim_for baseline
            python3 "$ATAQUES_DIR/Replay-attack.py" record \
                --iface vcan0 \
                --out   "$REPLAY_LOG" \
                --record-time "$REPLAY_RECORD_TIME" \
                >>"$MASTER_LOG" 2>&1 || true
            stop_icsim
            local n
            n="$(grep -c '^(' "$REPLAY_LOG" 2>/dev/null || echo 0)"
            log "Captura concluída: $n frames em $REPLAY_LOG"
        else
            log "Reutilizando captura existente: $REPLAY_LOG"
        fi
        # O run_scenario1.sh espera o arquivo em ataques/captura_replay.log.
        ln -sfn "$REPLAY_LOG" "$ATAQUES_DIR/captura_replay.log"
    fi
}

# Captura específica para cen3: sobe sender + controls (em vcan_trust)
ensure_replay_capture_cen3() {
    echo "$ATTACKS_GATEWAY" | grep -qw replay || return 0
    [[ " $SCENARIOS " == *" cen3 "* ]] || return 0
    if [[ -s "$REPLAY_LOG_CEN3" ]]; then
        log "Reutilizando captura cen3 existente: $REPLAY_LOG_CEN3"
        return 0
    fi

    log "Capturando 3s de frames autenticados em vcan0 (sender + controls em vcan_trust)…"
    "$CEN3_DIR/secoc_sender" -i vcan_trust -o vcan0 \
        >>"$MASTER_LOG" 2>&1 &
    local SENDER_PID=$!
    sleep 0.3
    if ! kill -0 "$SENDER_PID" 2>/dev/null; then
        warn "secoc_sender não subiu — cen3 replay vai cair no fallback intra-rodada."
        return 0
    fi

    local prev_use_icsim="$USE_ICSIM"
    start_icsim_for cen3   # icsim em vcan1, controls em vcan_trust
    USE_ICSIM="$prev_use_icsim"

    python3 "$ATAQUES_DIR/Replay-attack.py" record \
        --iface vcan0 \
        --out   "$REPLAY_LOG_CEN3" \
        --record-time 3 \
        >>"$MASTER_LOG" 2>&1 || true

    stop_icsim
    kill "$SENDER_PID" 2>/dev/null || true
    wait "$SENDER_PID" 2>/dev/null || true

    local n
    n="$(grep -c '^(' "$REPLAY_LOG_CEN3" 2>/dev/null || echo 0)"
    log "Captura cen3 concluída: $n frames em $REPLAY_LOG_CEN3"
    if [[ "$n" -lt 20 ]]; then
        warn "captura cen3 com $n frames (<20) — fallback intra-rodada será usado."
        : > "$REPLAY_LOG_CEN3"   # esvazia para que run_scenario3 use fallback
    fi
}


# EXECUÇÃO POR CENÁRIO

# Cenário 1: baseline (sem segurança) — passthrough vcan0 -> vcan1
#
# Loop análogo a run_cenario2/run_cenario3: cada rodada chama
# run_passthrough.sh que sobe o forwarder transparente, anexa perf nele
# e dispara o ataque. Substitui o antigo run_scenario1.sh, que anexava
# perf ao próprio atacante (Python/cangen) e produzia comparação injusta
# com gateway/sender.
run_baseline() {
    log ""
    log "============================================================"
    log "  CENÁRIO 1 — BASELINE (passthrough sem segurança)"
    log "============================================================"

    start_icsim_for baseline

    local logs_root="$RESULTS_ROOT/baseline/runs"
    mkdir -p "$logs_root"

    local total_runs count
    total_runs=$(( $(echo "$ATTACKS_BASELINE" | wc -w) * REPS ))
    count=0

    for attack in $ATTACKS_BASELINE; do
        log ""
        log "--- baseline/$attack — $REPS repetições de ${DURATION}s ---"
        for run in $(seq 1 "$REPS"); do
            count=$(( count + 1 ))
            log "  [$count/$total_runs] baseline / $attack / rep $(printf '%02d' "$run")"

            (
                cd "$CEN1_DIR"
                RUN_INDEX="$run" ./run_passthrough.sh "$attack" "$DURATION"
            ) >>"$MASTER_LOG" 2>&1 || log "  [AVISO] rep $run de $attack falhou — continuando"

            local last_dir
            last_dir="$(ls -1dt "$CEN1_DIR/results/"*"-${attack}" 2>/dev/null | head -1 || true)"
            if [[ -n "$last_dir" && -d "$last_dir" ]]; then
                local target="$logs_root/${attack}_run$(printf '%02d' "$run")"
                mv "$last_dir" "$target"
            fi

            [[ "$run" -lt "$REPS" ]] && sleep "$COOLDOWN"
        done
        sleep "$COOLDOWN"
    done

    stop_icsim
    log "  [ok] cenário baseline concluído (perf → $PERF_DATA_CSV; logs → $logs_root/)"
}

# Cenário 2: Firewall/Allowlist
run_cenario2() {
    log ""
    log "============================================================"
    log "  CENÁRIO 2 — FIREWALL/ALLOWLIST"
    log "============================================================"

    start_icsim_for cen2

    local logs_root="$RESULTS_ROOT/cenario2/runs"
    mkdir -p "$logs_root"

    local total_runs count
    total_runs=$(( $(echo "$ATTACKS_GATEWAY" | wc -w) * REPS ))
    count=0

    for attack in $ATTACKS_GATEWAY; do
        log ""
        log "--- cen2/$attack — $REPS repetições de ${DURATION}s ---"
        for run in $(seq 1 "$REPS"); do
            count=$(( count + 1 ))
            log "  [$count/$total_runs] cen2 / $attack / rep $(printf '%02d' "$run")"

            (
                cd "$CEN2_DIR"
                RUN_INDEX="$run" ./run_scenario2.sh "$attack" "$DURATION"
            ) >>"$MASTER_LOG" 2>&1 || log "  [AVISO] rep $run de $attack falhou — continuando"

            local last_dir
            last_dir="$(ls -1dt "$CEN2_DIR/results/"*"-${attack}" 2>/dev/null | head -1 || true)"
            if [[ -n "$last_dir" && -d "$last_dir" ]]; then
                local target="$logs_root/${attack}_run$(printf '%02d' "$run")"
                mv "$last_dir" "$target"
            fi

            [[ "$run" -lt "$REPS" ]] && sleep "$COOLDOWN"
        done
        sleep "$COOLDOWN"
    done

    stop_icsim
    log " [ok] cenário 2 concluído (perf → $PERF_DATA_CSV; logs → $logs_root/)"
}

# Cenário 3: SecOC (autenticação + freshness)
run_cenario3() {
    log ""
    log "============================================================"
    log "  CENÁRIO 3 — SecOC (autenticação simplificada)"
    log "============================================================"

    start_icsim_for cen3

    local logs_root="$RESULTS_ROOT/cenario3"
    mkdir -p "$logs_root"

    local total_runs count
    total_runs=$(( $(echo "$ATTACKS_GATEWAY" | wc -w) * REPS ))
    count=0

    for attack in $ATTACKS_GATEWAY; do
        log ""
        log "--- cen3/$attack — $REPS repetições de ${DURATION}s ---"
        for run in $(seq 1 "$REPS"); do
            count=$(( count + 1 ))
            log "  [$count/$total_runs] cen3 / $attack / rep $(printf '%02d' "$run")"

            (
                cd "$CEN3_DIR"
                RUN_INDEX="$run" ./run_scenario3.sh "$attack" "$DURATION"
            ) >>"$MASTER_LOG" 2>&1 || log "  [AVISO] rep $run de $attack falhou — continuando"

            local last_dir
            last_dir="$(ls -1dt "$CEN3_DIR/results/"*"-${attack}" 2>/dev/null | head -1 || true)"
            if [[ -n "$last_dir" && -d "$last_dir" ]]; then
                local target="$logs_root/${attack}_run$(printf '%02d' "$run")"
                mv "$last_dir" "$target"
            fi

            [[ "$run" -lt "$REPS" ]] && sleep "$COOLDOWN"
        done
        sleep "$COOLDOWN"
    done

    stop_icsim
    log " [ok] cenário 3 concluído (perf → $PERF_DATA_CSV; logs → $logs_root/)"
}

# PÓS-PROCESSAMENTO (análise dos dados)
postprocess() {
    # [LEGADO] analyze_all.py — gera comparison_overhead.csv/tex.
    if [[ -x "$HERE/analyze_all.py" && -s "$PERF_DATA_CSV" ]]; then
        log ""
        log "Rodando analyze_all.py (legado, comparação overhead)..."
        python3 "$HERE/analyze_all.py" \
            --master-dir "$RESULTS_ROOT" \
            2>&1 | tee -a "$MASTER_LOG" || true
    fi

    # Parser dos logs do gateway/sender — extrai contadores rx/fwd/bloqueios.
    if [[ -x "$HERE/parse_gateway_logs.py" ]]; then
        log ""
        log "Rodando parse_gateway_logs.py..."
        python3 "$HERE/parse_gateway_logs.py" \
            --master-dir "$RESULTS_ROOT" \
            2>&1 | tee -a "$MASTER_LOG" || true
    fi

    # Análise principal: custo absoluto + normalizado por frame com IC95.
    if [[ -x "$HERE/analyze_absolute.py" \
          && -s "$RESULTS_ROOT/gateway_logs.csv" ]]; then
        log ""
        log "Rodando analyze_absolute.py (custo absoluto + normalizado)..."
        python3 "$HERE/analyze_absolute.py" \
            --master-dir "$RESULTS_ROOT" \
            2>&1 | tee -a "$MASTER_LOG" || true
    fi

    # Figuras prontas para o capítulo de Resultados.
    if [[ -x "$HERE/plot_absolute.py" \
          && -s "$RESULTS_ROOT/absolute_cost.csv" ]]; then
        log ""
        log "Gerando figuras (plot_absolute.py)..."
        python3 "$HERE/plot_absolute.py" \
            --master-dir "$RESULTS_ROOT" \
            2>&1 | tee -a "$MASTER_LOG" || true
    fi

    log ""
    log "Resultados disponíveis em: $RESULTS_ROOT"
    log "  perf_data.csv             — TODOS os dados em formato canônico"
    log "  summary_all.csv           — estatísticas (μ, σ, IC95) por cen/ataque"
    log "  gateway_logs.csv          — contadores rx/fwd/bloqueios por rodada"
    log "  absolute_cost_wide.csv    — custo absoluto da camada (legível)"
    log "  absolute_cost_*.tex       — tabelas LaTeX (cycles/instructions/taskclock)"
    log "  normalized_cost_*.tex     — tabelas LaTeX cycles-por-frame e similares"
    log "  throughput_table.tex      — carga oferecida ao gateway"
    log "  figuras/                  — fig_taskclock, fig_cycles_per_frame, etc."
    log "  cenario2/runs/            — logs auxiliares (gateway.log, attack.log)"
    log "  cenario3/                 — logs auxiliares (gateway, sender, attack)"
}

# LIMPEZA
cleanup() {
    log "Limpando processos em background…"
    stop_icsim
    # Mata possíveis filhos remanescentes do perf/gateway.
    pkill -P $$ 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# MAIN
main() {
    require_root
    mkdir -p "$RESULTS_ROOT"
    : > "$MASTER_LOG"
    check_prereqs
    setup_vcans
    collect_sysinfo

    # Inicializa o CSV unificado da campanha (header canônico)
    perf_csv_init "$PERF_DATA_CSV"
    log "CSV unificado inicializado: $PERF_DATA_CSV"

    log "============================================================"
    log "  BATERIA DE EXPERIMENTOS — INÍCIO"
    log "  Cenários : $SCENARIOS"
    log "  Reps     : $REPS × ${DURATION}s (cooldown ${COOLDOWN}s)"
    log "  Ataques  : $ATTACKS_BASELINE"
    log "  ICSim    : $([[ $USE_ICSIM -eq 1 ]] && echo sim || echo não)"
    log "  Saída    : $RESULTS_ROOT"
    log "============================================================"

    ensure_replay_capture
    ensure_replay_capture_cen3

    for s in $SCENARIOS; do
        case "$s" in
            baseline) run_baseline ;;
            cen2)     run_cenario2 ;;
            cen3)     run_cenario3 ;;
            *) log "[AVISO] cenário desconhecido: $s — pulando" ;;
        esac
    done

    log ""
    log "============================================================"
    log "  BATERIA CONCLUÍDA"
    log "============================================================"
    {
        echo
        echo "Fim: $(date -Iseconds)"
    } >> "$SYSINFO"

    postprocess
}

main "$@"
