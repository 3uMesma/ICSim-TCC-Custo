# Este script é o IRMÃO do `master_run.sh`. Toda a infraestrutura de
# orquestração (setup de vcans, ICSim em background, captura de replay,
# trap de limpeza, parsing de argumentos) é IDÊNTICA. As únicas mudanças:
#
#   1. Chama os sub-scripts SYSTEM-WIDE:
#        ataques/run_experiments_sw.sh
#        cenario2-firewall/run_scenario2_sw.sh
#        cenario3-secoc/run_scenario3_sw.sh
#
#   2. Usa 10 rps
#

set -euo pipefail
export LC_NUMERIC=C

# CONFIGURAÇÕES
DURATION=30
REPS=10                                          # vs 20 do master_run.sh
COOLDOWN=5
ATTACKS="dos-py dos-cangen fuzzing replay spoofing"
SCENARIOS="baseline cen2 cen3"
USE_ICSIM=1
FD_MODE=0                                         # 1=usa binários CAN FD (--fd)
REPLAY_RECORD_TIME=30

# CAMINHOS
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ATAQUES_DIR="$HERE/../scripts-attacks"
CEN1_DIR="$HERE/../scenario1-baseline"
CEN2_DIR="$HERE/../scenario2-firewall"
CEN3_DIR="$HERE/../scenario3-secoc"
ICSIM_DIR="$HERE/../" 

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
RESULTS_ROOT="$HERE/resultados-sw/$TIMESTAMP"
MASTER_LOG="$RESULTS_ROOT/master_log.txt"
SYSINFO="$RESULTS_ROOT/sysinfo.txt"
REPLAY_LOG="$RESULTS_ROOT/replay_capture.log"
export REPLAY_LOG     # ← visível para os run_*_sw.sh
REPLAY_LOG_CEN3="$RESULTS_ROOT/replay_capture_cen3.log"
export REPLAY_LOG_CEN3

PERF_DATA_CSV="$RESULTS_ROOT/perf_data.csv"
export PERF_DATA_CSV

# shellcheck source=lib/perf_csv.sh
. "$HERE/../lib/perf_csv.sh"
. "$HERE/../lib/governor.sh"

ICSIM_PID=""
CONTROLS_PID=""

# HELPERS
usage() {
    cat <<EOF
Uso: sudo $0 [opções]

Opções:
  -n NUM         Repetições por ataque/cenário (default: $REPS)
  -d SEC         Duração de cada rodada em segundos (default: $DURATION)
  -c SEC         Cooldown entre rodadas em segundos (default: $COOLDOWN)
  -s LISTA       Cenários separados por vírgula (default: todos)
  -a LISTA       Ataques separados por vírgula (default: $ATTACKS)
  --no-icsim     Não inicia ICSim/controls
  --fd           Campanha CAN FD: usa passthrough-fd/gateway-fd (cen3 já é FD).
                 Recomendado com --no-icsim (ICSim clássico não lê frames FD).
  -h             Mostra esta ajuda

Modo de medição: SYSTEM-WIDE (perf stat -a) — Etapa C do TCC.
Saída: $HERE/resultados-sw/<timestamp>/
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

warn() { log "[AVISO] $*"; }
fail() { log "[ERRO] $*"; exit 1; }

# PARSING DE ARGUMENTOS
while [[ $# -gt 0 ]]; do
    case "$1" in
        -n) REPS="$2"; shift 2 ;;
        -d) DURATION="$2"; shift 2 ;;
        -c) COOLDOWN="$2"; shift 2 ;;
        -s) SCENARIOS="${2//,/ }"; shift 2 ;;
        -a) ATTACKS="${2//,/ }"; shift 2 ;;
        --no-icsim) USE_ICSIM=0; shift ;;
        --fd) FD_MODE=1; shift ;;
        -h|--help) usage ;;
        *) echo "[erro] opção desconhecida: $1" >&2; usage ;;
    esac
done

# VALIDAÇÕES
require_root() {
    [[ "$EUID" -eq 0 ]] || die "este script precisa de sudo (perf stat -a + ip link)."
}

check_prereqs() {
    local missing=()
    command -v perf    >/dev/null 2>&1 || missing+=("perf")
    command -v python3 >/dev/null 2>&1 || missing+=("python3")
    command -v cangen  >/dev/null 2>&1 || missing+=("cangen (can-utils)")
    command -v candump >/dev/null 2>&1 || missing+=("candump (can-utils)")
    [[ ${#missing[@]} -eq 0 ]] || die "dependências ausentes: ${missing[*]}"

    [[ -x "$CEN1_DIR/run_passthrough_sw.sh" ]] \
        || die "$CEN1_DIR/run_passthrough_sw.sh não é executável"
    [[ -x "$CEN2_DIR/run_scenario2_sw.sh" ]] \
        || die "$CEN2_DIR/run_scenario2_sw.sh não é executável"
    [[ -x "$CEN3_DIR/run_scenario3_sw.sh" ]] \
        || die "$CEN3_DIR/run_scenario3_sw.sh não é executável"

    for s in $SCENARIOS; do
        case "$s" in
            baseline)
                if [[ "$FD_MODE" -eq 1 ]]; then
                    [[ -x "$CEN1_DIR/passthrough-fd" ]] \
                        || die "binário ausente: $CEN1_DIR/passthrough-fd (rode 'make' em $CEN1_DIR)"
                else
                    [[ -x "$CEN1_DIR/passthrough" ]] \
                        || die "binário ausente: $CEN1_DIR/passthrough (rode 'make -f experiments.mk cen1')"
                fi ;;
            cen2)
                if [[ "$FD_MODE" -eq 1 ]]; then
                    [[ -x "$CEN2_DIR/gateway-fd" ]] \
                        || die "binário ausente: $CEN2_DIR/gateway-fd (rode 'make gateway-fd' em $CEN2_DIR)"
                else
                    [[ -x "$CEN2_DIR/gateway" ]] \
                        || die "binário ausente: $CEN2_DIR/gateway (rode 'make' em $CEN2_DIR)"
                fi ;;
            cen3)
                [[ -x "$CEN3_DIR/secoc_sender"  ]] \
                    || die "binário ausente: $CEN3_DIR/secoc_sender"
                [[ -x "$CEN3_DIR/secoc_gateway" ]] \
                    || die "binário ausente: $CEN3_DIR/secoc_gateway" ;;
            *) die "cenário desconhecido: $s" ;;
        esac
    done

    if [[ "$USE_ICSIM" -eq 1 ]]; then
        if [[ ! -x "$ICSIM_DIR/icsim" || ! -x "$ICSIM_DIR/controls" ]]; then
            log "[AVISO] ICSim/controls não compilados — continuando sem ICSim."
            USE_ICSIM=0
        fi
        if [[ -z "${DISPLAY:-}" && "$USE_ICSIM" -eq 1 ]]; then
            log "[AVISO] DISPLAY não definido — forçando --no-icsim."
            USE_ICSIM=0
        fi
    fi

    # perf_event_paranoid pode bloquear -a mesmo em root em alguns kernels. Não falha aqui, só registra.
    local pp
    pp="$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo 'N/A')"
    if [[ "$pp" =~ ^[0-9]+$ && "$pp" -gt 1 ]]; then
        log "[AVISO] perf_event_paranoid=$pp (>1). 'perf stat -a' pode falhar."
        log "[AVISO] Para abrir, rode: sudo sysctl kernel.perf_event_paranoid=-1"
    fi
}

# SYSINFO
collect_sysinfo() {
    {
        echo "===================================================================="
        echo " ETAPA C — Campanha SYSTEM-WIDE (perf stat -a)"
        echo " Análise do Custo Computacional de Segurança em CAN"
        echo "===================================================================="
        echo
        echo "=== Modalidade ==="
        echo "Modo perf : SYSTEM-WIDE (-a) — todos os processos, todos os cores"
        echo "Reps      : $REPS"
        echo "Duração   : ${DURATION}s por rodada"
        echo
        echo "=== Tempo ==="
        echo "Início: $(date -Iseconds)"
        echo
        echo "=== Sistema ==="
        echo "Hostname : $(hostname)"
        echo "Kernel   : $(uname -srm)"
        echo "Distro   : $(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || echo 'N/A')"
        echo "CPU      : $(lscpu | awk -F: '/Model name|Modelo do CPU/{gsub(/^ +/,"",$2); print $2; exit}')"
        echo "Cores    : $(nproc)"
        echo "Frequência : $(lscpu | awk -F: '/CPU max MHz|Frequência máxima/{gsub(/^ +/,"",$2); print $2 " MHz"; exit}')"
        echo "RAM      : $(free -h | awk '/^Mem:/ {print $2}')"
        echo "Governor : $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo 'N/A')"
        echo "perf_event_paranoid : $(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo 'N/A')"
        echo
        echo "=== Versões ==="
        echo "perf       : $(perf --version 2>&1)"
        echo "python3    : $(python3 --version 2>&1)"
        echo "python-can : $(python3 -c 'import can; print(can.__version__)' 2>&1 || echo 'N/A')"
        echo "gcc        : $(gcc --version | head -1 2>&1 || echo 'N/A')"
        echo
        echo "=== Parâmetros da Campanha ==="
        echo "Repetições por (cenário, ataque) : $REPS"
        echo "Duração por rodada              : ${DURATION}s"
        echo "Cooldown entre rodadas          : ${COOLDOWN}s"
        echo "Cenários                        : $SCENARIOS"
        echo "Modo CAN FD (--fd)              : $([[ $FD_MODE -eq 1 ]] && echo sim || echo não)"
        echo "Ataques                         : $ATTACKS"
        echo "ICSim em background             : $([[ $USE_ICSIM -eq 1 ]] && echo sim || echo não)"
        echo
        echo "=== Custo total estimado ==="
        local n_attacks
        n_attacks=$(echo "$ATTACKS" | wc -w)
        local n_scen
        n_scen=$(echo "$SCENARIOS" | wc -w)
        local total_runs=$(( n_scen * n_attacks * REPS ))
        local total_time=$(( total_runs * (DURATION + COOLDOWN + 5) ))  # +5s buffer
        printf "Rodadas totais : %d\n" "$total_runs"
        printf "Tempo bruto    : %d s ≈ %.1f min ≈ %.2f h\n" \
            "$total_time" "$(echo "$total_time/60" | bc -l)" \
            "$(echo "$total_time/3600" | bc -l)"
    } > "$SYSINFO"
    log "Sysinfo salvo em $SYSINFO"
}

# ICSIM (TRÁFEGO LEGÍTIMO DE FUNDO)
# Topologia idêntica à da campanha process-attached:
#   baseline : icsim em vcan1 ; controls em vcan0   (atrás do passthrough)
#   cen2     : icsim em vcan1 ; controls em vcan0   (atrás do gateway)
#   cen3     : icsim em vcan1 ; controls em vcan_trust (atrás de sender+gateway)
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
    kill -0 "$ICSIM_PID" 2>/dev/null || { ICSIM_PID=""; log "[AVISO] icsim morreu"; }
    kill -0 "$CONTROLS_PID" 2>/dev/null || { CONTROLS_PID=""; log "[AVISO] controls morreu"; }
}

stop_icsim() {
    [[ -n "${CONTROLS_PID:-}" ]] && kill "$CONTROLS_PID" 2>/dev/null || true
    [[ -n "${ICSIM_PID:-}"    ]] && kill "$ICSIM_PID"    2>/dev/null || true
    wait "${CONTROLS_PID:-}" 2>/dev/null || true
    wait "${ICSIM_PID:-}"    2>/dev/null || true
    CONTROLS_PID=""
    ICSIM_PID=""
}

# SETUP DE INTERFACES VCAN
setup_vcans() {
    log "Preparando interfaces virtuais (vcan0, vcan1, vcan_trust)…"
    modprobe can  2>/dev/null || true
    modprobe vcan
    for iface in vcan0 vcan1 vcan_trust; do
        ip link show "$iface" >/dev/null 2>&1 || ip link add dev "$iface" type vcan
        ip link set "$iface" down 2>/dev/null || true
        ip link set "$iface" mtu 72 2>/dev/null || true   # CAN FD-capable (inofensivo p/ clássico)
        ip link set "$iface" up
    done
    ip -br link show type vcan | tee -a "$MASTER_LOG" >/dev/null
}

# CAPTURA COMPARTILHADA PARA REPLAY
ensure_replay_capture() {
    if echo "$ATTACKS" | grep -qw replay; then
        if [[ ! -s "$REPLAY_LOG" ]]; then
            log "Capturando ${REPLAY_RECORD_TIME}s de tráfego legítimo em vcan0..."
            start_icsim_for baseline
            python3 "$ATAQUES_DIR/Replay-attack.py" record \
                --iface vcan0 --out "$REPLAY_LOG" \
                --record-time "$REPLAY_RECORD_TIME" \
                >>"$MASTER_LOG" 2>&1 || true
            stop_icsim
            local n
            n="$(grep -c '^(' "$REPLAY_LOG" 2>/dev/null || echo 0)"
            log "Captura concluída: $n frames em $REPLAY_LOG"
        else
            log "Reutilizando captura existente: $REPLAY_LOG"
        fi
        ln -sfn "$REPLAY_LOG" "$ATAQUES_DIR/captura_replay.log"
    fi
}

# Captura cen3 (frames autenticados pelo sender em vcan0)
ensure_replay_capture_cen3() {
    echo "$ATTACKS" | grep -qw replay || return 0
    [[ " $SCENARIOS " == *" cen3 "* ]] || return 0
    if [[ -s "$REPLAY_LOG_CEN3" ]]; then
        log "Reutilizando captura cen3 existente: $REPLAY_LOG_CEN3"
        return 0
    fi

    log "Capturando 3s de frames autenticados em vcan0 (sender + controls em vcan_trust)…"
    "$CEN3_DIR/secoc_sender" -i vcan_trust -o vcan0 >>"$MASTER_LOG" 2>&1 &
    local SENDER_PID=$!
    sleep 0.3
    if ! kill -0 "$SENDER_PID" 2>/dev/null; then
        warn "secoc_sender não subiu — cen3 replay vai cair no fallback intra-rodada."
        return 0
    fi

    local prev_use_icsim="$USE_ICSIM"
    start_icsim_for cen3
    USE_ICSIM="$prev_use_icsim"

    python3 "$ATAQUES_DIR/Replay-attack.py" record \
        --iface vcan0 --out "$REPLAY_LOG_CEN3" --record-time 3 \
        >>"$MASTER_LOG" 2>&1 || true

    stop_icsim
    kill "$SENDER_PID" 2>/dev/null || true
    wait "$SENDER_PID" 2>/dev/null || true

    local n
    n="$(grep -c '^(' "$REPLAY_LOG_CEN3" 2>/dev/null || echo 0)"
    log "Captura cen3 concluída: $n frames em $REPLAY_LOG_CEN3"
    if [[ "$n" -lt 20 ]]; then
        warn "captura cen3 com $n frames (<20) — fallback intra-rodada será usado."
        : > "$REPLAY_LOG_CEN3"
    fi
}


# EXECUÇÃO POR CENÁRIO

run_baseline() {
    log ""
    log "============================================================"
    log "  CENÁRIO 1 — BASELINE SYSTEM-WIDE (passthrough)"
    log "============================================================"

    start_icsim_for baseline

    local logs_root="$RESULTS_ROOT/baseline/runs"
    mkdir -p "$logs_root"

    local total_runs count
    total_runs=$(( $(echo "$ATTACKS" | wc -w) * REPS ))
    count=0

    for attack in $ATTACKS; do
        log ""
        log "--- baseline/$attack — $REPS repetições de ${DURATION}s ---"
        for run in $(seq 1 "$REPS"); do
            count=$(( count + 1 ))
            log "  [$count/$total_runs] baseline / $attack / rep $(printf '%02d' "$run")"

            (
                cd "$CEN1_DIR"
                if [[ "$FD_MODE" -eq 1 ]]; then
                    export PT_BIN="$CEN1_DIR/passthrough-fd" PT_COMPONENT="passthrough-fd"
                fi
                RUN_INDEX="$run" ./run_passthrough_sw.sh "$attack" "$DURATION"
            ) >>"$MASTER_LOG" 2>&1 || log "  [AVISO] rep $run de $attack falhou"

            local last_dir
            last_dir="$(ls -1dt "$CEN1_DIR/results-sw/"*"-${attack}" 2>/dev/null | head -1 || true)"
            if [[ -n "$last_dir" && -d "$last_dir" ]]; then
                local target="$logs_root/${attack}_run$(printf '%02d' "$run")"
                mv "$last_dir" "$target"
            fi

            [[ "$run" -lt "$REPS" ]] && sleep "$COOLDOWN"
        done
        sleep "$COOLDOWN"
    done

    stop_icsim
    log "  [ok] baseline-sw concluído (perf → $PERF_DATA_CSV; logs → $logs_root/)"
}

run_cenario2() {
    log ""
    log "============================================================"
    log "  CENÁRIO 2 — FIREWALL SYSTEM-WIDE"
    log "============================================================"

    start_icsim_for cen2

    local logs_root="$RESULTS_ROOT/cenario2/runs"
    mkdir -p "$logs_root"

    local total_runs count
    total_runs=$(( $(echo "$ATTACKS" | wc -w) * REPS ))
    count=0

    for attack in $ATTACKS; do
        log ""
        log "--- cen2/$attack — $REPS repetições de ${DURATION}s ---"
        for run in $(seq 1 "$REPS"); do
            count=$(( count + 1 ))
            log "  [$count/$total_runs] cen2 / $attack / rep $(printf '%02d' "$run")"

            (
                cd "$CEN2_DIR"
                if [[ "$FD_MODE" -eq 1 ]]; then
                    export GATEWAY_BIN="$CEN2_DIR/gateway-fd" COMPONENT="gateway-fd"
                fi
                RUN_INDEX="$run" ./run_scenario2_sw.sh "$attack" "$DURATION"
            ) >>"$MASTER_LOG" 2>&1 || log "  [AVISO] rep $run de $attack falhou"

            local last_dir
            last_dir="$(ls -1dt "$CEN2_DIR/results-sw/"*"-${attack}" 2>/dev/null | head -1 || true)"
            if [[ -n "$last_dir" && -d "$last_dir" ]]; then
                local target="$logs_root/${attack}_run$(printf '%02d' "$run")"
                mv "$last_dir" "$target"
            fi

            [[ "$run" -lt "$REPS" ]] && sleep "$COOLDOWN"
        done
        sleep "$COOLDOWN"
    done

    stop_icsim
    log "  [ok] cen2-sw concluído (perf → $PERF_DATA_CSV)"
}

run_cenario3() {
    log ""
    log "============================================================"
    log "  CENÁRIO 3 — SecOC SYSTEM-WIDE"
    log "============================================================"

    start_icsim_for cen3

    local logs_root="$RESULTS_ROOT/cenario3/runs"
    mkdir -p "$logs_root"

    local total_runs count
    total_runs=$(( $(echo "$ATTACKS" | wc -w) * REPS ))
    count=0

    for attack in $ATTACKS; do
        log ""
        log "--- cen3/$attack — $REPS repetições de ${DURATION}s ---"
        for run in $(seq 1 "$REPS"); do
            count=$(( count + 1 ))
            log "  [$count/$total_runs] cen3 / $attack / rep $(printf '%02d' "$run")"

            (
                cd "$CEN3_DIR"
                RUN_INDEX="$run" ./run_scenario3_sw.sh "$attack" "$DURATION"
            ) >>"$MASTER_LOG" 2>&1 || log "  [AVISO] rep $run de $attack falhou"

            local last_dir
            last_dir="$(ls -1dt "$CEN3_DIR/results-sw/"*"-${attack}" 2>/dev/null | head -1 || true)"
            if [[ -n "$last_dir" && -d "$last_dir" ]]; then
                local target="$logs_root/${attack}_run$(printf '%02d' "$run")"
                mv "$last_dir" "$target"
            fi

            [[ "$run" -lt "$REPS" ]] && sleep "$COOLDOWN"
        done
        sleep "$COOLDOWN"
    done

    stop_icsim
    log "  [ok] cen3-sw concluído (perf → $PERF_DATA_CSV)"
}

# PÓS-PROCESSAMENTO
postprocess() {
    # 1) Análise system-wide do perf — overhead % com IC95 propagado.
    if [[ -x "$HERE/analyze_overhead_sw.py" && -s "$PERF_DATA_CSV" ]]; then
        log ""
        log "Rodando analyze_overhead_sw.py sobre $PERF_DATA_CSV..."
        python3 "$HERE/analyze_overhead_sw.py" \
            --master-dir "$RESULTS_ROOT" \
            2>&1 | tee -a "$MASTER_LOG" || warn "etapa de pós-processamento retornou não-zero"
    fi

    # 2) Análise de latência/jitter — Etapa B (candump por rodada).
    if [[ -x "$HERE/analyze_latency.py" ]]; then
        log ""
        log "Rodando analyze_latency.py sobre logs candump em $RESULTS_ROOT..."
        python3 "$HERE/analyze_latency.py" \
            --master-dir "$RESULTS_ROOT" \
            2>&1 | tee -a "$MASTER_LOG" || warn "etapa de pós-processamento retornou não-zero"
    fi

    # 3) Figuras de latência — só roda se a análise gerou os CSVs.
    if [[ -x "$HERE/plot_latency.py" \
          && -s "$RESULTS_ROOT/latency_summary.csv" ]]; then
        log ""
        log "Gerando figuras de latência..."
        python3 "$HERE/plot_latency.py" \
            --master-dir "$RESULTS_ROOT" \
            2>&1 | tee -a "$MASTER_LOG" || warn "etapa de pós-processamento retornou não-zero"
    fi

    log ""
    log "Resultados disponíveis em: $RESULTS_ROOT"
    log "  perf_data.csv             — todos os dados system-wide"
    log "  overhead_sw.{csv,tex}     — overhead vs baseline (perf)"
    log "  latency_summary.{csv,tex} — latência de encaminhamento (candump)"
    log "  jitter_summary.csv        — jitter inter-chegada"
    log "  figuras-lat/              — boxplot, CDF e p99 da latência"
}

# TRAP DE LIMPEZA
cleanup() {
    log "Limpando processos em background..."
    stop_icsim
    pkill -P $$ 2>/dev/null || true
    restore_governor
}
trap cleanup EXIT INT TERM

# MAIN
main() {
    require_root
    mkdir -p "$RESULTS_ROOT"
    : > "$MASTER_LOG"
    check_prereqs
    if [[ "$FD_MODE" -eq 1 && "$USE_ICSIM" -eq 1 ]]; then
        log "[AVISO] --fd com ICSim ativo: o ICSim clássico não lê frames FD de vcan1. Considere --no-icsim."
    fi
    setup_vcans
    pin_performance_mode
    collect_sysinfo

    perf_csv_init "$PERF_DATA_CSV"
    log "CSV unificado inicializado: $PERF_DATA_CSV"

    log "============================================================"
    log "  CAMPANHA SYSTEM-WIDE — INÍCIO"
    log "  Cenários : $SCENARIOS"
    log "  Reps     : $REPS × ${DURATION}s (cooldown ${COOLDOWN}s)"
    log "  Ataques  : $ATTACKS"
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
    log "  CAMPANHA SYSTEM-WIDE CONCLUÍDA"
    log "============================================================"
    {
        echo
        echo "Fim: $(date -Iseconds)"
    } >> "$SYSINFO"

    postprocess
}

main "$@"
