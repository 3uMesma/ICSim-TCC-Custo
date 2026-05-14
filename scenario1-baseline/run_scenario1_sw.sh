# Este script é o IRMÃO do `run_scenario1.sh` para a campanha system-wide.
# A ÚNICA mudança experimental é COMO o `perf` é invocado:
#
#   run_scenario1.sh    →  perf stat -p $ATTACK_PID  (mede só o atacante)
#   run_scenario1_sw.sh →  perf stat -a              (mede o sistema todo)

set -euo pipefail

IFACE="vcan0"
DURATION=30
REPS=10
COOLDOWN=5
ATTACKS="dos-py dos-cangen fuzzing replay spoofing"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/../master-experiment/resultados-sw"
REPLAY_LOG="${SCRIPT_DIR}/captura_replay.log"
ATTACK_DIR="$SCRIPT_DIR/../scripts-attacks"
REPLAY_RECORD_TIME=20

# Helpers compartilhados.
. "${SCRIPT_DIR}/../lib/perf_csv.sh"
. "${SCRIPT_DIR}/../lib/can_capture.sh"

PERF_DATA_CSV="${PERF_DATA_CSV:-${RESULTS_DIR}/perf_data.csv}"
PERF_EVENTS="${PERF_EVENTS:-$PERF_EVENTS_DEFAULT}"

# Buffer extra na janela do ataque para garantir que ele cobre a janela do perf.
# perf stat -a -- sleep DURATION cobre exatamente DURATION segundos. Para que
# o ataque esteja "em regime" em todos esses segundos, lançamos o ataque
# por DURATION + ATTACK_PADDING segundos, com 1 s de estabilização antes do perf.
ATTACK_PADDING="${ATTACK_PADDING:-3}"
STABILIZATION_DELAY="${STABILIZATION_DELAY:-1}"

# Parsing
usage() {
    cat <<EOF
Uso: sudo $0 [-i iface] [-d duration_s] [-n reps] [-a attacks] [-c cooldown_s]

  -i   Interface CAN (default: vcan0)
  -d   Duração de cada rodada em segundos (default: 30)
  -n   Número de repetições (default: 10)
  -a   Ataques separados por vírgula (default: todos)
       Opções: dos-py, dos-cangen, fuzzing, replay, spoofing
  -c   Cooldown entre rodadas em segundos (default: 5)
  -h   Mostra esta ajuda
EOF
    exit 0
}

while getopts "i:d:n:a:c:h" opt; do
    case "$opt" in
        i) IFACE="$OPTARG" ;;
        d) DURATION="$OPTARG" ;;
        n) REPS="$OPTARG" ;;
        a) ATTACKS="${OPTARG//,/ }" ;;
        c) COOLDOWN="$OPTARG" ;;
        h|*) usage ;;
    esac
done

# Validações
check_prereqs() {
    local missing=()
    command -v perf    >/dev/null 2>&1 || missing+=("perf (linux-tools)")
    command -v python3 >/dev/null 2>&1 || missing+=("python3")
    command -v cangen  >/dev/null 2>&1 || missing+=("cangen (can-utils)")

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "[ERRO] Dependências não encontradas:" >&2
        printf '  - %s\n' "${missing[@]}" >&2
        exit 1
    fi

    ip link show "$IFACE" >/dev/null 2>&1 || {
        modprobe vcan
        ip link add dev "$IFACE" type vcan 2>/dev/null || true
        ip link set up "$IFACE"
    }
}

# Funções Auxiliares
log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $*"
    echo "$msg"
    echo "$msg" >> "${RESULTS_DIR}/experiment_log.txt"
}

# ETAPA A - Lança o ataque em background (sem perf wrapping). Devolve o PID 
# em $1. Os ataques rodam por DURATION+ATTACK_PADDING segundos para cobrir 
# toda a janela do perf, mesmo com o delay de estabilização.
spawn_attack_bg() {
    local attack="$1"
    local run_num="$2"
    local out_var="$3"
    local total_time=$(( DURATION + ATTACK_PADDING ))

    case "$attack" in
        dos-py)
            python3 "${ATTACK_DIR}/DoS-attack.py" \
                --iface "$IFACE" --duration "$total_time" --rate 0 \
                >>"${RESULTS_DIR}/attacks_run.log" 2>&1 &
            ;;
        dos-cangen)
            timeout --preserve-status "${total_time}s" \
                cangen "$IFACE" -g 0 -I 000 -L 8 -D FFFFFFFFFFFFFFFF \
                >>"${RESULTS_DIR}/attacks_run.log" 2>&1 &
            ;;
        fuzzing)
            python3 "${ATTACK_DIR}/Fuzzy-attack.py" \
                --iface "$IFACE" --duration "$total_time" \
                --seed $((42 + run_num)) \
                >>"${RESULTS_DIR}/attacks_run.log" 2>&1 &
            ;;
        replay)
            python3 "${ATTACK_DIR}/Replay-attack.py" replay \
                --iface "$IFACE" --in "$REPLAY_LOG" --speedup 10 --loops 999 \
                >>"${RESULTS_DIR}/attacks_run.log" 2>&1 &
            ;;
        spoofing)
            python3 "${ATTACK_DIR}/Spoofing-attack.py" \
                --iface "$IFACE" --target speed --value 220 \
                --duration "$total_time" --rate 1 \
                >>"${RESULTS_DIR}/attacks_run.log" 2>&1 &
            ;;
        *)
            log "  [ERRO] Ataque desconhecido: $attack"
            return 1
            ;;
    esac
    eval "$out_var=$!"
}

run_perf_on_attack_sw() {
    local attack="$1"
    local run_num="$2"

    # ETAPA B — captura passiva via candump em paralelo ao perf.
    # No baseline, só vcan0 importa (tráfego legítimo + ataque).
    # Diretório por rodada para que analyze_latency.py encontre os logs.
    local cap_dir="${RESULTS_DIR}/lat_runs/${attack}_run$(printf '%02d' "$run_num")"
    mkdir -p "$cap_dir"
    local pid_in
    pid_in="$(can_capture_start vcan0 "$cap_dir/can_in.log")"

    local atk_pid
    spawn_attack_bg "$attack" "$run_num" atk_pid || {
        can_capture_stop "$pid_in"
        return 1
    }
    log "  ataque PID=$atk_pid (rodando por $((DURATION + ATTACK_PADDING))s)"

    # Aguarda estabilização para que o perf não pegue o startup do ataque.
    sleep "$STABILIZATION_DELAY"

    # Coleta system-wide pelo tempo exato da janela.
    perf_csv_run_systemwide "$PERF_DATA_CSV" baseline "$attack" "$run_num" \
        "$DURATION" "$PERF_EVENTS"

    # Fecha o ataque (se ainda estiver vivo).
    kill "$atk_pid" 2>/dev/null || true
    wait "$atk_pid" 2>/dev/null || true

    # Encerra a captura candump (faz flush) e reporta contagem.
    can_capture_stop "$pid_in"
    local n_in
    n_in="$(can_capture_count "$cap_dir/can_in.log")"
    log "  candump vcan0: $n_in frames legítimos capturados"
}

# =Captura para Replay
ensure_replay_log() {
    if [[ ! -f "$REPLAY_LOG" ]]; then
        log "Capturando tráfego legítimo para replay (${REPLAY_RECORD_TIME}s)..."
        python3 "${ATTACK_DIR}/Replay-attack.py" record \
            --iface "$IFACE" --out "$REPLAY_LOG" \
            --record-time "$REPLAY_RECORD_TIME"
        log "Captura concluída: $(grep -c '^(' "$REPLAY_LOG" 2>/dev/null || echo 0) frames"
    fi
}

# Info do Sistema
collect_sysinfo() {
    local info="${RESULTS_DIR}/sysinfo.txt"
    {
        echo "=== Informações do Sistema (campanha SYSTEM-WIDE) ==="
        echo "Modalidade: perf stat -a (system-wide, todos os cores)"
        echo "Data/Hora: $(date -Iseconds)"
        echo "Hostname: $(hostname)"
        echo "Kernel: $(uname -r)"
        echo "Cores: $(nproc)"
        echo "perf version: $(perf version 2>&1)"
        echo
        echo "=== Parâmetros ==="
        echo "Interface: $IFACE"
        echo "Duração por rodada: ${DURATION}s"
        echo "Repetições: $REPS"
        echo "Cooldown: ${COOLDOWN}s"
        echo "Ataques: $ATTACKS"
        echo "Eventos perf: $PERF_EVENTS"
        echo "Padding do ataque: ${ATTACK_PADDING}s (cobre a janela do perf)"
        echo "Delay de estabilização: ${STABILIZATION_DELAY}s"
        echo "Cenário: baseline (sem segurança, system-wide)"
    } > "$info"
}

# Main
main() {
    if [[ "$EUID" -ne 0 ]]; then
        echo "[erro] precisa de root para perf stat -a." >&2
        exit 1
    fi
    check_prereqs

    mkdir -p "${RESULTS_DIR}"
    : > "${RESULTS_DIR}/experiment_log.txt"
    : > "${RESULTS_DIR}/attacks_run.log"

    perf_csv_init "$PERF_DATA_CSV"

    log "============================================================"
    log "  ETAPA C — BASELINE SYSTEM-WIDE"
    log "  Ataques    : $ATTACKS"
    log "  Repetições : $REPS × ${DURATION}s cada"
    log "  CSV alvo   : $PERF_DATA_CSV"
    log "============================================================"

    collect_sysinfo

    if echo "$ATTACKS" | grep -q "replay"; then
        ensure_replay_log
    fi

    local total=0
    for a in $ATTACKS; do total=$((total + REPS)); done
    local count=0

    for attack in $ATTACKS; do
        log ""
        log "--- Ataque: $attack ($REPS repetições) ---"

        for run in $(seq 1 "$REPS"); do
            count=$((count + 1))
            log "[$count/$total] ${attack} — rodada $run/$REPS (system-wide)"

            run_perf_on_attack_sw "$attack" "$run"

            if [[ "$run" -lt "$REPS" ]]; then
                sleep "$COOLDOWN"
            fi
        done
        sleep "$COOLDOWN"
    done

    log ""
    log "============================================================"
    log "  COLETA SYSTEM-WIDE CONCLUÍDA — dados em $PERF_DATA_CSV"
    log "============================================================"
}

main "$@"
