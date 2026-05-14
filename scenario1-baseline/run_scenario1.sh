# Para cada ataque, executa N repetições com perf e salva CSVs brutos

set -euo pipefail # por segurança
export LC_NUMERIC=C

# CONFIGURAÇÕES
IFACE="vcan0"
DURATION=30 # segundos/ataque
REPS=20
COOLDOWN=5
ATTACKS="dos-py dos-cangen fuzzing replay spoofing"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ATTACK_DIR="$SCRIPT_DIR/../scripts-attacks"
RESULTS_DIR="${SCRIPT_DIR}/results-comparison-dos"
REPLAY_LOG="${SCRIPT_DIR}/captura_replay.log"
REPLAY_RECORD_TIME=30

# Helper compartilhado de coleta perf (define o formato canônico).
. "${SCRIPT_DIR}/../lib/perf_csv.sh"
PERF_DATA_CSV="${PERF_DATA_CSV:-${RESULTS_DIR}/perf_data.csv}"
PERF_EVENTS="${PERF_EVENTS:-$PERF_EVENTS_DEFAULT}"


# PARSING
usage() {
    echo "Uso: sudo $0 [-i iface] [-d duration_s] [-n reps] [-a attacks] [-c cooldown_s]"
    echo
    echo "  -i   Interface CAN"
    echo "  -d   Duração de cada rodada em segundos "
    echo "  -n   Número de repetições"
    echo "  -a   Ataques separados por vírgula"
    echo "  -c   Cooldown entre rodadas em segundos"
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

# alias de dos-python para dos
normalize_attakcs() {
    local out=()
    local a
    for a in $ATTACKS; do
        case "$a" in
            dos)    out+=("dos-python") ;;
            *)      out+=("$a") ;;
        esac
    done
    ATTACKS="${out[*]}"            
}
normalize_attakcs


log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $*"
    echo "$msg"
    echo "$msg" >> "${RESULTS_DIR}/experiment_log.txt"
}

run_perf_on_attack() {
    local attack="$1"
    local run_num="$2"

    # caso especial: dos-cangen é delegado a um script externo
    if [[ "$attack" == "dos-cangen" ]]; then
        local cangen_script="${ATTACK_DIR}/dos-cangen-attack.sh"
        if [[ ! -f "$cangen_script" ]]; then
            log "  [ERRO] Script cangen não encontrado: $cangen_script"
            return 1
        fi

        local raw
        raw="$(mktemp -t perfcangen.XXXXXX)"
        log "  CMD: PERF_RAW=$raw bash $cangen_script ..."

        PERF_RAW="$raw" \
        PERF_EVENTS="$PERF_EVENTS" \
            bash "$cangen_script" -i "$IFACE" -d "$DURATION" -g 0 -m fixed || true

        perf_csv_append_raw "$raw" "$PERF_DATA_CSV" \
            baseline process dos-cangen "$run_num"
        return 0
    fi

    # demais ataques: comando síncrono que perf "wrapa" diretamente
    local attack_cmd
    case "$attack" in
        dos-py)
            attack_cmd="python3 ${ATTACK_DIR}/DoS-attack.py --iface $IFACE --duration $DURATION --rate 0"
            ;;
        fuzzing)
            attack_cmd="python3 ${ATTACK_DIR}/Fuzzy-attack.py --iface $IFACE --duration $DURATION --seed $((42 + run_num))"
            ;;
        replay)
            attack_cmd="timeout ${DURATION}s python3 ${ATTACK_DIR}/Replay-attack.py replay --iface $IFACE --in $REPLAY_LOG --speedup 2 --loops 999"
            ;;
        spoofing)
            attack_cmd="python3 ${ATTACK_DIR}/Spoofing-attack.py --iface $IFACE --target speed --value 220 --duration $DURATION --rate 1"
            ;;
        *)
            log "  [ERRO] Ataque desconhecido: $attack"
            return 1
            ;;
    esac

    log "  CMD: $attack_cmd"

    perf_csv_run "$PERF_DATA_CSV" baseline process "$attack" "$run_num" \
        "$PERF_EVENTS" \
        -- bash -c "exec $attack_cmd"
}


# SNIFFING PARA REPLAY
ensure_replay_log() {
    if [[ -f "$REPLAY_LOG" ]]; then
        log "Arquivo de replay encontrado: $REPLAY_LOG ($(wc -l < "$REPLAY_LOG") frames)"
        
        read -rp "[?] Deseja usar o arquivo existente? [S/n]: " answer
        answer="${answer,,}" # lowercase
        
        if [[ "$answer" == "n" || "$answer" == "nao" || "$answer" == "não" ]]; then
            log "Recapturando tráfego legítimo para replay (${REPLAY_RECORD_TIME}s)..."
            python3 "${ATTACK_DIR}/Replay-attack.py" record \
                --iface "$IFACE" \
                --out "$REPLAY_LOG" \
                --record-time "$REPLAY_RECORD_TIME"
            log "Captura concluída: $(wc -l < "$REPLAY_LOG") frames em $REPLAY_LOG"
        else
            log "Usando arquivo existente: $REPLAY_LOG"
        fi
    else
        log "Nenhum arquivo de replay encontrado. Capturando (${REPLAY_RECORD_TIME}s)..."
        python3 "${ATTACK_DIR}/Replay-attack.py" record \
            --iface "$IFACE" \
            --out "$REPLAY_LOG" \
            --record-time "$REPLAY_RECORD_TIME"
        log "Captura concluída: $(wc -l < "$REPLAY_LOG") frames em $REPLAY_LOG"
    fi
}

collect_sysinfo() {
    local info="${RESULTS_DIR}/sysinfo.txt"
    {
        echo "=== Informações do Sistema ==="
        echo "Data/Hora: $(date -Iseconds)"
        echo "Hostname: $(hostname)"
        echo "Kernel: $(uname -r)"
        echo "CPU: $(lscpu | grep 'Model name' | sed 's/.*:\s*//')"
        echo "Cores: $(nproc)"
        echo "RAM: $(free -h | awk '/Mem:/{print $2}')"
        echo "perf version: $(perf version 2>&1)"
        echo "python-can: $(python3 -c 'import can; print(can.__version__)' 2>&1 || echo 'N/A')"
        echo "can-utils: $(dpkg -l can-utils 2>/dev/null | tail -1 | awk '{print $3}' || echo 'N/A')"
        echo
        echo "=== Parâmetros do Experimento ==="
        echo "Interface: $IFACE"
        echo "Duração por rodada: ${DURATION}s"
        echo "Repetições: $REPS"
        echo "Cooldown: ${COOLDOWN}s"
        echo "Ataques: $ATTACKS"
        echo "Eventos perf: $PERF_EVENTS"
        echo "Cenário: baseline (sem segurança)"
    } > "$info"
    log "Informações do sistema salvas em $info"
}

check_icsim_running() {
    local missing=0

    if ! pgrep -x "icsim" > /dev/null 2>&1; then
        log "  [ERRO] icsim não está rodando. Inicie com: ./icsim $IFACE"
        missing=1
    else
        log "  [OK] icsim está rodando (PID: $(pgrep -x icsim))"
    fi

    if ! pgrep -x "controls" > /dev/null 2>&1; then
        log "  [ERRO] controls não está rodando. Inicie com: ./controls $IFACE"
        missing=1
    else
        log "  [OK] controls está rodando (PID: $(pgrep -x controls))"
    fi

    if [[ "$missing" -eq 1 ]]; then
        log "  Abortando experimento. Inicie os processos e tente novamente."
        exit 1
    fi
}

main() {
    mkdir -p "${RESULTS_DIR}"
    : > "${RESULTS_DIR}/experiment_log.txt"

    perf_csv_init "$PERF_DATA_CSV"

    log "Verificando pré-requisitos..."
    check_icsim_running 

    log "============================================================"
    log "  ETAPA 1 — TESTE DE ESTRESSE (BASELINE)"
    log "  Ataques : $ATTACKS"
    log "  Repetições: $REPS × ${DURATION}s cada"
    log "  CSV alvo : $PERF_DATA_CSV"
    log "============================================================"

    collect_sysinfo

    # Se replay está na lista, garante captura prévia
    if echo "$ATTACKS" | grep -q "replay"; then
        ensure_replay_log
    fi

    # Conta total para progresso
    local total=0
    for a in $ATTACKS; do total=$((total + REPS)); done
    local count=0

    for attack in $ATTACKS; do
        log ""
        log "--- Ataque: $attack ($REPS repetições) ---"

        for run in $(seq 1 "$REPS"); do
            count=$((count + 1))
            log "[$count/$total] ${attack} — rodada $run/$REPS"

            run_perf_on_attack "$attack" "$run"

            if [[ "$run" -lt "$REPS" ]]; then
                sleep "$COOLDOWN"
            fi
        done

        # Cooldown extra entre ataques diferentes
        sleep "$COOLDOWN"
    done

    log ""
    log "============================================================"
    log "  COLETA CONCLUÍDA — dados em $PERF_DATA_CSV"
    log "  Para análise estatística: python3 ../analyze_all.py --master-dir <dir>"
    log "============================================================"
}

main "$@"
