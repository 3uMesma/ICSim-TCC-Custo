# Cenário 1 — BASELINE (process-attached).
#
# Cada execução:
#   1) Sobe o passthrough (forwarder transparente) em background apontando vcan0 -> vcan1
#   2) Anexa `perf stat` ao PID do passthrough
#   3) Dispara o ataque escolhido contra vcan0 por --duration segundos
#   4) Finaliza tudo, coleta o relatório do passthrough e o CSV do perf

set -euo pipefail
export LC_NUMERIC=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/probes.sh"

ATTACK="${1:-}"
DURATION="${2:-30}"

if [[ -z "$ATTACK" ]]; then
    echo "uso: $0 <dos-py|fuzzing|replay|spoofing|dos-cangen|idle> [duration_s]"
    exit 2
fi

if [[ "$EUID" -ne 0 ]]; then
    echo "[erro] precisa de root para perf e para tráfego CAN."
    exit 1
fi

HERE="$SCRIPT_DIR"
ATAQUES="$HERE/../scripts-attacks"
RESULTS="$HERE/results/$(date +%Y%m%d-%H%M%S)-${ATTACK}"
mkdir -p "$RESULTS"

# Helper compartilhado — define o formato canônico do CSV de saída.
. "$HERE/../lib/perf_csv.sh"
PERF_DATA_CSV="${PERF_DATA_CSV:-$HERE/results/perf_data.csv}"
RUN_INDEX="${RUN_INDEX:-1}"

# Binário e rótulo do componente (D0): default = clássico. Para a variante
# FD do baseline: PT_BIN=$HERE/passthrough-fd PT_COMPONENT=passthrough-fd
PT_BIN="${PT_BIN:-$HERE/passthrough}"
PT_COMPONENT="${PT_COMPONENT:-passthrough}"

echo "[info] resultados -> $RESULTS"
echo "[info] ataque=$ATTACK duração=${DURATION}s (process-attached baseline)"

# Reusa o setup dual do cen2 — vcan0 + vcan1 são exatamente as interfaces
# que o passthrough precisa. 
"$HERE/../scenario2-firewall/setup_vcan_dual.sh" >/dev/null

# Subir passthrough em background e capturar PID
PT_LOG="$RESULTS/passthrough.log"
"$PT_BIN" -i vcan0 -o vcan1 >"$PT_LOG" 2>&1 &
PT_PID=$!
sleep 0.3

if ! kill -0 "$PT_PID" 2>/dev/null; then
    echo "[erro] passthrough morreu na inicialização. Verifique $PT_LOG"
    cat "$PT_LOG"
    exit 3
fi
echo "[info] passthrough rodando com PID $PT_PID"

# perf stat anexado ao passthrough — mesmo conjunto de eventos do cen2/cen3.
PERF_RAW="$RESULTS/perf_passthrough.raw"
PERF_EVENTS="${PERF_EVENTS:-$PERF_EVENTS_DEFAULT}"
LC_NUMERIC=C perf stat -p "$PT_PID" \
    -e "$PERF_EVENTS" \
    -x ';' -o "$PERF_RAW" \
    -- sleep "$DURATION" &
PERF_PID=$!

# esperar perf abrir counters antes de disparar o ataque.
wait_perf_attached "$PERF_PID" || true

cleanup_and_die() {
    local msg="$1"
    local code="${2:-9}"
    echo "[erro] $msg"
    kill "$PT_PID" "$PERF_PID" 2>/dev/null || true
    exit "$code"
}

# Disparar ataque
case "$ATTACK" in
    idle)
        echo "[info] baseline passivo; aguardando $DURATION s"
        sleep "$DURATION"
        ;;
    dos-py)
        python3 "$ATAQUES/DoS-attack.py" --iface vcan0 --duration "$DURATION" --rate 0 \
            >"$RESULTS/attack.log" 2>&1
        ;;
    fuzzing)
        python3 "$ATAQUES/Fuzzy-attack.py" --iface vcan0 --duration "$DURATION" \
            >"$RESULTS/attack.log" 2>&1
        ;;
    replay)
        SCRIPT="$ATAQUES/Replay-attack.py"
        [[ -r "$SCRIPT" ]] || cleanup_and_die "não achei $SCRIPT"
        echo "[info] usando $SCRIPT"

        # Usa a captura compartilhada da campanha (via env REPLAY_LOG do master)
        CAP="${REPLAY_LOG:-}"
        if [[ -z "$CAP" || ! -s "$CAP" ]]; then
            CAP="$RESULTS/capture.log"
            echo "[replay] sem REPLAY_LOG compartilhado — gravando..." \
                | tee -a "$RESULTS/attack.log"
            python3 "$SCRIPT" record \
                --iface vcan0 --out "$CAP" --record-time 3 \
                >>"$RESULTS/attack.log" 2>&1 || true

            if [[ ! -s "$CAP" ]]; then
                FALLBACK="$HERE/../captura.log"
                if [[ -r "$FALLBACK" ]]; then
                    echo "[replay] usando fallback: $FALLBACK" \
                        | tee -a "$RESULTS/attack.log"
                    sed 's/) can0 /) vcan0 /' "$FALLBACK" > "$CAP"
                else
                    cleanup_and_die "captura vazia e fallback indisponível" 5
                fi
            fi
        else
            n_frames="$(grep -c '^(' "$CAP" 2>/dev/null || echo 0)"
            echo "[replay] usando captura compartilhada: $CAP ($n_frames frames)" \
                | tee -a "$RESULTS/attack.log"
        fi

        echo "[replay] re-injetando por ${DURATION}s (speedup=10x)..." \
            | tee -a "$RESULTS/attack.log"
        python3 "$SCRIPT" replay \
            --iface vcan0 --in "$CAP" --speedup 10 --loops 99999 \
            >>"$RESULTS/attack.log" 2>&1 &
        REPLAY_PID=$!
        sleep "$DURATION"
        kill "$REPLAY_PID" 2>/dev/null || true
        wait "$REPLAY_PID" 2>/dev/null || true
        ;;
    spoofing)
        python3 "$ATAQUES/Spoofing-attack.py" --iface vcan0 --target speed \
            --value 220 --duration "$DURATION" --rate 1 \
            >"$RESULTS/attack.log" 2>&1
        ;;
    dos-cangen)
        cangen vcan0 -I 000 -L 8 -D FFFFFFFFFFFFFFFF -g 0 &
        CANGEN_PID=$!
        sleep "$DURATION"
        kill "$CANGEN_PID" 2>/dev/null || true
        ;;
    *)
        cleanup_and_die "ataque desconhecido: $ATTACK" 4
        ;;
esac

# Encerrar tudo
wait "$PERF_PID" 2>/dev/null || true
kill -INT "$PT_PID" 2>/dev/null || true
wait "$PT_PID"     2>/dev/null || true

# Rotula como (baseline, passthrough) no CSV unificado.
perf_csv_append_raw "$PERF_RAW" "$PERF_DATA_CSV" \
    baseline "$PT_COMPONENT" "$ATTACK" "$RUN_INDEX"

echo "[ok] experiment concluído (rep=$RUN_INDEX → $PERF_DATA_CSV)."
echo
echo "======= passthrough (resumo) ======="
tail -n 20 "$PT_LOG"
