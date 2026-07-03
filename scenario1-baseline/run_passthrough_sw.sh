# Irmão de `run_passthrough.sh` para a campanha SYSTEM-WIDE. A única
# diferença é que perf passa a observar o sistema todo (`perf stat -a`),
# não apenas o passthrough. 

set -euo pipefail
export LC_NUMERIC=C

ATTACK="${1:-}"
DURATION="${2:-30}"

if [[ -z "$ATTACK" ]]; then
    echo "uso: $0 <dos-py|fuzzing|replay|spoofing|dos-cangen|idle> [duration_s]"
    exit 2
fi

if [[ "$EUID" -ne 0 ]]; then
    echo "[erro] precisa de root para perf stat -a e tráfego CAN."
    exit 1
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS="$HERE/results-sw/$(date +%Y%m%d-%H%M%S)-${ATTACK}"
mkdir -p "$RESULTS"

# Helpers compartilhados.
. "$HERE/../lib/perf_csv.sh"
. "$HERE/../lib/can_capture.sh"

PERF_DATA_CSV="${PERF_DATA_CSV:-$HERE/results-sw/perf_data.csv}"
RUN_INDEX="${RUN_INDEX:-1}"

# Binário do baseline (D0): default clássico; FD via PT_BIN=$HERE/passthrough-fd.
PT_BIN="${PT_BIN:-$HERE/passthrough}"
PERF_EVENTS="${PERF_EVENTS:-$PERF_EVENTS_DEFAULT}"
ATTACK_PADDING="${ATTACK_PADDING:-3}"
STABILIZATION_DELAY="${STABILIZATION_DELAY:-1}"

ATAQUES="${ATAQUES:-$HERE/../scripts-attacks}"

echo "[info] resultados -> $RESULTS"
echo "[info] ataque=$ATTACK duração=${DURATION}s (system-wide baseline)"

# vcan0 + vcan1 via setup compartilhado do cen2 (idempotente).
"$HERE/../scenario2-firewall/setup_vcan_dual.sh" >/dev/null

# Subir passthrough em background — papel funcional idêntico ao gateway/cen2.
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

# DISPARAR ATAQUE em background — antes do perf, para que o ataque
# já esteja em regime quando a janela do perf abrir.
ATK_TOTAL=$(( DURATION + ATTACK_PADDING ))
ATK_PID=""

cleanup_and_die() {
    local msg="$1"
    local code="${2:-9}"
    echo "[erro] $msg"
    [[ -n "$ATK_PID" ]] && kill "$ATK_PID" 2>/dev/null || true
    kill "$PT_PID" 2>/dev/null || true
    exit "$code"
}

case "$ATTACK" in
    dos-py)
        SCRIPT="$ATAQUES/DoS-attack.py"
        [[ -r "$SCRIPT" ]] || cleanup_and_die "não achei $SCRIPT"
        echo "[info] usando $SCRIPT"
        python3 "$SCRIPT" --iface vcan0 --duration "$ATK_TOTAL" --rate 0 \
            >"$RESULTS/attack.log" 2>&1 &
        ATK_PID=$!
        ;;
    fuzzing)
        SCRIPT="$ATAQUES/Fuzzy-attack.py"
        [[ -r "$SCRIPT" ]] || cleanup_and_die "não achei $SCRIPT"
        echo "[info] usando $SCRIPT"
        python3 "$SCRIPT" --iface vcan0 --duration "$ATK_TOTAL" \
            >"$RESULTS/attack.log" 2>&1 &
        ATK_PID=$!
        ;;
    replay)
        SCRIPT="$ATAQUES/Replay-attack.py"
        [[ -r "$SCRIPT" ]] || cleanup_and_die "não achei $SCRIPT"
        echo "[info] usando $SCRIPT"

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

        echo "[replay] re-injetando por ${ATK_TOTAL}s (speedup=10x)..." \
            | tee -a "$RESULTS/attack.log"
        python3 "$SCRIPT" replay \
            --iface vcan0 --in "$CAP" --speedup 10 --loops 99999 \
            >>"$RESULTS/attack.log" 2>&1 &
        ATK_PID=$!
        ;;
    spoofing)
        SCRIPT="$ATAQUES/Spoofing-attack.py"
        [[ -r "$SCRIPT" ]] || cleanup_and_die "não achei $SCRIPT"
        echo "[info] usando $SCRIPT"
        python3 "$SCRIPT" --iface vcan0 --target speed \
            --value 220 --duration "$ATK_TOTAL" --rate 1 \
            >"$RESULTS/attack.log" 2>&1 &
        ATK_PID=$!
        ;;
    dos-cangen)
        cangen vcan0 -I 000 -L 8 -D FFFFFFFFFFFFFFFF -g 0 \
            >"$RESULTS/attack.log" 2>&1 &
        ATK_PID=$!
        ;;
    *)
        cleanup_and_die "ataque desconhecido: $ATTACK" 4
        ;;
esac

# Captura passiva candump nas DUAS interfaces (entrada e saída do
# passthrough). Necessária para que analyze_latency.py também encontre
# can_in.log/can_out.log no baseline
PID_CAN_IN="$(can_capture_start vcan0 "$RESULTS/can_in.log")"
PID_CAN_OUT="$(can_capture_start vcan1 "$RESULTS/can_out.log")"

echo "[info] ataque PID=$ATK_PID; aguardando ${STABILIZATION_DELAY}s para estabilizar"
sleep "$STABILIZATION_DELAY"

# perf SYSTEM-WIDE durante DURATION s — bloqueante.
# A função fixa o component como "system" (perf -a não distingue processos)
# e o cenário como "baseline".
perf_csv_run_systemwide "$PERF_DATA_CSV" baseline "$ATTACK" "$RUN_INDEX" \
    "$DURATION" "$PERF_EVENTS"

# Encerrar ataque, passthrough e capturas em ordem.
kill "$ATK_PID" 2>/dev/null || true
wait "$ATK_PID" 2>/dev/null || true
kill -INT "$PT_PID" 2>/dev/null || true
wait "$PT_PID"     2>/dev/null || true

can_capture_stop "$PID_CAN_IN"
can_capture_stop "$PID_CAN_OUT"
echo "[info] candump capturou: $(can_capture_count "$RESULTS/can_in.log") frames vcan0 → $(can_capture_count "$RESULTS/can_out.log") frames vcan1"

echo "[ok] experiment concluído (rep=$RUN_INDEX → $PERF_DATA_CSV)."
echo
echo "======= passthrough (resumo) ======="
tail -n 20 "$PT_LOG"
