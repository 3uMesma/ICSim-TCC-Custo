# run_scenario3_sw.sh — irmão SYSTEM-WIDE do run_scenario3.sh (cen3 SecOC-FD).
#
#   run_scenario3.sh    →  perf stat -p $GW_PID   (mede o gateway)
#   run_scenario3_sw.sh →  perf stat -a           (mede o sistema todo)
#
# Grava com component=system (perf) + as linhas de contador SecOC do gateway
# (component=gateway), incluindo reached_mac. Espelha run_scenario2_sw.sh.
set -euo pipefail
export LC_NUMERIC=C

ATTACK="${1:-}"
DURATION="${2:-30}"
shift $(( $# < 2 ? $# : 2 ))
EXTRA_GATEWAY_FLAGS=("$@")

if [[ -z "$ATTACK" ]]; then
    echo "uso: $0 <dos-py|fuzzing|replay|spoofing|dos-cangen|idle> [duration_s] [flags]"
    exit 2
fi

if [[ "$EUID" -ne 0 ]]; then
    echo "[erro] precisa de root para perf stat -a e tráfego CAN."
    exit 1
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS="$HERE/results-sw/$(date +%Y%m%d-%H%M%S)-${ATTACK}"
mkdir -p "$RESULTS"

. "$HERE/../lib/perf_csv.sh"
. "$HERE/../lib/can_capture.sh"

PERF_DATA_CSV="${PERF_DATA_CSV:-$HERE/results-sw/perf_data.csv}"
RUN_INDEX="${RUN_INDEX:-1}"
PERF_EVENTS="${PERF_EVENTS:-$PERF_EVENTS_DEFAULT}"
ATTACK_PADDING="${ATTACK_PADDING:-3}"
STABILIZATION_DELAY="${STABILIZATION_DELAY:-1}"
COMPONENT="${COMPONENT:-gateway}"
GATEWAY_BIN="${GATEWAY_BIN:-$HERE/secoc_gateway}"
ATAQUES="${ATAQUES:-$HERE/../scripts-attacks}"

echo "[info] resultados -> $RESULTS"
echo "[info] ataque=$ATTACK duração=${DURATION}s (cen3 SecOC-FD, system-wide)"

# vcans (vcan0 entrada, vcan1 saída) com MTU 72 — setup compartilhado do cen2.
"$HERE/../scenario2-firewall/setup_vcan_dual.sh" >/dev/null

# Subir gateway em background.
GW_LOG="$RESULTS/gateway.log"
"$GATEWAY_BIN" -i vcan0 -o vcan1 "${EXTRA_GATEWAY_FLAGS[@]}" >"$GW_LOG" 2>&1 &
GW_PID=$!
sleep 0.3
if ! kill -0 "$GW_PID" 2>/dev/null; then
    echo "[erro] gateway morreu na inicialização. Verifique $GW_LOG"
    cat "$GW_LOG"
    exit 3
fi
echo "[info] secoc_gateway rodando com PID $GW_PID"

# Dispara o ataque em background ANTES do perf — para já estar em regime
# quando a janela do perf abrir.
ATK_TOTAL=$(( DURATION + ATTACK_PADDING ))
ATK_PID=""

cleanup_and_die() {
    echo "[erro] $1"
    [[ -n "$ATK_PID" ]] && kill "$ATK_PID" 2>/dev/null || true
    kill "$GW_PID" 2>/dev/null || true
    exit "${2:-9}"
}

case "$ATTACK" in
    dos-py)
        python3 "$ATAQUES/DoS-attack.py" --iface vcan0 --duration "$ATK_TOTAL" --rate 0 \
            >"$RESULTS/attack.log" 2>&1 &
        ATK_PID=$!
        ;;
    fuzzing)
        python3 "$ATAQUES/Fuzzy-attack.py" --iface vcan0 --duration "$ATK_TOTAL" \
            >"$RESULTS/attack.log" 2>&1 &
        ATK_PID=$!
        ;;
    replay)
        SCRIPT="$ATAQUES/Replay-attack.py"
        [[ -r "$SCRIPT" ]] || cleanup_and_die "não achei $SCRIPT"
        CAP="${REPLAY_LOG_CEN3:-${REPLAY_LOG:-}}"
        if [[ -z "$CAP" || ! -s "$CAP" ]]; then
            CAP="$RESULTS/capture.log"
            python3 "$SCRIPT" record --iface vcan0 --out "$CAP" --record-time 3 \
                >>"$RESULTS/attack.log" 2>&1 || true
            if [[ ! -s "$CAP" ]]; then
                FALLBACK="$HERE/../captura.log"
                if [[ -r "$FALLBACK" ]]; then
                    sed 's/) can0 /) vcan0 /' "$FALLBACK" > "$CAP"
                else
                    cleanup_and_die "captura vazia e fallback indisponível" 5
                fi
            fi
        fi
        python3 "$SCRIPT" replay --iface vcan0 --in "$CAP" --speedup 10 --loops 99999 \
            >>"$RESULTS/attack.log" 2>&1 &
        ATK_PID=$!
        ;;
    spoofing)
        python3 "$ATAQUES/Spoofing-attack.py" --iface vcan0 --target speed \
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

# Captura passiva candump nas duas interfaces (entrada e saída do gateway).
PID_CAN_IN="$(can_capture_start vcan0 "$RESULTS/can_in.log")"
PID_CAN_OUT="$(can_capture_start vcan1 "$RESULTS/can_out.log")"

echo "[info] ataque PID=$ATK_PID; aguardando ${STABILIZATION_DELAY}s para estabilizar"
sleep "$STABILIZATION_DELAY"

# perf SYSTEM-WIDE por DURATION s — bloqueante (component=system).
perf_csv_run_systemwide "$PERF_DATA_CSV" cen3 "$ATTACK" "$RUN_INDEX" \
    "$DURATION" "$PERF_EVENTS"

# Encerrar ataque, gateway e capturas em ordem.
kill "$ATK_PID" 2>/dev/null || true
wait "$ATK_PID" 2>/dev/null || true
kill -INT "$GW_PID" 2>/dev/null || true
wait "$GW_PID"     2>/dev/null || true

can_capture_stop "$PID_CAN_IN"
can_capture_stop "$PID_CAN_OUT"
echo "[info] candump: $(can_capture_count "$RESULTS/can_in.log") frames vcan0 → $(can_capture_count "$RESULTS/can_out.log") frames vcan1"

# Contadores SecOC do log -> MESMO CSV (component=gateway), incl. reached_mac.
gw_num() { grep -m1 -F "$1" "$GW_LOG" 2>/dev/null | grep -oE '[0-9]+' | tail -1; }
emit()   { [[ -n "$2" ]] && printf 'cen3;%s;%s;%s;%s;%s;\n' \
             "$COMPONENT" "$ATTACK" "$RUN_INDEX" "$1" "$2" >> "$PERF_DATA_CSV"; }

rx="$(gw_num 'Frames recebidos em')"
ok="$(gw_num 'Verdicts SECOC_OK')"
bid="$(gw_num 'Rejeições por ID desconhecido')"
blen="$(gw_num 'Rejeições por DLC')"
bfv="$(gw_num 'Rejeições por FV')"
bmac="$(gw_num 'Rejeições por MAC')"

emit rx_total    "$rx"
emit ok          "$ok"
emit blocked_id  "$bid"
emit blocked_len "$blen"
emit blocked_fv  "$bfv"
emit blocked_mac "$bmac"
if [[ -n "$ok" && -n "$bmac" ]]; then
    emit reached_mac "$(( ok + bmac ))"
fi

echo "[ok] experiment concluído (rep=$RUN_INDEX → $PERF_DATA_CSV)."
echo
echo "======= secoc_gateway (resumo) ======="
tail -n 20 "$GW_LOG"
