# run_scenario3.sh — Cenário 3 (SecOC-FD): gateway sob ataque.
#
# Sobe o secoc_gateway (CAN FD) em vcan0 -> vcan1, anexa `perf stat` ao seu
# PID, dispara o ataque contra vcan0 por DURATION s e, ao final, raspa os
# contadores SecOC do log do gateway para o MESMO CSV canônico do cen2.
#
# Métrica-chave de H_gateway:  reached_mac = SECOC_OK + ERR_MAC  (frames que
# passaram ID+DLC+FV e de fato chegaram ao CMAC). Sob ataque isto deve ser ~0
# (os frames maliciosos morrem no ID; o spoofing clássico morre no DLC).
#
# Espelha run_scenario2.sh; muda só o binário (secoc_gateway), o rótulo de
# cenário (cen3) e o conjunto de contadores raspados.
set -euo pipefail
export LC_NUMERIC=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/probes.sh"

ATTACK="${1:-}"
DURATION="${2:-30}"
shift $(( $# < 2 ? $# : 2 ))
EXTRA_GATEWAY_FLAGS=("$@")

if [[ -z "$ATTACK" ]]; then
    echo "uso: $0 <dos-py|fuzzing|replay|spoofing|dos-cangen|idle> [duration_s] [flags]"
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

. "$HERE/../lib/perf_csv.sh"
PERF_DATA_CSV="${PERF_DATA_CSV:-$HERE/results/perf_data.csv}"
RUN_INDEX="${RUN_INDEX:-1}"
COMPONENT="${COMPONENT:-gateway}"
GATEWAY_BIN="${GATEWAY_BIN:-$HERE/secoc_gateway}"

echo "[info] resultados -> $RESULTS"
echo "[info] ataque=$ATTACK duração=${DURATION}s (cen3 SecOC-FD)"

# vcans (vcan0 entrada, vcan1 saída) com MTU 72 — setup compartilhado do cen2.
"$HERE/../scenario2-firewall/setup_vcan_dual.sh" >/dev/null

# Subir gateway em background e capturar PID.
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

# perf stat anexado ao gateway.
PERF_RAW="$RESULTS/perf_gateway.raw"
PERF_EVENTS="${PERF_EVENTS:-$PERF_EVENTS_DEFAULT}"
LC_NUMERIC=C perf stat -p "$GW_PID" \
    -e "$PERF_EVENTS" \
    -x ';' -o "$PERF_RAW" \
    -- sleep "$DURATION" &
PERF_PID=$!

wait_perf_attached "$PERF_PID" || true

cleanup_and_die() {
    echo "[erro] $1"
    kill "$GW_PID" "$PERF_PID" 2>/dev/null || true
    exit "${2:-9}"
}

# Disparar ataque (mesmo repertório e flags do run_scenario2.sh).
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

# Encerrar perf e gateway em ordem.
wait "$PERF_PID" 2>/dev/null || true
kill -INT "$GW_PID" 2>/dev/null || true
wait "$GW_PID"     2>/dev/null || true

# perf do gateway no CSV canônico (scenario=cen3).
perf_csv_append_raw "$PERF_RAW" "$PERF_DATA_CSV" cen3 "$COMPONENT" "$ATTACK" "$RUN_INDEX"

# Contadores SecOC do log -> MESMO CSV, mesmas chaves.
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

# reached_mac = frames que chegaram ao CMAC = OK + ERR_MAC.
if [[ -n "$ok" && -n "$bmac" ]]; then
    emit reached_mac "$(( ok + bmac ))"
fi

echo "[ok] experiment concluído (rep=$RUN_INDEX → $PERF_DATA_CSV)."
echo
echo "======= secoc_gateway (resumo) ======="
tail -n 30 "$GW_LOG"
