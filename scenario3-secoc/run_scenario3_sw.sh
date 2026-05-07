# Este script é o IRMÃO do `run_scenario3.sh` para a campanha system-wide.
# A diferença está em quantos `perf` rodam e como:
#
#   run_scenario3_sw.sh →  perf stat -a              (sistema todo)
#                          → uma linha no CSV (component=system)
#
# Em system-wide, sender + gateway + ataque + ICSim + kernel — todo o custo
# computacional é capturado num único par (cenário, rodada). 
#
set -euo pipefail

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
ATTACK_DIR="$HERE/../scripts-attacks"

echo "[info] resultados -> $RESULTS"
echo "[info] ataque=$ATTACK duração=${DURATION}s (system-wide)"

# Garantir que os três vcans existem
"$HERE/setup_vcan_triple.sh" >/dev/null

# Subir sender e gateway em background — IDÊNTICO ao run_scenario3.sh
SENDER_LOG="$RESULTS/sender.log"
GW_LOG="$RESULTS/gateway.log"

"$HERE/secoc_sender" -i vcan_trust -o vcan0 >"$SENDER_LOG" 2>&1 &
SENDER_PID=$!
sleep 0.2

"$HERE/secoc_gateway" -i vcan0 -o vcan1 "${EXTRA_GATEWAY_FLAGS[@]}" >"$GW_LOG" 2>&1 &
GW_PID=$!
sleep 0.3

if ! kill -0 "$SENDER_PID" 2>/dev/null; then
    echo "[erro] sender morreu na inicialização. Verifique $SENDER_LOG"
    cat "$SENDER_LOG"; exit 3
fi
if ! kill -0 "$GW_PID" 2>/dev/null; then
    echo "[erro] gateway morreu na inicialização. Verifique $GW_LOG"
    cat "$GW_LOG"; kill "$SENDER_PID" 2>/dev/null || true; exit 3
fi
echo "[info] sender PID=$SENDER_PID  gateway PID=$GW_PID"

# Disparar ataque em background (mesma lógica do run_scenario3.sh)
ATK_TOTAL=$(( DURATION + ATTACK_PADDING ))
ATK_PID=""

cleanup_and_die() {
    local msg="$1"; local code="${2:-9}"
    echo "[erro] $msg"
    [[ -n "$ATK_PID" ]] && kill "$ATK_PID" 2>/dev/null || true
    kill "$SENDER_PID" "$GW_PID" 2>/dev/null || true
    exit "$code"
}

case "$ATTACK" in
    dos-py)
        SCRIPT="${ATTACK_DIR}/DoS-attack.py"
        [[ -r "$SCRIPT" ]] || cleanup_and_die "não achei $SCRIPT"
        echo "[info] usando $SCRIPT"
        python3 "$SCRIPT" --iface vcan0 --duration "$ATK_TOTAL" --rate 0 \
            >"$RESULTS/attack.log" 2>&1 &
        ATK_PID=$!
        ;;
    fuzzing)
        SCRIPT="${ATTACK_DIR}/Fuzzy-attack.py"
        [[ -r "$SCRIPT" ]] || cleanup_and_die "não achei $SCRIPT"
        echo "[info] usando $SCRIPT"
        python3 "$SCRIPT" --iface vcan0 --duration "$ATK_TOTAL" \
            >"$RESULTS/attack.log" 2>&1 &
        ATK_PID=$!
        ;;
    replay)
        SCRIPT="${ATTACK_DIR}/Replay-attack.py"
        [[ -r "$SCRIPT" ]] || cleanup_and_die "não achei $SCRIPT"
        echo "[info] usando $SCRIPT"

        # Usa a captura compartilhada da campanha (vinda de master_run_sw.sh
        # via env var REPLAY_LOG). Elimina o record intra-rodada e mantém a
        # janela do perf 100% ocupada com replay.
        CAP="${REPLAY_LOG:-}"
        if [[ -z "$CAP" || ! -s "$CAP" ]]; then
            # Fallback: grava na própria rodada (modo legado).
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
        SCRIPT="${ATTACK_DIR}/Spoofing-attack.py"
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

# Captura passiva candump em TRÊS pontos:
#      vcan_trust → entrada do sender (frame puro do controls)
#      vcan0      → saída do sender = entrada do gateway (frame autenticado)
#      vcan1      → saída do gateway (frame validado, encaminhado ao ICSim)
PID_CAN_TRUST="$(can_capture_start vcan_trust "$RESULTS/can_trust.log")"
PID_CAN_BUS="$(can_capture_start vcan0       "$RESULTS/can_bus.log")"
PID_CAN_OUT="$(can_capture_start vcan1       "$RESULTS/can_out.log")"

echo "[info] ataque PID=$ATK_PID; aguardando ${STABILIZATION_DELAY}s para estabilizar"
sleep "$STABILIZATION_DELAY"

# 4) perf SYSTEM-WIDE durante DURATION s — bloqueante
perf_csv_run_systemwide "$PERF_DATA_CSV" cen3 "$ATTACK" "$RUN_INDEX" \
    "$DURATION" "$PERF_EVENTS"

# Encerrar ataque, gateway, sender e capturas em ordem
kill "$ATK_PID" 2>/dev/null || true
wait "$ATK_PID" 2>/dev/null || true
kill -INT "$GW_PID"      2>/dev/null || true
kill -INT "$SENDER_PID"  2>/dev/null || true
wait "$GW_PID"           2>/dev/null || true
wait "$SENDER_PID"       2>/dev/null || true

can_capture_stop "$PID_CAN_TRUST"
can_capture_stop "$PID_CAN_BUS"
can_capture_stop "$PID_CAN_OUT"
echo "[info] candump capturou: $(can_capture_count "$RESULTS/can_trust.log") trust, \
$(can_capture_count "$RESULTS/can_bus.log") bus, $(can_capture_count "$RESULTS/can_out.log") out"

echo "[ok] experimento concluído (rep=$RUN_INDEX → $PERF_DATA_CSV)."
echo
echo "======= gateway (resumo) ======="
tail -n 20 "$GW_LOG"
echo
echo "======= sender (resumo) ======="
tail -n 12 "$SENDER_LOG"
