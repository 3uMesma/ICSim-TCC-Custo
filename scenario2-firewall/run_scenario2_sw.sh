# Este script é o IRMÃO do `run_scenario2.sh` para a campanha system-wide.
# A maior mudança é como o `perf` é invocado:
#
#   run_scenario2.sh    →  perf stat -p $GW_PID         (mede o gateway)
#   run_scenario2_sw.sh →  perf stat -a                 (mede o sistema todo)
#
# O resultado é gravado em perf_data.csv com `component = system` (não
# `gateway`), permitindo a comparação válida com o baseline-system.
#
# Uso:
#   sudo ./run_scenario2_sw.sh <attack> [duration_s] [extra_gateway_flags...]

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

# Helper compartilhado.
. "$HERE/../lib/perf_csv.sh"
. "$HERE/../lib/can_capture.sh"

PERF_DATA_CSV="${PERF_DATA_CSV:-$HERE/results-sw/perf_data.csv}"
RUN_INDEX="${RUN_INDEX:-1}"
PERF_EVENTS="${PERF_EVENTS:-$PERF_EVENTS_DEFAULT}"
ATTACK_PADDING="${ATTACK_PADDING:-3}"
STABILIZATION_DELAY="${STABILIZATION_DELAY:-1}"

ATAQUES="${ATAQUES:-$HERE/../scripts-attacks}"

echo "[info] resultados -> $RESULTS"
echo "[info] ataque=$ATTACK duração=${DURATION}s (system-wide)"

# Garantir que os vcans existem
"$HERE/setup_vcan_dual.sh" >/dev/null

# Subir gateway em background — IDÊNTICO ao run_scenario2.sh
GW_LOG="$RESULTS/gateway.log"
"$HERE/gateway" -i vcan0 -o vcan1 "${EXTRA_GATEWAY_FLAGS[@]}" >"$GW_LOG" 2>&1 &
GW_PID=$!
sleep 0.3

if ! kill -0 "$GW_PID" 2>/dev/null; then
    echo "[erro] gateway morreu na inicialização. Verifique $GW_LOG"
    cat "$GW_LOG"
    exit 3
fi
echo "[info] gateway rodando com PID $GW_PID"

# DISPARAR ATAQUE em background — antes do perf, para que o ataque
#    já esteja em regime quando a janela do perf abrir.
ATK_TOTAL=$(( DURATION + ATTACK_PADDING ))
ATK_PID=""

cleanup_and_die() {
    local msg="$1"
    local code="${2:-9}"
    echo "[erro] $msg"
    [[ -n "$ATK_PID" ]] && kill "$ATK_PID" 2>/dev/null || true
    kill "$GW_PID" 2>/dev/null || true
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

#  Captura passiva candump nas DUAS interfaces (entrada e saída do gateway). 
# Iniciada antes do delay de estabilização para não perder frames; encerrada 
# depois do perf.
PID_CAN_IN="$(can_capture_start vcan0 "$RESULTS/can_in.log")"
PID_CAN_OUT="$(can_capture_start vcan1 "$RESULTS/can_out.log")"

echo "[info] ataque PID=$ATK_PID; aguardando ${STABILIZATION_DELAY}s para estabilizar"
sleep "$STABILIZATION_DELAY"

# perf SYSTEM-WIDE durante DURATION s — bloqueante.
perf_csv_run_systemwide "$PERF_DATA_CSV" cen2 "$ATTACK" "$RUN_INDEX" \
    "$DURATION" "$PERF_EVENTS"

# Encerrar ataque, gateway e capturas em ordem
kill "$ATK_PID" 2>/dev/null || true
wait "$ATK_PID" 2>/dev/null || true
kill -INT "$GW_PID" 2>/dev/null || true
wait "$GW_PID"     2>/dev/null || true

can_capture_stop "$PID_CAN_IN"
can_capture_stop "$PID_CAN_OUT"
echo "[info] candump capturou: $(can_capture_count "$RESULTS/can_in.log") frames vcan0 → $(can_capture_count "$RESULTS/can_out.log") frames vcan1"

echo "[ok] experiment concluído (rep=$RUN_INDEX → $PERF_DATA_CSV)."
echo
echo "======= gateway (resumo) ======="
tail -n 20 "$GW_LOG"
