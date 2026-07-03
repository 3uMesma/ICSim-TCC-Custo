# Varre a matriz do macro reusando run_scenario2.sh:
#   {linear, direct} × {27, 256} × {dos-py, fuzzing, legit-flood} × REPS
# Cada célula: sobe a variante do gateway, anexa perf, dispara o ataque.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

REPS="${REPS:-20}"
DURATION="${DURATION:-30}"
COOLDOWN="${COOLDOWN:-5}"
STRATS=(linear direct)
NS=(27 256)
ATTACKS=(dos-py fuzzing legit-flood)

if [[ "$EUID" -ne 0 ]]; then
    echo "[erro] precisa de root (perf + tráfego CAN)."; exit 1
fi

# Pré-requisitos
for cmd in perf cangen python3; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "[erro] falta '$cmd' no PATH."; exit 1; }
done

OUT="$HERE/results/macro-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
CSV="$OUT/perf_macro.csv"

# Inicializa o CSV com o cabeçalho canônico (como o master_run faz)
. "$HERE/../lib/perf_csv.sh"
perf_csv_init "$CSV"

# Mata filhos remanescentes (gateway/perf) se abortar no meio
trap 'pkill -P $$ 2>/dev/null || true' EXIT INT TERM

echo "[macro] saída -> $CSV"
echo "[macro] $(( ${#STRATS[@]} * ${#NS[@]} * ${#ATTACKS[@]} * REPS )) rodadas de ${DURATION}s (+${COOLDOWN}s cooldown)"

for s in "${STRATS[@]}"; do
    for n in "${NS[@]}"; do
        BIN="$HERE/gateway-${s}-${n}"
        if [[ ! -x "$BIN" ]]; then
            echo "[erro] falta $BIN — rode 'make variants' antes."; exit 2
        fi
        for atk in "${ATTACKS[@]}"; do
            for r in $(seq 1 "$REPS"); do
                echo "[macro] ${s} N=${n} ${atk} rep=${r}/${REPS}"
                GATEWAY_BIN="$BIN" COMPONENT="${s}-${n}" \
                PERF_DATA_CSV="$CSV" RUN_INDEX="$r" \
                    "$HERE/run_scenario2.sh" "$atk" "$DURATION" >/dev/null 2>&1 \
                    || echo "[aviso] falhou: ${s} N=${n} ${atk} rep=${r}"
                sleep "$COOLDOWN"
            done
        done
    done
done

echo "[ok] macro concluído -> $CSV"
