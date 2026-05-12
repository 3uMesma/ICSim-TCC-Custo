#!/usr/bin/env bash
# Verifica que o refactor da Fase 1 não muda artefatos gerados pelos
# scripts Python. Roda os 8 scripts contra um perf_data.csv real e
# compara sha256 de todos os CSV/TeX produzidos.
#
# Uso:
#   REGRESSION_MODE=before ./tests/regression_test.sh <campanha>
#       grava referência em /tmp/refactor_before/
#   ./tests/regression_test.sh <campanha>
#       compara estado atual contra a referência

set -euo pipefail
export LC_NUMERIC=C

[[ $# -eq 1 ]] || { echo "uso: $0 <master_results/timestamp>"; exit 2; }
CAMPAIGN="$(cd "$1" && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HERE="$(cd "$SCRIPT_DIR/.." && pwd)"

MODE="${REGRESSION_MODE:-after}"
REF_DIR="/tmp/refactor_before"

run_pipeline() {
    local out="$1"
    rm -rf "$out"
    mkdir -p "$out"
    cp "$CAMPAIGN/perf_data.csv" "$out/"
    python3 "$HERE/parse_gateway_logs.py"    --master-dir "$CAMPAIGN" --out "$out/gateway_logs.csv"
    python3 "$HERE/split_baseline_to_raw.py" --master-dir "$out" --csv "$out/perf_data.csv"
    # analyze_all.py espera estrutura cenario2/cenario3 — copiar do campaign.
    for d in baseline cenario2 cenario3; do
        if [[ -d "$CAMPAIGN/$d" ]]; then
            cp -r "$CAMPAIGN/$d" "$out/" 2>/dev/null || true
        fi
    done
    python3 "$HERE/analyze_all.py"          --master-dir "$out" > /dev/null
    python3 "$HERE/analyze_absolute.py"     --master-dir "$out" > /dev/null
    python3 "$HERE/plot_absolute.py"        --master-dir "$out" > /dev/null
    if grep -q ';system;' "$out/perf_data.csv" 2>/dev/null; then
        python3 "$HERE/analyze_overhead_sw.py" --master-dir "$out" > /dev/null
    fi
}

hash_artifacts() {
    local dir="$1"
    ( cd "$dir" && find . -type f \( -name '*.csv' -o -name '*.tex' \) \
        ! -path './baseline/raw/*' | sort | xargs sha256sum )
}

if [[ "$MODE" == "before" ]]; then
    echo "[refactor] capturando referência -> $REF_DIR"
    run_pipeline "$REF_DIR"
    hash_artifacts "$REF_DIR" > "$REF_DIR/HASHES"
    n=$(wc -l < "$REF_DIR/HASHES")
    echo "[OK] $n artefatos catalogados em $REF_DIR/HASHES"
    exit 0
fi

[[ -f "$REF_DIR/HASHES" ]] || {
    echo "[ERRO] sem referência. Rode primeiro:"
    echo "    REGRESSION_MODE=before $0 $CAMPAIGN"
    exit 2
}

AFTER_DIR="/tmp/refactor_after"
echo "[refactor] executando estado atual -> $AFTER_DIR"
run_pipeline "$AFTER_DIR"
hash_artifacts "$AFTER_DIR" > "$AFTER_DIR/HASHES"

# Compara ignorando o prefixo de diretório.
if diff <(sed "s|$REF_DIR|<DIR>|g"   "$REF_DIR/HASHES") \
        <(sed "s|$AFTER_DIR|<DIR>|g" "$AFTER_DIR/HASHES") > /dev/null; then
    n=$(wc -l < "$AFTER_DIR/HASHES")
    echo "[OK] $n artefatos byte-idênticos — refactor seguro"
    exit 0
fi

echo "[FAIL] hashes divergem:"
diff <(sed "s|$REF_DIR|<DIR>|g"   "$REF_DIR/HASHES") \
     <(sed "s|$AFTER_DIR|<DIR>|g" "$AFTER_DIR/HASHES") || true
echo
echo "ref:   $REF_DIR/HASHES"
echo "after: $AFTER_DIR/HASHES"
exit 1
