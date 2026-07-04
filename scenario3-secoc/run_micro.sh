# Mede o micro_secoc no rig usa governor 'performance' (via lib/governor.sh), turbo
# off, core isolado e prioridade RT — e grava micro.csv + environment.txt.
#
set -euo pipefail
export LC_NUMERIC=C
 
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
 
CORE="${CORE:-}"
REPS="${REPS:-400}"
WARMUP="${WARMUP:-5000}"
SEED="${SEED:-42}"
MICRO_BIN="${MICRO_BIN:-$SCRIPT_DIR/micro_secoc}"
 
usage() { echo "uso: sudo $0 -c <core-isolado> [-r reps] [-w warmup] [-s seed]"; }
log()   { echo "[micro] $*" >&2; }
 
while getopts "c:r:w:s:h" opt; do
    case "$opt" in
        c) CORE="$OPTARG" ;;
        r) REPS="$OPTARG" ;;
        w) WARMUP="$OPTARG" ;;
        s) SEED="$OPTARG" ;;
        h) usage; exit 0 ;;
        *) usage; exit 2 ;;
    esac
done
 
[[ "$EUID" -eq 0 ]]   || { echo "[erro] precisa de root (governor, turbo)."; exit 1; }
[[ -n "$CORE" ]]      || { echo "[erro] informe o core isolado com -c <N>."; usage; exit 2; }
[[ -x "$MICRO_BIN" ]] || { echo "[erro] não achei $MICRO_BIN — rode 'make micro'."; exit 3; }
 
# Governor: reusa o helper compartilhado
. "$SCRIPT_DIR/../lib/governor.sh"
 
# Turbo boost off (best-effort; o caminho depende do driver de frequência).
# rdtsc conta na frequência nominal fixa; travar a freq real faz cada tick do
# TSC ~ 1 ciclo de verdade e elimina o ruído de DVFS/turbo.
TURBO_KIND=""; TURBO_ORIG=""
turbo_off() {
    if [[ -w /sys/devices/system/cpu/intel_pstate/no_turbo ]]; then
        TURBO_KIND="intel_pstate"
        TURBO_ORIG="$(cat /sys/devices/system/cpu/intel_pstate/no_turbo)"
        echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo
        log "turbo: intel_pstate/no_turbo=1 (off)"
    elif [[ -w /sys/devices/system/cpu/cpufreq/boost ]]; then
        TURBO_KIND="cpufreq_boost"
        TURBO_ORIG="$(cat /sys/devices/system/cpu/cpufreq/boost)"
        echo 0 > /sys/devices/system/cpu/cpufreq/boost
        log "turbo: cpufreq/boost=0 (off)"
    else
        log "turbo: nenhum controle conhecido — pulei (registre no environment.txt)"
    fi
}
turbo_restore() {
    case "$TURBO_KIND" in
        intel_pstate)  echo "$TURBO_ORIG" > /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null || true ;;
        cpufreq_boost) echo "$TURBO_ORIG" > /sys/devices/system/cpu/cpufreq/boost 2>/dev/null || true ;;
    esac
}
 
cleanup() { turbo_restore; restore_governor; }
trap cleanup EXIT INT TERM
 
pin_performance_mode
turbo_off
 
# Sanidade
ISOL="$(cat /sys/devices/system/cpu/isolated 2>/dev/null || echo '')"
if [[ ",$ISOL," != *",$CORE,"* ]]; then
    log "AVISO: core $CORE não está em isolcpus ('$ISOL') — o ruído entre reps pode subir."
fi
 
OUT="$SCRIPT_DIR/results-micro/$(date +%Y%m%d-%H%M%S)-fase2"
mkdir -p "$OUT"
CSV="$OUT/micro.csv"
ENVF="$OUT/environment.txt"
 
# Captura de ambiente
{
    echo "== data ==";           date -Is || true
    echo "== host/kernel ==";    uname -a || true
    echo "== cpu ==";            lscpu 2>/dev/null || grep -m1 'model name' /proc/cpuinfo || true
    echo "== cmdline ==";        cat /proc/cmdline 2>/dev/null || true
    echo "== isolated ==";       cat /sys/devices/system/cpu/isolated 2>/dev/null || echo "(nenhum)"
    echo "== governor ==";       cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null | sort -u || true
    echo "== freq_cur_kHz ==";   cat "/sys/devices/system/cpu/cpu${CORE}/cpufreq/scaling_cur_freq" 2>/dev/null || echo "(n/a)"
    echo "== turbo ==";          echo "kind=${TURBO_KIND:-} orig=${TURBO_ORIG:-}"
    echo "== gcc ==";            gcc --version 2>/dev/null | head -1 || echo "(gcc n/a)"
    echo "== params ==";         echo "core=$CORE reps=$REPS warmup=$WARMUP seed=$SEED"
    echo "== bin ==";            echo "$MICRO_BIN"; sha1sum "$MICRO_BIN" 2>/dev/null || true
} > "$ENVF"
 
log "ambiente -> $ENVF"
log "rodando micro_secoc no core $CORE (taskset, reps=$REPS)..."
 
# Medição: pinado no core (taskset)
taskset -c "$CORE" \
    "$MICRO_BIN" -c "$CORE" -r "$REPS" -w "$WARMUP" -s "$SEED" > "$CSV" 2> "$OUT/summary.txt"
cat "$OUT/summary.txt" >&2
 
log "csv -> $CSV ($(wc -l < "$CSV") linhas) · resumo -> $OUT/summary.txt"
echo "[ok] Fase 2 medida. Resultados em $OUT"