# Probes para esperar por estados específicos em vez de sleep fixo.

# wait_perf_attached PERF_PID
# Espera o perf abrir seu counter group no PID alvo. Até ~2.5s.
# Retorna 0 quando perf parece ativo, 1 se timeout.
wait_perf_attached() {
    local pid="$1"
    local i
    for i in $(seq 1 50); do
        if [[ -d "/proc/$pid/fdinfo" ]] && \
           ls /proc/"$pid"/fdinfo/* >/dev/null 2>&1 && \
           grep -q '^pos' /proc/"$pid"/fdinfo/* 2>/dev/null; then
            return 0
        fi
        sleep 0.05
    done
    declare -F warn >/dev/null && warn "wait_perf_attached: timeout (pid=$pid)"
    return 1
}

# wait_proc_sleeping PID [MAX_ITER]
# Espera o processo entrar em estado S (sleeping = bloqueado em read).
# Default 20 iterações × 50ms = ~1s.
wait_proc_sleeping() {
    local pid="$1"
    local max="${2:-20}"
    local i state
    for i in $(seq 1 "$max"); do
        state=$(awk '/^State:/ {print $2}' /proc/"$pid"/status 2>/dev/null || echo "")
        [[ "$state" == "S" ]] && return 0
        sleep 0.05
    done
    return 1
}
