# Fixa o governor de frequência da CPU em 'performance' durante a
# campanha de medição, restaurando o valor original no cleanup.

ORIG_GOVERNOR=""

pin_performance_mode() {
    [[ -d /sys/devices/system/cpu/cpu0/cpufreq ]] || return 0
    ORIG_GOVERNOR="$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo '')"
    [[ -n "$ORIG_GOVERNOR" ]] || return 0
    if declare -F log >/dev/null; then
        log "Governor: fixando '$ORIG_GOVERNOR' -> 'performance'"
    fi
    for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        echo performance > "$g" 2>/dev/null || true
    done
}

restore_governor() {
    [[ -n "$ORIG_GOVERNOR" ]] || return 0
    if declare -F log >/dev/null; then
        log "Governor: restaurando '$ORIG_GOVERNOR'"
    fi
    for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        echo "$ORIG_GOVERNOR" > "$g" 2>/dev/null || true
    done
}
