# Helpers de log com classificação de severidade

# log MSG... — emite [HH:MM:SS] MSG no stdout (e em MASTER_LOG, se definido)
log() {
    local msg="[$(date '+%H:%M:%S')] $*"
    echo "$msg"
    if [[ -n "${MASTER_LOG:-}" && -d "$(dirname "$MASTER_LOG")" ]]; then
        echo "$msg" >> "$MASTER_LOG"
    fi
    return 0   # nunca falhar (importante para set -e nos callers)
}

# warn MSG... — registra como AVISO (continua execução)
warn() { log "[AVISO] $*"; }

# fail MSG... — registra como ERRO e sai com 1
fail() { log "[ERRO] $*"; exit 1; }

# die MSG... — alias histórico para fail (existia em master_run.sh)
die() { fail "$@"; }
