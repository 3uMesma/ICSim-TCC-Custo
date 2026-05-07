# Este módulo encapsula o ciclo "iniciar candump em background → matá-lo
# de volta" para que os três scripts `run_*_sw.sh` chamem o mesmo código
# e mantenham consistência de filtros/timestamp/formato de saída.
#
# Formato dos arquivos produzidos
# 
# `candump -t a -L` produz log no formato canplayer-compatível, com
# timestamp absoluto Unix-epoch:
#
#   (1747526400.123456) vcan1 244#01020304ABCDEF01
#   (1747526400.124012) vcan1 188#0000000000000000
#   ...
#
# Como usar
# 
#   THIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#   . "$THIS_DIR/../lib/can_capture.sh"
#
#   # Iniciar captura em vcan0 filtrada por IDs legítimos
#   PID_IN="$(can_capture_start vcan0 "$RESULTS/can_in.log" "244:7FF,188:7FF,19B:7FF")"
#
#   # ...rodar a janela de medição (perf, ataque, etc.)
#
#   # Parar e fazer flush
#   can_capture_stop "$PID_IN"
#
# Filtros: passa-se "ID:MASK,ID:MASK,..." onde para CAN normal a máscara
# é 0x7FF (11 bits). Por exemplo, "244:7FF" só deixa passar frames com
# CAN-ID exatamente 0x244.
# =============================================================================

# IDs legítimos do ICSim (usados como default em campanhas — pode ser
# sobrescrito por chamada). Estes são os IDs que o gateway encaminha
# tanto em cen2 (allowlist) quanto em cen3 (lista de associações SecOC).
CAN_LEGIT_IDS_DEFAULT="244:7FF,188:7FF,19B:7FF"

can_capture_start() {
    local iface="$1"
    local out_log="$2"
    local filter="${3:-$CAN_LEGIT_IDS_DEFAULT}"

    if [[ -z "$iface" || -z "$out_log" ]]; then
        echo "[can_capture_start] uso: <iface> <out_log> [filter]" >&2
        return 1
    fi

    # Garante que a interface existe (não criamos aqui — é responsabilidade
    # do master_run_sw.sh; aqui só checamos para falhar cedo).
    if ! ip link show "$iface" >/dev/null 2>&1; then
        echo "[can_capture_start] interface $iface não existe" >&2
        echo ""
        return 0
    fi

    mkdir -p "$(dirname "$out_log")"

    # candump -t a   → timestamp absoluto Unix epoch (segundos.microssegundos)
    # candump -L     → formato log compatível com canplayer
    # iface,filter   → só captura frames cujo ID casa com a máscara
    candump -t a -L "${iface},${filter}" >"$out_log" 2>/dev/null &
    local pid=$!

    # 100ms para estabilizar o socket. Se morreu antes, abortamos.
    sleep 0.1
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "[can_capture_start] candump morreu na inicialização ($iface)" >&2
        echo ""
        return 0
    fi

    echo "$pid"
}

# can_capture_stop <pid>
#
# Sinaliza candump (TERM), espera ele sair, e força flush para disco.
# Tolera PID vazio (no-op) — útil para o caller poder fazer:
#
#   PID="$(can_capture_start ...)"   # eventualmente vazio
#   ...
#   can_capture_stop "$PID"          # seguro mesmo se vazio
can_capture_stop() {
    local pid="$1"
    [[ -z "$pid" ]] && return 0

    # candump responde a SIGTERM fazendo flush ordenado.
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
}

# can_capture_count <log_file>
#
# Imprime o número de frames no log (linhas que começam com '('). Usado
# pelos scripts para diagnóstico ("capturei N frames legítimos nesta rodada").
can_capture_count() {
    local f="$1"
    [[ -f "$f" ]] || { echo 0; return; }
    grep -c '^(' "$f" 2>/dev/null || echo 0
}
