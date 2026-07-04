# setup_vcan_triple.sh - Sobe os três barramentos virtuais do cen3 (CAN FD).
#
# Topologia:
#   vcan_trust (zona confiável - controls/cangen legítimo -> secoc_sender)
#   vcan0      (barramento      - secoc_sender + atacante  -> secoc_gateway)
#   vcan1      (zona crítica     - secoc_gateway            -> ICSim)
#
# Todas com MTU 72 para carregar frame CAN FD (payload de até 64 B).
set -euo pipefail

need_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo "[erro] este script precisa de root (para modprobe / ip link)."
        echo "      execute: sudo $0"
        exit 1
    fi
}

up_iface() {
    local iface="$1"
    if ip link show "$iface" &>/dev/null; then
        echo "[info] $iface já existe — verificando estado..."
    else
        echo "[info] criando $iface"
        ip link add dev "$iface" type vcan
    fi
    ip link set "$iface" down 2>/dev/null || true
    ip link set "$iface" mtu 72          # CAN FD: payload de até 64 B
    ip link set up "$iface"
    echo "[ok]   $iface está UP (MTU 72, CAN FD)"
}

need_root
echo "[info] carregando módulos (vcan/can)..."
modprobe can 2>/dev/null || true
modprobe vcan

up_iface vcan_trust
up_iface vcan0
up_iface vcan1

echo
echo "========================================================"
echo " Interfaces prontas (MTU 72). Verificação:"
echo "========================================================"
ip -br link show type vcan
