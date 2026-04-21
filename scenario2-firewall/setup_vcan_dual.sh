# setup_vcan_dual.sh - Sobe os dois barramentos virtuais CAN 
#
# Topologia:
#   vcan0  (zona "comprometida" - controls legítimo + scripts de ataque)
#   vcan1  (zona "crítica"      - ICSim)
# 
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
    ip link set up "$iface"
    echo "[ok]   $iface está UP"
}

need_root
echo "[info] carregando módulos (vcan/can)..."
modprobe can 2>/dev/null || true
modprobe vcan

up_iface vcan0
up_iface vcan1

echo
echo "========================================================"
echo " Interfaces prontas. Verificação:"
echo "========================================================"
ip -br link show type vcan
