# setup_vcan_triple.sh - Sobe os três barramentos virtuais CAN do Cenário 3.
#
# Topologia:
#   vcan_trust  (zona "confiável"     - controls legítimo)
#   vcan0       (zona "comprometida"  - sender autenticado + ataques)
#   vcan1       (zona "crítica"       - ICSim)
#
# Fluxo:
#   controls  -[vcan_trust]->  secoc_sender  -[vcan0]->  secoc_gateway  -[vcan1]->  icsim
#                                      ^-- atacantes injetam AQUI (cru, sem MAC) --^
#
# A separação vcan_trust / vcan0 materializa, no experimento, a
# *trusted computing base* do SecOC: o sender só recebe mensagens de um
# domínio em que se confia por construção.
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

up_iface vcan_trust
up_iface vcan0
up_iface vcan1

echo
echo "========================================================"
echo " Interfaces prontas. Verificação:"
echo "========================================================"
ip -br link show type vcan
echo
echo "Para o Cenário 3 rode, em quatro terminais separados:"
echo "  1) ./secoc_sender  -i vcan_trust -o vcan0   # ECU autenticadora"
echo "  2) ./secoc_gateway -i vcan0      -o vcan1   # gateway verificador"
echo "  3) ../ICSim-TCC-Custo/icsim   vcan1         # ICSim atrás do gateway"
echo "  4) ../ICSim-TCC-Custo/controls vcan_trust   # controles legítimos"
echo