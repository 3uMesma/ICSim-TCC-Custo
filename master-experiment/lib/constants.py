# Constantes canônicas compartilhadas entre os scripts de análise.

from __future__ import annotations

# Ordem de apresentação dos ataques nas tabelas/figuras.
ATTACK_ORDER: list[str] = [
    "dos-py", "dos-cangen", "fuzzing", "spoofing", "replay",
]

# Métricas perf focadas no relatório de custo absoluto (5 itens).
PERF_METRICS_FOCUS_ABSOLUTE: list[str] = [
    "cycles", "instructions", "task-clock",
    "context-switches", "cache-misses",
]

# Métricas perf focadas no relatório system-wide (6 itens — inclui page-faults).
PERF_METRICS_FOCUS_SW: list[str] = [
    "cycles", "instructions", "task-clock",
    "context-switches", "cache-misses", "page-faults",
]

NORMALIZE_EXCLUDE: set[str] = set()

# IDs legítimos da allowlist do projeto (hex sem 0x).
LEGITIMATE_IDS: set[str] = {"244", "188", "19B"}

# Etapas de latência por cenário, formato (label, input_log, output_log).
SCENARIO_STAGES: dict[str, list[tuple[str, str, str]]] = {
    "cen2": [
        ("firewall", "can_in.log", "can_out.log"),
    ],
    "cen3": [
        ("secoc_sender",  "can_trust.log", "can_bus.log"),
        ("secoc_gateway", "can_bus.log",   "can_out.log"),
        ("secoc_total",   "can_trust.log", "can_out.log"),
    ],
}

# Ordem (cenário, componente) para o eixo X de tabelas wide.
SCENARIO_ORDER_ABSOLUTE: list[tuple[str, str]] = [
    ("cen2", "gateway"),
    ("cen3", "gateway"),
    ("cen3", "sender"),
    ("cen3", "total"),
]
