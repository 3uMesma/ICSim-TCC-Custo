# Define o FORMATO CANÔNICO de saída usado pelos três cenários experimentais
# (baseline, cen2-firewall, cen3-secoc). Além disso, todos os scripts 
# precisam para emitir esse formato:
#
#     scenario;component;attack;run;metric;value;unit
#
# onde:
#   scenario  ∈ {baseline, cen2, cen3}
#   component ∈ {process, gateway, sender}
#                 process : processo do ataque (medido no baseline)
#                 gateway : firewall (cen2) ou secoc_gateway (cen3)
#                 sender  : secoc_sender (cen3, ECU autenticadora)
#   attack    ∈ {dos-py, dos-cangen, fuzzing, replay, spoofing, idle}
#   run       inteiro ≥ 1 (índice da repetição)
#   metric    nome do evento perf (cycles, instructions, task-clock, …)
#   value     valor escalar — contagem absoluta ou duração
#   unit      vazio para contagens; "msec" para task-clock; etc.

PERF_CSV_HEADER="scenario;component;attack;run;metric;value;unit"
PERF_EVENTS_DEFAULT="cycles,instructions,cache-references,cache-misses,context-switches,page-faults,task-clock"

# Garante que <out> existe e começa com o header canônico
perf_csv_init() {
    local out="$1"
    [[ -n "$out" ]] || return 0
    mkdir -p "$(dirname "$out")"
    if [[ ! -s "$out" ]] || [[ "$(head -n1 "$out" 2>/dev/null)" != "$PERF_CSV_HEADER" ]]; then
        echo "$PERF_CSV_HEADER" > "$out"
    fi
}

# Lê o CSV nativo do `perf stat -x ';' -o <raw_in>` e acrescenta linhas
# tidy a <out_csv>. <raw_in> é apagado ao final (para evitar acúmulo de
# arquivos temporários entre repetições).
perf_csv_append_raw() {
    local raw="$1" out="$2"
    local scenario="$3" component="$4" attack="$5" run="$6"

    perf_csv_init "$out"
    [[ -s "$raw" ]] || { rm -f "$raw"; return 0; }

    # Cada linha útil do `perf -x ';'` tem o formato:
    #   value;unit;event;counter_runtime;pct_run;metric_value;metric_unit
    while IFS=';' read -r value unit event _rest; do
        [[ -z "$value" || "$value" == \#* ]] && continue
        # Remove TODO whitespace dos campos primários
        value="${value//[[:space:]]/}"
        unit="${unit//[[:space:]]/}"
        event="${event//[[:space:]]/}"
        # remove modificador (cycles:u → cycles)
        event="${event%%:*}"
        # Rejeita '<not counted>', '<not supported>', linha sem evento, etc.
        [[ -z "$event" || -z "$value" || "$value" == "<"* ]] && continue
        echo "${scenario};${component};${attack};${run};${event};${value};${unit}" >> "$out"
    done < "$raw"

    rm -f "$raw"
}

# MAIN
perf_csv_run() {
    local out="$1"; local scenario="$2"; local component="$3"
    local attack="$4"; local run="$5"; local events="$6"
    shift 6

    local raw
    raw="$(mktemp -t perfcsv.XXXXXX)"
    LC_NUMERIC=C perf stat -x ';' -e "$events" -o "$raw" "$@" 2>/dev/null || true
    perf_csv_append_raw "$raw" "$out" "$scenario" "$component" "$attack" "$run"
}
