# Define o FORMATO CANÔNICO de saída usado pelos três cenários experimentais
# (baseline, cen2-firewall, cen3-secoc) e fornece os dois primitivos que
# todos os scripts precisam para emitir esse formato:
#
#     scenario;component;attack;run;metric;value;unit
#
# onde:
#   scenario  ∈ {baseline, cen2, cen3}
#   component ∈ {process, gateway, sender, system}
#                 process : processo do ataque (medido no baseline, modo -p)
#                 gateway : firewall (cen2) ou secoc_gateway (cen3, modo -p)
#                 sender  : secoc_sender (cen3, ECU autenticadora, modo -p)
#                 system  : medida system-wide (perf stat -a, todos os cores)
#   attack    ∈ {dos-py, dos-cangen, fuzzing, replay, spoofing, idle}
#   run       inteiro ≥ 1 (índice da repetição)
#   metric    nome do evento perf (cycles, instructions, task-clock, …)
#   value     valor escalar — contagem absoluta ou duração
#   unit      vazio para contagens; "msec" para task-clock; etc.
#

# Header canônico (constante).
PERF_CSV_HEADER="scenario;component;attack;run;metric;value;unit"

# Conjunto padrão de eventos. Pode ser sobrescrito por chamada se necessário.
PERF_EVENTS_DEFAULT="cycles,instructions,cache-references,cache-misses,context-switches,page-faults,task-clock"

# perf_csv_init <out>
#
# Garante que <out> existe e começa com o header canônico. Idempotente:
# se o arquivo já tem o header certo, não faz nada — assim várias chamadas
# (de scripts diferentes, ou de várias reps) podem appendar com segurança.
perf_csv_init() {
    local out="$1"
    [[ -n "$out" ]] || return 0
    mkdir -p "$(dirname "$out")"
    if [[ ! -s "$out" ]] || [[ "$(head -n1 "$out" 2>/dev/null)" != "$PERF_CSV_HEADER" ]]; then
        echo "$PERF_CSV_HEADER" > "$out"
    fi
}

# perf_csv_append_raw <raw_in> <out_csv> <scenario> <component> <attack> <run>
#
# Lê o CSV nativo do `perf stat -x ';' -o <raw_in>` e acrescenta linhas
# tidy a <out_csv>. <raw_in> é apagado ao final (para evitar acúmulo de
# arquivos temporários entre repetições).
#
# Tolera as seguintes patologias do output do perf:
#   * linhas iniciadas com '#' (cabeçalho/comentário)
#   * '<not counted>' ou '<not supported>' no campo de valor
#   * espaços em branco ao redor dos campos (alguns kernels emitem)
#   * modificadores de evento como ":u" ou ":k" (são removidos)
perf_csv_append_raw() {
    local raw="$1" out="$2"
    local scenario="$3" component="$4" attack="$5" run="$6"

    perf_csv_init "$out"
    [[ -s "$raw" ]] || { rm -f "$raw"; return 0; }

    # Cada linha útil do `perf -x ';'` tem o formato:
    #   value;unit;event;counter_runtime;pct_run;metric_value;metric_unit
    while IFS=';' read -r value unit event _rest; do
        [[ -z "$value" || "$value" == \#* ]] && continue
        # Remove TODO whitespace dos campos primários — números e nomes de
        # evento/unidade nunca têm espaços internos relevantes (o "insn per
        # cycle" fica no metric_unit, que descartamos).
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

# perf_csv_run <out_csv> <scenario> <component> <attack> <run> <events> -- <perf_args...>
#
# Atalho para o caso síncrono: chama
#     perf stat -x ';' -e <events> -o <tmp> <perf_args...>
# e em seguida passa por `perf_csv_append_raw`. <perf_args...> é o que viria
# DEPOIS do `--` em uma chamada normal de `perf stat` — tipicamente
# `bash -c "exec <comando do ataque>"`.
perf_csv_run() {
    local out="$1"; local scenario="$2"; local component="$3"
    local attack="$4"; local run="$5"; local events="$6"
    shift 6

    local raw
    raw="$(mktemp -t perfcsv.XXXXXX)"
    LC_NUMERIC=C perf stat -x ';' -e "$events" -o "$raw" "$@" 2>/dev/null || true
    perf_csv_append_raw "$raw" "$out" "$scenario" "$component" "$attack" "$run"
}

# perf_csv_run_systemwide <out_csv> <scenario> <attack> <run> <duration_s> <events>
#
# Coleta SYSTEM-WIDE (`perf stat -a`) durante <duration_s> segundos. Use este
# primitivo na ETAPA C (campanha system-wide), em que o objetivo é medir o
# custo agregado da camada de segurança sobre TODO o sistema, não sobre um
# processo específico. Ideal para a comparação `overhead = cen − baseline`,
# pois o "denominador" (sistema operacional inteiro) é o mesmo nos três
# cenários.
#
# Diferenças em relação a `perf_csv_run`:
#   * usa `-a` (system-wide) em vez de `-p PID` ou wrap de comando
#   * não dispara o workload — quem dispara é o caller (assíncrono):
#         iniciar gateway/sender em bg →
#         iniciar ataque em bg →
#         chamar perf_csv_run_systemwide bloqueante por DURATION s
#   * o `component` é fixado como "system" (sem parâmetro), uma vez que
#     system-wide não distingue processos.
#
# task-clock em modo system-wide é reportado em msec acumulado entre todos
# os cores, então em uma máquina com N cores e 30 s de janela o valor pode
# chegar a ~30 000 × N. Esta é uma característica esperada do `perf` e o
# analisador (analyze_overhead_sw.py) precisa estar ciente.
perf_csv_run_systemwide() {
    local out="$1"; local scenario="$2"; local attack="$3"
    local run="$4"; local duration="$5"; local events="$6"

    local raw
    raw="$(mktemp -t perfcsvsw.XXXXXX)"
    # `perf stat -a` exige privilégio (kernel.perf_event_paranoid<=0 ou root).
    # Roda perf bloqueante por <duration> s observando todos os cores.
    LC_NUMERIC=C perf stat -a -x ';' -e "$events" -o "$raw" \
        -- sleep "$duration" 2>/dev/null || true
    perf_csv_append_raw "$raw" "$out" "$scenario" system "$attack" "$run"
}
