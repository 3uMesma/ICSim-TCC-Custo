# ICSim-TCC-Custo 
**Título do projeto de TCC:** *Análise do Custo Computacional de Mecanismos de Segurança em Redes CAN*.  
**Vínculo acadêmico:** Trabalho de Conclusão de Curso em Ciência da Computação (USP), sob orientação da professora Kalinka Castelo Branco (ICMC - USP).  
**Resumo do artigo/projeto:** com a transição para arquiteturas zonais e o uso de Security Gateways em veículos modernos, este trabalho investiga o trade-off entre proteção cibernética e latência em sistemas embarcados críticos. Este projeto é um fork do [ICSim de Craig Smith](https://github.com/zombieCraig/ICSim), o que permitiu focar na análise de segurança sem a necessidade de construir um simulador CAN do zero. O trabalho compara três cenários (`baseline`, `cen2/firewall`, `cen3/secoc`) sob cinco ataques (`dos-py`, `dos-cangen`, `fuzzing`, `replay`, `spoofing`), utilizando `perf` para quantificar overhead de processamento e impacto no tempo de resposta.

# Estrutura do readme.md
Este README foi adaptado com base no modelo de avaliação de artefatos do SBRC (CTA) e cobre seguintes requisitos:

1. Informações Básicas.
2. Estrutura do Repositório.
2. Dependências do projeto.
4. Considerações de Segurança.
5. Instalação.
6. Teste mínimo.
5. Experimentos (com reivindicações em subseções).
6. Licença.

# Informações Básicas
- **Objetivo científico do artefato:** quantificar o custo de CPU e latência introduzido por mecanismos de segurança em CAN.
- **Pergunta de pesquisa:** qual é o impacto computacional de mecanismos de defesa (firewall e SecOC simplificado) quando submetidos a ataques de estresse em rede CAN simulada?
- **Cenários avaliados:**
  - `baseline`: sem segurança (referência).
  - `cen2`: firewall/allowlist no gateway.
  - `cen3`: SecOC simplificado (autenticação + freshness).
- **Ataques avaliados:** `dos-py`, `dos-cangen`, `fuzzing`, `replay`, `spoofing`.
- **Modos de medição:**
  - **Process-attached** (`master_run.sh`): `perf stat` anexado aos processos-alvo.
  - **System-wide** (`master_run_sw.sh`): `perf stat -a` no sistema todo.
- **Ambiente de execução esperado:** Linux com SocketCAN (`vcan`) e permissões `sudo/root`.

# Estrutura do Repositório
O repositório combina o simulador ICSim original do OpenGarages (Craig Smith / "Zombie Craig", licenciado em GPL-3.0) com toda a infraestrutura de cenários de defesa, ataques, captura e análise estatística desenvolvida especificamente para este TCC. A separação abaixo deixa explícito o que veio do upstream e o que foi adicionado neste trabalho.

## Herdado do ICSim original (OpenGarages / Zombie Craig)
Arquivos preservados do projeto upstream, sem mudanças de comportamento:
- icsim.c, controls.c — simulador do painel (Instrument Cluster) e aplicativo de envio de comandos via CAN.
- lib.c, lib.h, lib.o — utilitários CAN derivados do can-utils, usados pelo simulador.
- Makefile, make.inc, meson.build — build original do simulador.
- art/ — assets gráficos vetoriais (ic.svg, joypad.ora, joypad.xcf).
- data/ — sprites, ícones e amostra de tráfego (ic.png, joypad.png, needle.png, spritesheet.png, sample-can.log).
- setup_vcan.sh — script original para subir a interface vcan0.
- README-historico.md — README original do ICSim, mantido como referência histórica.
- LICENSE, .clang-format.

## Adicionado neste TCC
Todo o restante foi criado a partir do zero sobre o ICSim:

Cenários de medição (C):
- scenario1-baseline/ — execução de referência, sem proteção. Inclui run_experiments.sh e run_experiments_sw.sh.
- scenario2-firewall/ — gateway com allowlist (IDs, DLC e taxa de envio): gateway.c, allowlist.c/.h, setup_vcan_dual.sh, run_scenario2.sh, run_scenario2_sw.sh e Makefile próprio.
- scenario3-secoc/ — SecOC simplificado (AES-CMAC + freshness value) com sender e gateway separados: secoc_sender.c, secoc_gateway.c, secoc.c/.h, secoc_assocs.c, aes.c, cmac.c, test_cmac.c, setup_vcan_triple.sh e scripts run_scenario3*.sh.

Ataques (Python + shell):
- scripts-attacks/ — DoS-attack.py, Fuzzy-attack.py, Replay-attack.py, Spoofing-attack.py e dos-cangen-attack.sh.
- scripts-attacks/lib/ — módulos compartilhados entre os ataques (attack_runtime.py, candump_io.py, icsim_frames.py).

Orquestração e análise dos experimentos:
- master-experiment/master_run.sh, master-experiment/master_run_sw.sh — campanhas process-attached e system-wide.
- master-experiment/analyze_absolute.py, analyze_all.py, analyze_latency.py, analyze_overhead_sw.py — pós-processamento estatístico.
- master-experiment/plot_absolute.py, plot_latency.py — geração de figuras.
- master-experiment/parse_gateway_logs.py, split_baseline_to_raw.py, roda_analise_tudo.sh — utilitários de pipeline.
- master-experiment/lib/ — biblioteca Python compartilhada da análise (perf_io.py, stats.py, plotting.py, latex.py, constants.py).

Biblioteca compartilhada dos cenários (lib/):
- lib/can_io.c, lib/can_io.h — captura/escrita CAN em formato canônico, usadas pelos gateways dos cenários 2 e 3.
- lib/can_capture.sh, lib/probes.sh, lib/perf_csv.sh, lib/log.sh, lib/governor.sh — helpers de coleta com candump/perf e controle do governor de CPU.

Build, configuração e documentação:
- experiments.mk — alvos cen-all, all-with-base etc. para compilar os cenários sem interferir no Makefile original.
- README.md — este arquivo, no formato CTA/SBRC.

# Dependências do Projeto
## Dependências de sistema
Exemplo (Arch Linux):

```bash
sudo pacman -Syu
sudo pacman -S --needed \
  base-devel clang \
  sdl2 sdl2_image \
  can-utils iproute2 kmod \
  perf \
  python python-pip bc
```

## Dependências Python
```bash
python3 -m pip install --upgrade pip
python3 -m pip install python-can pandas numpy matplotlib
```

## Ferramentas Principais
- `gcc`, `make` → compilador C e ferramenta de build; necessários para compilar o código do ICSim
- `perf` → ferramenta do kernel Linux para medir performance e overhead de CPU
- `python-can` → biblioteca Python para comunicação com redes CAN; usada nos scripts de ataque (`dos-py`, `replay`, etc.)
- `candump`/`cangen` (pacote `can-utils`) → utilitários CLI do pacote `can-utils`; `cangen` gera tráfego CAN (usado no ataque `dos-cangen`) e `candump` captura pacotes na interface
- módulos de kernel: `can` e `vcan` → `can` é o driver base do protocolo CAN no Linux; `vcan` cria uma interface CAN virtual, que é o que permite simular a rede sem hardware físico

# Considerações de Segurança
1. **Execução com privilégios:** os scripts de experimento usam `sudo` para `perf`, `modprobe` e `ip link`.
2. **Tráfego agressivo de ataques:** DoS/Fuzzing/Spoofing geram alta taxa de frames.
3. **Interfaces CAN:** os experimentos são desenhados para `vcan*` (virtual), não para barramentos físicos. 
4. **Remoção de logs:** alvos como `clean-logs` removem diretórios de resultados.

# Instalação
## 1) Clonar o repositório
```bash
git clone https://github.com/3uMesma/ICSim-TCC-Custo.git
cd ICSim-TCC-Custo
```

## 2) Compilar ICSim base
```bash
make all
```

## 3) Compilar cenários experimentais
```bash
make -f experiments.mk cen-all
```

Opcional (compilar tudo de uma vez):
```bash
make -f experiments.mk all-with-base
```

## 4) (Opcional) Testar implementação criptográfica do SecOC
```bash
cd scenario3-secoc
make test
cd ..
```

## 5) Subir interfaces virtuais CAN
Para baseline simples:
```bash
sudo ./setup_vcan.sh
```

Para cenários com gateway/SecOC, os scripts específicos também podem preparar interfaces:
- `scenario2-firewall/setup_vcan_dual.sh`
- `scenario3-secoc/setup_vcan_triple.sh`

# Teste mínimo
Objetivo: confirmar que o artefato compila e executa funcionalidade observável.

## Passo a passo
1. Em um terminal:
```bash
./icsim vcan0
```
2. Em outro terminal:
```bash
./controls vcan0
```
3. Em um terceiro terminal, execute um ataque curto:
```bash
python3 scripts-attacks/DoS-attack.py --iface vcan0 --duration 5 --rate 0
```

Resultado esperado:
- janela do `icsim` ativa;
- saída do ataque com linha `[RESULTADO] ...`;
- tráfego CAN visível em `candump vcan0` (se monitorado).

## Teste mínimo automatizado (cenário 2, 1 rodada curta)
```bash
sudo ./scenario2-firewall/run_scenario2.sh idle 5
```
Resultado esperado:
- criação de pasta em `scenario2-firewall/results/`;
- `gateway.log` e `perf_gateway.raw` gerados;
- mensagem final `[ok] experiment concluído`.

# Experimentos
Esta seção descreve como reproduzir as principais reivindicações do artigo.

## Configuração padrão dos experimentos
- Ataques: `dos-py dos-cangen fuzzing replay spoofing`
- Duração por rodada: `30s`
- Repetições:
  - Process-attached: `20`
  - System-wide: `10`
- Cooldown: `5s`

Tempo bruto aproximado:
- Process-attached: `3 cenários × 5 ataques × 20 reps × (30+5)s ≈ 2.9h` (+ overhead de setup/pós-processamento)
- System-wide: `3 cenários × 5 ataques × 10 reps × (30+5)s ≈ 1.5h` (+ overhead de setup/pós-processamento)

## Reivindicação #1
**(Custo computacional absoluto da camada de segurança: baseline vs firewall vs SecOC)**  
Reproduz tabelas e figuras de custo por `cycles`, `instructions`, `task-clock` no modo process-attached.

### Comando de execução
```bash
sudo ./master-experiment/master_run.sh \
  -n 20 -d 30 -c 5 \
  -s baseline,cen2,cen3 \
  -a dos-py,dos-cangen,fuzzing,replay,spoofing
```

### Arquivos de saída esperados
Em `master-experiment/master_results/<TIMESTAMP>/`:
- `perf_data.csv`
- `summary_all.csv`
- `absolute_cost.csv`
- `normalized_cost.csv`
- `figuras/` (geradas no pós-processamento)

### Expectativa de resultado
- `cen2` e `cen3` com custo maior que `baseline`;
- `cen3/total` (gateway + sender) acima de `cen2/gateway` para métricas de custo absoluto.

## Reivindicação #2
**(Overhead system-wide e latência de encaminhamento)**  
Reproduz overhead global e latência/jitter no modo `perf stat -a`.

### Comando de execução
```bash
sudo ./master-experiment/master_run_sw.sh \
  -n 10 -d 30 -c 5 \
  -s baseline,cen2,cen3 \
  -a dos-py,dos-cangen,fuzzing,replay,spoofing
```

### Arquivos de saída esperados
Em `master-experiment/resultados-sw/<TIMESTAMP>/`:
- `perf_data.csv`
- `overhead_sw.csv` e `overhead_sw.tex`
- `latency_summary.csv`, `jitter_summary.csv`
- `figuras-lat/` com boxplot, CDF e p99

### Expectativa de resultado
- overhead de `cen3` acima de `cen2` para parte dos ataques;
- latência `secoc_total` superior à latência `firewall` em cenários equivalentes de carga.

# LICENSE
Este projeto está licenciado sob **GPL-3.0** (ver arquivo `LICENSE`).

