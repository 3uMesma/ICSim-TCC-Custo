# ICSim-TCC-Custo
**Undergraduate thesis title:** *Analysis of the Computational Cost of Security Mechanisms in CAN Networks*.
**Academic affiliation:** Undergraduate thesis in Computer Science (USP), under the supervision of Professor Kalinka Castelo Branco (ICMC – USP).
**Paper/project summary:** with the transition to zonal architectures and the adoption of Security Gateways in modern vehicles, this work investigates the trade-off between cybersecurity protection and latency in critical embedded systems. This project is a fork of [Craig Smith's ICSim](https://github.com/zombieCraig/ICSim), which allowed us to focus on the security analysis without needing to build a CAN simulator from scratch. The work compares three scenarios (`baseline`, `cen2/firewall`, `cen3/secoc`) under five attacks (`dos-py`, `dos-cangen`, `fuzzing`, `replay`, `spoofing`), using `perf` to quantify processing overhead and impact on response time.

# README structure
This README was adapted from the SBRC (CTA) artifact evaluation template and covers the following requirements:

1. Basic Information.
2. Repository Structure.
3. Project Dependencies.
4. Security Considerations.
5. Installation.
6. Minimal Test.
7. Experiments (with claims in subsections).
8. License.

# Basic Information
- **Scientific objective of the artifact:** to quantify the CPU and latency cost introduced by security mechanisms in CAN.
- **Research question:** what is the computational impact of defense mechanisms (firewall and simplified SecOC) when subjected to stress attacks on a simulated CAN network?
- **Evaluated scenarios:**
  - `baseline`: no security (reference).
  - `cen2`: firewall/allowlist at the gateway.
  - `cen3`: simplified SecOC (authentication + freshness).
- **Evaluated attacks:** `dos-py`, `dos-cangen`, `fuzzing`, `replay`, `spoofing`.
- **Measurement modes:**
  - **Process-attached** (`master_run.sh`): `perf stat` attached to the target processes.
  - **System-wide** (`master_run_sw.sh`): `perf stat -a` on the entire system.
- **Expected execution environment:** Linux with SocketCAN (`vcan`) and `sudo/root` privileges.

# Repository Structure
The repository combines the original ICSim simulator by OpenGarages (Craig Smith / "Zombie Craig", licensed under GPL-3.0) with the entire infrastructure of defense scenarios, attacks, capture, and statistical analysis developed specifically for this thesis. The separation below makes explicit what came from upstream and what was added in this work.

## Inherited from the original ICSim (OpenGarages / Zombie Craig)
Files preserved from the upstream project, without behavioral changes:
- icsim.c, controls.c — instrument cluster simulator and command-sending application over CAN.
- lib.c, lib.h, lib.o — CAN utilities derived from can-utils, used by the simulator.
- Makefile, make.inc, meson.build — original simulator build.
- art/ — vector graphic assets (ic.svg, joypad.ora, joypad.xcf).
- data/ — sprites, icons, and traffic sample (ic.png, joypad.png, needle.png, spritesheet.png, sample-can.log).
- setup_vcan.sh — original script to bring up the vcan0 interface.
- README-historico.md — original ICSim README, kept for historical reference.
- LICENSE, .clang-format.

## Added in this thesis
Everything else was built from scratch on top of ICSim:

Measurement scenarios (C):
- scenario1-baseline/ — reference execution, without protection. Includes run_experiments.sh and run_experiments_sw.sh.
- scenario2-firewall/ — gateway with allowlist (IDs, DLC, and send rate): gateway.c, allowlist.c/.h, setup_vcan_dual.sh, run_scenario2.sh, run_scenario2_sw.sh, and its own Makefile.
- scenario3-secoc/ — simplified SecOC (AES-CMAC + freshness value) with separate sender and gateway: secoc_sender.c, secoc_gateway.c, secoc.c/.h, secoc_assocs.c, aes.c, cmac.c, test_cmac.c, setup_vcan_triple.sh, and run_scenario3*.sh scripts.

Attacks (Python + shell):
- scripts-attacks/ — DoS-attack.py, Fuzzy-attack.py, Replay-attack.py, Spoofing-attack.py, and dos-cangen-attack.sh.
- scripts-attacks/lib/ — shared modules across the attacks (attack_runtime.py, candump_io.py, icsim_frames.py).

Experiment orchestration and analysis:
- master-experiment/master_run.sh, master-experiment/master_run_sw.sh — process-attached and system-wide campaigns.
- master-experiment/analyze_absolute.py, analyze_all.py, analyze_latency.py, analyze_overhead_sw.py — statistical post-processing.
- master-experiment/plot_absolute.py, plot_latency.py — figure generation.
- master-experiment/parse_gateway_logs.py, split_baseline_to_raw.py, roda_analise_tudo.sh — pipeline utilities.
- master-experiment/lib/ — shared Python library for the analysis (perf_io.py, stats.py, plotting.py, latex.py, constants.py).

Shared scenario library (lib/):
- lib/can_io.c, lib/can_io.h — canonical-format CAN capture/write, used by the gateways of scenarios 2 and 3.
- lib/can_capture.sh, lib/probes.sh, lib/perf_csv.sh, lib/log.sh, lib/governor.sh — helpers for candump/perf collection and CPU governor control.

Build, configuration, and documentation:
- experiments.mk — targets cen-all, all-with-base, etc., to compile the scenarios without interfering with the original Makefile.
- README.md — this file, in the CTA/SBRC format.

# Project Dependencies
## System dependencies
Example (Arch Linux):

```bash
sudo pacman -Syu
sudo pacman -S --needed \
  base-devel clang \
  sdl2 sdl2_image \
  can-utils iproute2 kmod \
  perf \
  python python-pip bc
```

## Python dependencies
```bash
python3 -m pip install --upgrade pip
python3 -m pip install python-can pandas numpy matplotlib
```

## Main Tools
- `gcc`, `make` → C compiler and build tool; required to compile the ICSim code
- `perf` → Linux kernel tool to measure performance and CPU overhead
- `python-can` → Python library for communication with CAN networks; used in attack scripts (`dos-py`, `replay`, etc.)
- `candump`/`cangen` (`can-utils` package) → CLI utilities from the `can-utils` package; `cangen` generates CAN traffic (used in the `dos-cangen` attack) and `candump` captures packets on the interface
- kernel modules: `can` and `vcan` → `can` is the base driver for the CAN protocol on Linux; `vcan` creates a virtual CAN interface, which is what allows simulating the network without physical hardware

# Security Considerations
1. **Privileged execution:** the experiment scripts use `sudo` for `perf`, `modprobe`, and `ip link`.
2. **Aggressive attack traffic:** DoS/Fuzzing/Spoofing generate high frame rates.
3. **CAN interfaces:** the experiments are designed for `vcan*` (virtual), not for physical buses.
4. **Log removal:** targets such as `clean-logs` delete result directories.

# Installation
## 1) Clone the repository
```bash
git clone https://github.com/3uMesma/ICSim-TCC-Custo.git
cd ICSim-TCC-Custo
```

## 2) Build the base ICSim
```bash
make all
```

## 3) Build the experimental scenarios
```bash
make -f experiments.mk cen-all
```

Optional (build everything at once):
```bash
make -f experiments.mk all-with-base
```

## 4) (Optional) Test the SecOC cryptographic implementation
```bash
cd scenario3-secoc
make test
cd ..
```

## 5) Bring up the virtual CAN interfaces
For simple baseline:
```bash
sudo ./setup_vcan.sh
```

For gateway/SecOC scenarios, the specific scripts can also prepare the interfaces:
- `scenario2-firewall/setup_vcan_dual.sh`
- `scenario3-secoc/setup_vcan_triple.sh`

# Minimal Test
Goal: confirm that the artifact builds and runs with observable functionality.

## Step by step
1. In one terminal:
```bash
./icsim vcan0
```
2. In another terminal:
```bash
./controls vcan0
```
3. In a third terminal, run a short attack:
```bash
python3 scripts-attacks/DoS-attack.py --iface vcan0 --duration 5 --rate 0
```

Expected result:
- active `icsim` window;
- attack output with a `[RESULT] ...` line;
- CAN traffic visible in `candump vcan0` (if monitored).

## Automated minimal test (scenario 2, 1 short run)
```bash
sudo ./scenario2-firewall/run_scenario2.sh idle 5
```
Expected result:
- creation of a folder under `scenario2-firewall/results/`;
- `gateway.log` and `perf_gateway.raw` generated;
- final message `[ok] experiment complete`.

# Experiments
This section describes how to reproduce the main claims of the paper.

## Default experiment configuration
- Attacks: `dos-py dos-cangen fuzzing replay spoofing`
- Duration per run: `30s`
- Repetitions:
  - Process-attached: `20`
  - System-wide: `10`
- Cooldown: `5s`

Approximate raw time:
- Process-attached: `3 scenarios × 5 attacks × 20 reps × (30+5)s ≈ 2.9h` (+ setup/post-processing overhead)
- System-wide: `3 scenarios × 5 attacks × 10 reps × (30+5)s ≈ 1.5h` (+ setup/post-processing overhead)

## Claim #1
**(Absolute computational cost of the security layer: baseline vs firewall vs SecOC)**
Reproduces tables and figures of cost by `cycles`, `instructions`, and `task-clock` in process-attached mode.

### Execution command
```bash
sudo ./master-experiment/master_run.sh \
  -n 20 -d 30 -c 5 \
  -s baseline,cen2,cen3 \
  -a dos-py,dos-cangen,fuzzing,replay,spoofing
```

### Expected output files
In `master-experiment/master_results/<TIMESTAMP>/`:
- `perf_data.csv`
- `summary_all.csv`
- `absolute_cost.csv`
- `normalized_cost.csv`
- `figuras/` (generated during post-processing)

### Expected result
- `cen2` and `cen3` with cost higher than `baseline`;
- `cen3/total` (gateway + sender) above `cen2/gateway` for absolute cost metrics.

## Claim #2
**(System-wide overhead and forwarding latency)**
Reproduces global overhead and latency/jitter in `perf stat -a` mode.

### Execution command
```bash
sudo ./master-experiment/master_run_sw.sh \
  -n 10 -d 30 -c 5 \
  -s baseline,cen2,cen3 \
  -a dos-py,dos-cangen,fuzzing,replay,spoofing
```

### Expected output files
In `master-experiment/resultados-sw/<TIMESTAMP>/`:
- `perf_data.csv`
- `overhead_sw.csv` and `overhead_sw.tex`
- `latency_summary.csv`, `jitter_summary.csv`
- `figuras-lat/` with boxplot, CDF, and p99

### Expected result
- `cen3` overhead above `cen2` for some of the attacks;
- `secoc_total` latency higher than `firewall` latency under equivalent load scenarios.

# LICENSE
This project is licensed under **GPL-3.0** (see `LICENSE` file).
