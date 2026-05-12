# Process-attached
python3 analyze_absolute.py    --master-dir master_results/20260506-175507
python3 plot_absolute.py       --master-dir master_results/20260506-175507

# System-wide
python3 analyze_overhead_sw.py --master-dir resultados-sw/20260506-210207
python3 analyze_latency.py     --master-dir resultados-sw/20260506-210207
python3 plot_latency.py        --master-dir resultados-sw/20260506-210207