include ../make.inc

# Instrumentos de medição da escala da allowlist. Compilam contra o allowlist.c
# do gateway (em ../scenario2-firewall) + o header gerado em generated/.
S2    := ../scenario2-firewall
GEN   := gen
IDS   := extraction-HCRL/allowlist_ids.h
MICRO := micro/microbench.c
DIFF  := micro/diff_test.c

CFLAGS += -I$(S2) -I$(GEN)
SWEEP  := $(GEN)/allowlist_sweep.h

.PHONY: diff-test id-tables clean

# Microbenchmark: custo por lookup
microbench: $(MICRO) $(S2)/allowlist.c $(SWEEP)
	$(CC) $(CFLAGS) $(MICRO) $(S2)/allowlist.c -o microbench

# Teste diferencial: os três backends devem concordar em todo o sweep.
diff-test: $(DIFF) $(S2)/allowlist.c $(SWEEP)
	$(CC) $(CFLAGS) $(DIFF) $(S2)/allowlist.c -o diff_test && ./diff_test

# Regenera o header do sweep a partir dos IDs reais.
id-tables: $(IDS)
	python3 gen/synth_padding.py $(IDS) \
	  --header-out $(SWEEP) --manifest-out $(GEN)/padding_manifest.csv

clean:
	rm -f microbench diff_test
