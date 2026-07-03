include ../make.inc

# Instrumentos de medição da escala da allowlist. Compilam contra o allowlist.c
# do gateway (em ../scenario2-firewall) + o header gerado em generated/.
S2  := ../scenario2-firewall
MICRO  := ./micro/micro.c
DIFF_TEST := ./micro/diff_test.c
CFLAGS += -I$(S2) -I$(GEN)
SWEEP := $(GEN)/allowlist_sweep.h

.PHONY: diff-test id-tables clean

# Microbenchmark: custo por lookup
micro: $(MICRO) $(S2)/allowlist.c $(SWEEP)
	$(CC) $(CFLAGS) $(MICRO) $(S2)/allowlist.c -o micro

# Teste diferencial: os três backends devem concordar em todo o sweep.
diff-test: $(DIFF_TEST) $(S2)/allowlist.c $(SWEEP)
	$(CC) $(CFLAGS) $(DIFF_TEST) $(S2)/allowlist.c -o diff_test && ./diff_test

# Regenera o header do sweep a partir dos IDs reais (precisa de allowlist_ids.h).
id-tables: $(GEN)/allowlist_ids.h
	python3 gen/synth_padding.py $(GEN)/allowlist_ids.h \
	  --header-out $(SWEEP) --manifest-out $(GEN)/padding_manifest.csv

clean:
	rm -f micro diff_test
