include ../make.inc

CFLAGS   += -I../lib

# --- Header gerado (gateway.c inclui allowlist_sweep.h para g_macro_ids) ---
# Grafia: allowlist-scaling (um "l"). Ajuste SWEEP_DIR se não usou generated/.
SWEEP_DIR := ../allowlist-scaling/gen
SWEEP     := $(SWEEP_DIR)/allowlist_sweep.h
CFLAGS    += -I$(SWEEP_DIR)
# --------------------------------------------------------------------------

BIN      := gateway
SRC      := gateway.c allowlist.c ../lib/can_io.c
OBJ      := gateway.o allowlist.o can_io.o

.PHONY: all clean clean-logs format perf-check variants

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

gateway.o: gateway.c allowlist.h ../lib/can_io.h $(SWEEP)
	$(CC) $(CFLAGS) -c gateway.c -o gateway.o

allowlist.o: allowlist.c allowlist.h
	$(CC) $(CFLAGS) -c allowlist.c -o allowlist.o

can_io.o: ../lib/can_io.c ../lib/can_io.h
	$(CC) $(CFLAGS) -c ../lib/can_io.c -o can_io.o

# --- Variantes do macro: linear/direct × N=27/256 -------------------------
# Compiladas direto dos fontes (LOOKUP e ALLOWLIST_N mudam por binário).
# A binária fica só no micro. N=3 reproduz a allowlist original do TCC.
gateway-linear-27:  $(SRC) $(SWEEP)
	$(CC) $(CFLAGS) -DLOOKUP=LOOKUP_LINEAR -DALLOWLIST_N=27  $(SRC) -o $@ $(LDFLAGS)
gateway-linear-256: $(SRC) $(SWEEP)
	$(CC) $(CFLAGS) -DLOOKUP=LOOKUP_LINEAR -DALLOWLIST_N=256 $(SRC) -o $@ $(LDFLAGS)
gateway-direct-27:  $(SRC) $(SWEEP)
	$(CC) $(CFLAGS) -DLOOKUP=LOOKUP_DIRECT -DALLOWLIST_N=27  $(SRC) -o $@ $(LDFLAGS)
gateway-direct-256: $(SRC) $(SWEEP)
	$(CC) $(CFLAGS) -DLOOKUP=LOOKUP_DIRECT -DALLOWLIST_N=256 $(SRC) -o $@ $(LDFLAGS)

variants: gateway-linear-27 gateway-linear-256 gateway-direct-27 gateway-direct-256

clean:
	rm -f $(BIN) $(OBJ) gateway-linear-* gateway-direct-*

clean-logs:
	sudo rm -rf results/

format:
	clang-format -i *.c *.h