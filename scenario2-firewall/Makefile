include ../make.inc

CFLAGS   += -I../lib

# --- Extensão LARS (Fase 1) -----------------------------------------------
# Header gerado pelo synth_padding.py (arranjos g_micro_ids / g_macro_ids).
SWEEP_DIR := ../allowlist-scaling/
SWEEP     := $(SWEEP_DIR)/allowlist_sweep.h
CFLAGS    += -I$(SWEEP_DIR)
# --------------------------------------------------------------------------

BIN      := gateway
SRC      := gateway.c allowlist.c ../lib/can_io.c
OBJ      := gateway.o allowlist.o can_io.o

.PHONY: all clean clean-logs format perf-check variants diff-test

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

# gateway.c passou a incluir allowlist_sweep.h (g_macro_ids) -> depende de $(SWEEP).
gateway.o: gateway.c allowlist.h ../lib/can_io.h $(SWEEP)
	$(CC) $(CFLAGS) -c gateway.c -o gateway.o

allowlist.o: allowlist.c allowlist.h
	$(CC) $(CFLAGS) -c allowlist.c -o allowlist.o

can_io.o: ../lib/can_io.c ../lib/can_io.h
	$(CC) $(CFLAGS) -c ../lib/can_io.c -o can_io.o

# --- Variantes do macro: linear/direct × N=27/256 -------------------------
gateway-linear-27:  $(SRC) $(SWEEP)
	$(CC) $(CFLAGS) -DLOOKUP=LOOKUP_LINEAR -DALLOWLIST_N=27  $(SRC) -o $@ $(LDFLAGS)
gateway-linear-256: $(SRC) $(SWEEP)
	$(CC) $(CFLAGS) -DLOOKUP=LOOKUP_LINEAR -DALLOWLIST_N=256 $(SRC) -o $@ $(LDFLAGS)
gateway-direct-27:  $(SRC) $(SWEEP)
	$(CC) $(CFLAGS) -DLOOKUP=LOOKUP_DIRECT -DALLOWLIST_N=27  $(SRC) -o $@ $(LDFLAGS)
gateway-direct-256: $(SRC) $(SWEEP)
	$(CC) $(CFLAGS) -DLOOKUP=LOOKUP_DIRECT -DALLOWLIST_N=256 $(SRC) -o $@ $(LDFLAGS)

variants: gateway-linear-27 gateway-linear-256 gateway-direct-27 gateway-direct-256

# --- Teste diferencial (Fase 1) -------------------------------------------
diff-test: allowlist.c diff_test.c $(SWEEP)
	$(CC) $(CFLAGS) allowlist.c diff_test.c -o diff_test && ./diff_test

clean:
	rm -f $(BIN) $(OBJ) gateway-linear-* gateway-direct-* diff_test

clean-logs:
	sudo rm -rf results/

format:
	clang-format -i *.c *.h