include ../make.inc

CFLAGS   += -I../lib

LIB_SRC  := aes.c cmac.c secoc.c secoc_assocs.c
LIB_OBJ  := $(LIB_SRC:.c=.o)
CAN_IO_OBJ := can_io.o

BIN_SENDER  := secoc_sender
BIN_GATEWAY := secoc_gateway
BIN_TEST    := test_cmac

.PHONY: all clean clean-logs format test perf-check

all: $(BIN_SENDER) $(BIN_GATEWAY)

$(BIN_SENDER): secoc_sender.o $(LIB_OBJ) $(CAN_IO_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BIN_GATEWAY): secoc_gateway.o $(LIB_OBJ) $(CAN_IO_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BIN_TEST): test_cmac.o $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Regra genérica para os .c locais (dependem de secoc.h).
%.o: %.c secoc.h
	$(CC) $(CFLAGS) -c $< -o $@

# Regra explícita para can_io.o vindo de ../lib.
can_io.o: ../lib/can_io.c ../lib/can_io.h
	$(CC) $(CFLAGS) -c ../lib/can_io.c -o can_io.o

# Executa os vetores da RFC 4493 e um smoke test de protect/verify.
test: $(BIN_TEST)
	./$(BIN_TEST)

clean:
	rm -f $(BIN_SENDER) $(BIN_GATEWAY) $(BIN_TEST) *.o

clean-logs:
	sudo rm -rf results/

format:
	clang-format -i *.c *.h
