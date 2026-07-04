include ../make.inc

CFLAGS   += -I../lib

LIB_SRC  := aes.c cmac.c secoc.c secoc_assocs.c
LIB_OBJ  := $(LIB_SRC:.c=.o)
CAN_IO_OBJ := can_io.o

BIN_SENDER  := secoc_sender
BIN_GATEWAY := secoc_gateway
BIN_TEST    := test_cmac
BIN_MICRO   := micro_secoc

SWEEP_LENS  := 4 8 20 36 52
SENDER_SRC  := secoc_sender.c  aes.c cmac.c secoc.c secoc_assocs.c ../lib/can_io.c
GATEWAY_SRC := secoc_gateway.c aes.c cmac.c secoc.c secoc_assocs.c ../lib/can_io.c

.PHONY: all sweep micro clean clean-logs format test perf-check

all: $(BIN_SENDER) $(BIN_GATEWAY)

$(BIN_SENDER): secoc_sender.o $(LIB_OBJ) $(CAN_IO_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BIN_GATEWAY): secoc_gateway.o $(LIB_OBJ) $(CAN_IO_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BIN_TEST): test_cmac.o $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Microbenchmark da Fase 2 (rdtscp; não usa can_io).
$(BIN_MICRO): micro_secoc.o $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

micro: $(BIN_MICRO)

# Variantes do sweep de payload: secoc_{sender,gateway}-<len>.
sweep:
	@for L in $(SWEEP_LENS); do \
	  echo "  [sweep] plain=$$L"; \
	  $(CC) $(CFLAGS) -DSWEEP_PLAIN_LEN=$$L -o $(BIN_SENDER)-$$L  $(SENDER_SRC)  $(LDFLAGS); \
	  $(CC) $(CFLAGS) -DSWEEP_PLAIN_LEN=$$L -o $(BIN_GATEWAY)-$$L $(GATEWAY_SRC) $(LDFLAGS); \
	done

%.o: %.c secoc.h
	$(CC) $(CFLAGS) -c $< -o $@

can_io.o: ../lib/can_io.c ../lib/can_io.h
	$(CC) $(CFLAGS) -c ../lib/can_io.c -o can_io.o

test: $(BIN_TEST)
	./$(BIN_TEST)

clean:
	rm -f $(BIN_SENDER) $(BIN_GATEWAY) $(BIN_TEST) $(BIN_MICRO) \
	      $(BIN_SENDER)-* $(BIN_GATEWAY)-* *.o

clean-logs:
	sudo rm -rf results/

format:
	clang-format -i *.c *.h
