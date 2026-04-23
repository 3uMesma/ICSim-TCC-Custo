CC       ?= gcc
CFLAGS   ?= -O2 -g -Wall -Wextra -Wpedantic -std=gnu11
LDFLAGS  ?=

LIB_SRC  := aes.c cmac.c secoc.c secoc_assocs.c
LIB_OBJ  := $(LIB_SRC:.c=.o)
BIN_SENDER  := secoc_sender
BIN_GATEWAY := secoc_gateway
BIN_TEST    := test_cmac

.PHONY: all clean format test perf-check

all: $(BIN_SENDER) $(BIN_GATEWAY)

$(BIN_SENDER): secoc_sender.o $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BIN_GATEWAY): secoc_gateway.o $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BIN_TEST): test_cmac.o $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c secoc.h
	$(CC) $(CFLAGS) -c $< -o $@

# Executa os vetores da RFC 4493 e um smoke test de protect/verify.
test: $(BIN_TEST)
	./$(BIN_TEST)

clean:
	rm -f $(BIN_SENDER) $(BIN_GATEWAY) $(BIN_TEST) *.o
	
clean-logs:
	sudo rm -rf results/

format:
	clang-format -i *.c *.h
