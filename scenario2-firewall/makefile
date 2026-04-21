CC       ?= gcc
CFLAGS   ?= -O2 -g -Wall -Wextra -Wpedantic -std=gnu11
LDFLAGS  ?=

BIN      := gateway
SRC      := gateway.c allowlist.c
OBJ      := $(SRC:.c=.o)

.PHONY: all clean format perf-check

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

%.o: %.c allowlist.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(BIN) $(OBJ)

clean-logs:
	sudo rm -rf results/

format:
	clang-format -i *.c *.h
