include ../make.inc

CFLAGS   += -I../lib

BIN      := gateway
SRC      := gateway.c allowlist.c ../lib/can_io.c
OBJ      := gateway.o allowlist.o can_io.o

.PHONY: all clean clean-logs format perf-check

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

gateway.o: gateway.c allowlist.h ../lib/can_io.h
	$(CC) $(CFLAGS) -c gateway.c -o gateway.o

allowlist.o: allowlist.c allowlist.h
	$(CC) $(CFLAGS) -c allowlist.c -o allowlist.o

can_io.o: ../lib/can_io.c ../lib/can_io.h
	$(CC) $(CFLAGS) -c ../lib/can_io.c -o can_io.o

clean:
	rm -f $(BIN) $(OBJ)

clean-logs:
	sudo rm -rf results/

format:
	clang-format -i *.c *.h
