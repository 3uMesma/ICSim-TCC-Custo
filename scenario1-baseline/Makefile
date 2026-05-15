include ../make.inc

BIN := passthrough
SRC := passthrough.c
OBJ := passthrough.o

.PHONY: all clean clean-logs format

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

passthrough.o: passthrough.c
	$(CC) $(CFLAGS) -c passthrough.c -o passthrough.o

clean:
	rm -f $(BIN) $(OBJ)

clean-logs:
	sudo rm -rf results/ results-sw/

format:
	clang-format -i *.c
