CC=gcc
CFLAGS=-O3
OBJ=disassemble-hexdump.o

all: disassemble-hexdump

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

disassemble-hexdump: disassemble-hexdump.o
	$(CC) $(OBJ) -o disassemble-hexdump -lopcodes

clean:
	rm disassemble-hexdump $(OBJ)
