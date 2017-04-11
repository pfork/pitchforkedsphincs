CC=gcc
OBJS = crypto_stream_chacha20.o wots.o prg.o hash.o horst.o sign.o permute.o
CFLAGS=-I/usr/include/sodium/ -Wall -Wextra -pedantic -Wstrict-overflow -fno-strict-aliasing -Wshadow -fstack-protector
LDFLAGS=-lsodium

all: signer.elf verifier.elf

signer.elf: $(OBJS) signer.o
	$(CC) -o signer.elf $(OBJS) signer.o $(LDFLAGS)

verifier.elf: $(OBJS) verifier.o
	$(CC) -o verifier.elf $(OBJS) verifier.o $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	find . -name \*.o -type f -exec rm -f {} \;
	find . -name \*.d -type f -exec rm -f {} \;
	rm -f *.elf
	rm -f *.bin
