AS := as
CC := clang
WARNINGS := -Wall -Wextra -Weverything -Werror -pedantic -Wno-disabled-macro-expansion -Wno-error=padded
CFLAGS := -std=c11 -O2 -march=native -D_DEFAULT_SOURCE -flto
CFLAGS_nosepass := $(WARNINGS)
LDFLAGS := -lm

nosepass: main.c bcrypt/bcrypt_pbkdf.c bcrypt/blf.o bcrypt/explicit_bzero.o bcrypt/sha2.o chacha/chacha20.o
	$(CC) $(CFLAGS) $(CFLAGS_nosepass) $^ $(LDFLAGS) -o $@

bcrypt/blf.o: bcrypt/blf.c bcrypt/blf.h
	$(CC) $(CFLAGS) -c $< -o $@

bcrypt/explicit_bzero.o: bcrypt/explicit_bzero.c bcrypt/explicit_bzero.h
	$(CC) $(CFLAGS) -c $< -o $@

bcrypt/sha2.o: bcrypt/sha2.c bcrypt/sha2.h
	$(CC) $(CFLAGS) -c $< -o $@

chacha/chacha20.o: chacha/chacha20.s
	$(AS) -c $< -o $@

clean:
	rm -f nosepass bcrypt/blf.o bcrypt/explicit_bzero.o bcrypt/sha2.o chacha/chacha20.o

.PHONY: clean
