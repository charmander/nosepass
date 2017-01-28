CC := clang
WARNINGS := -Wall -Wextra -Weverything -Werror -pedantic -Wno-disabled-macro-expansion -Wno-error=padded
CFLAGS := -std=c11 -O2 -march=native $(WARNINGS)
LDFLAGS := -lm

nosepass: main.c
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

clean:
	rm -f nosepass

.PHONY: clean
