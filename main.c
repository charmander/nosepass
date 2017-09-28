#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "bcrypt/bcrypt_pbkdf.h"
#include "bcrypt/explicit_bzero.h"
#include "chacha/ecrypt-sync.h"

#define S_(x) #x
#define S(x) S_(x)

#define CONFIG_NAME "/.nosepass"

#define DEFAULT_SET "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
#define DEFAULT_COUNT 20
#define DEFAULT_ROUNDS 200

#define MAX_COUNT_GENERATED 1024

#define PREFIX_COUNT "count="
#define PREFIX_SET "set="
#define PREFIX_ROUNDS "rounds="
#define PREFIX_INCREMENT "increment="

_Static_assert(' ' == 32 && '~' == 126, "character set is normal");
_Static_assert(DEFAULT_COUNT > 0 && DEFAULT_COUNT <= MAX_COUNT_GENERATED, "default count is within bounds");
_Static_assert(MAX_COUNT_GENERATED <= UINT_MAX, "maximum count is within bounds");

struct schema {
	uint64_t increment;
	unsigned int count;
	unsigned int rounds;
	uint8_t set_size;
	char set[95];
};

/*
 * Gets the next highest power of two, minus one.
 */
__attribute__ ((const, warn_unused_result))
static uint8_t get_mask(uint8_t n) {
	n |= n >> 1;
	n |= n >> 2;
	n |= n >> 4;
	return n;
}

__attribute__ ((warn_unused_result))
static char const* parse_count(char const* const line, size_t* const out) {
	char const* p = line;
	size_t n = 0;

	for (;; p++) {
		char const c = *p;

		if (c == ' ' || c == '\0') {
			if (p == line) {
				return NULL;
			}

			*out = n;
			return p;
		}

		if (c < '0' || c > '9') {
			return NULL;
		}

		size_t const digit_value = (size_t)(c - '0');

		if (n > SIZE_MAX / 10 || 10 * n > SIZE_MAX - digit_value) {
			return NULL;
		}

		n = 10 * n + digit_value;
	}
}

__attribute__ ((warn_unused_result))
static char const* parse_set(char const* line, struct schema* const result) {
	unsigned char in_set[95];
	memset(in_set, 0, sizeof in_set);
	char last = '\0';

	for (;; line++) {
		char const c = *line;

		if (c == ' ' || c == '\0') {
			break;
		}

		if (c == '\\') {
			last = *++line;

			if (last == '\0') {
				fputs("expected escaped character, but found end of line\n", stderr);
				return NULL;
			}

			in_set[last - ' '] = 1;
			continue;
		}

		if (c < ' ' || c & 0x80) {
			fprintf(stderr, "expected printable ASCII but found '\\x%02x' instead\n", (unsigned int)(unsigned char)c);
			return NULL;
		}

		if (c == '-') {
			if (last == '\0') {
				fputs("found hyphen range with no starting character\n", stderr);
				return NULL;
			}

			char end = *++line;

			if (end == '\\') {
				end = *++line;
			} else if (end == ' ') {
				end = '\0';
			}

			if (end == '\0') {
				fputs("found hyphen range with no ending character\n", stderr);
				return NULL;
			}

			if (end & 0x80) {
				fprintf(stderr, "expected printable ASCII but found '\\x%02x' instead\n", (unsigned int)(unsigned char)end);
				return NULL;
			}

			if (end < last) {
				fprintf(stderr, "empty range %c-%c\n", last, end);
				return NULL;
			}

			for (char add = last; add <= end; add++) {
				in_set[add - ' '] = 1;
			}

			last = '\0';
		} else {
			in_set[c - ' '] = 1;
			last = c;
		}
	}

	result->set_size = 0;

	for (char i = 0; (unsigned char)i < sizeof in_set; i++) {
		if (in_set[(unsigned char)i]) {
			result->set[result->set_size++] = i + ' ';
		}
	}

	if (result->set_size < 2) {
		fputs("character set must contain at least two characters\n", stderr);
		return NULL;
	}

	return line;
}

__attribute__ ((warn_unused_result))
static int parse_schema_line(char const* line, struct schema* const restrict result) {
	int has_count = 0;
	int has_set = 0;
	int has_rounds = 0;
	int has_increment = 0;

	while (*line != '\0') {
		if (*line != ' ') {
			fprintf(stderr, "expected space, but found '%s' instead\n", line);
			return 0;
		}

		line++;

		if (strncmp(line, PREFIX_COUNT, sizeof PREFIX_COUNT - 1) == 0) {
			if (has_count) {
				fputs("multiple settings for character count\n", stderr);
				return 0;
			}

			has_count = 1;

			size_t count;
			char const* const parse_end = parse_count(line + (sizeof PREFIX_COUNT - 1), &count);

			if (parse_end == NULL) {
				fprintf(stderr, "expected count, but found '%s' instead\n", line);
				return 0;
			}

			if (count == 0) {
				fputs("character count must be greater than 0\n", stderr);
				return 0;
			}

			if (count > MAX_COUNT_GENERATED) {
				fputs("character count must be at most " S(MAX_COUNT_GENERATED) "\n", stderr);
				return 0;
			}

			result->count = (unsigned int)count;
			line = parse_end;
		} else if (strncmp(line, PREFIX_SET, sizeof PREFIX_SET - 1) == 0) {
			if (has_set) {
				fputs("multiple settings for character set\n", stderr);
				return 0;
			}

			has_set = 1;

			if ((line = parse_set(line + (sizeof PREFIX_SET - 1), result)) == NULL) {
				return 0;
			}
		} else if (strncmp(line, PREFIX_ROUNDS, sizeof PREFIX_ROUNDS - 1) == 0) {
			if (has_rounds) {
				fputs("multiple settings for rounds\n", stderr);
				return 0;
			}

			has_rounds = 1;

			size_t rounds;
			char const* const parse_end = parse_count(line + (sizeof PREFIX_ROUNDS - 1), &rounds);

			if (parse_end == NULL) {
				fprintf(stderr, "expected number of rounds, but found '%s' instead\n", line);
				return 0;
			}

			if (rounds < 1) {
				fputs("number of rounds must be at least 1\n", stderr);
				return 0;
			}

			if (rounds > UINT_MAX) {
				fprintf(stderr, "number of rounds must be at most %u\n", UINT_MAX);
				return 0;
			}

			result->rounds = (unsigned int)rounds;
			line = parse_end;
		} else if (strncmp(line, PREFIX_INCREMENT, sizeof PREFIX_INCREMENT - 1) == 0) {
			if (has_increment) {
				fputs("multiple settings for increment\n", stderr);
				return 0;
			}

			has_increment = 1;

			size_t increment;
			char const* const parse_end = parse_count(line + (sizeof PREFIX_INCREMENT - 1), &increment);

			if (parse_end == NULL) {
				fprintf(stderr, "expected increment, but found '%s' instead\n", line);
				return 0;
			}

			if (increment > UINT64_MAX) {
				fprintf(stderr, "increment must be at most %" PRIu64 "\n", UINT64_MAX);
				return 0;
			}

			result->increment = (uint64_t)increment;
			line = parse_end;
		} else {
			fprintf(stderr, "expected one of " PREFIX_COUNT ", " PREFIX_SET ", " PREFIX_ROUNDS ", or " PREFIX_INCREMENT ", but found '%s' instead\n", line);
			return 0;
		}
	}

	return 1;
}

__attribute__ ((warn_unused_result))
static int parse_schema(char const* const name, FILE* const input, struct schema* restrict result) {
	size_t const name_length = strlen(name);

	char line[1024];
	line[1023] = '\0';

	for (;;) {
		if (fgets(line, sizeof line, input) == NULL) {
			if (!feof(input)) {
				fputs("failed to read configuration file\n", stderr);
				return 0;
			}

			return 1;
		}

		if (line[1023] != '\0') {
			fputs("configuration line too long; limit is 1022 characters.\n", stderr);
			return 0;
		}

		if (line[0] == '#' || line[0] == '\0') {
			continue;
		}

		size_t const line_length = strlen(line);

		if (line[line_length - 1] == '\n') {
			line[line_length - 1] = '\0';
		}

		if (strncmp(line, name, name_length) == 0) {
			char const c = line[name_length];

			if (c == ' ') {
				return parse_schema_line(line + name_length, result);
			} else if (c == '\0') {
				return 1;
			}
		}
	}
}

__attribute__ ((warn_unused_result))
static FILE* open_config_file(void) {
	char const* const home_path = getenv("HOME");

	if (home_path == NULL) {
		fputs("HOME environment variable must be set\n", stderr);
		return NULL;
	}

	size_t const home_path_length = strlen(home_path);

	char* const config_path = malloc(home_path_length + sizeof CONFIG_NAME);

	if (config_path == NULL) {
		fputs("failed to allocate memory\n", stderr);
		return NULL;
	}

	memcpy(config_path, home_path, home_path_length);
	memcpy(config_path + home_path_length, CONFIG_NAME, sizeof CONFIG_NAME);

	FILE* const config = fopen(config_path, "r");

	free(config_path);

	if (config == NULL) {
		perror("failed to open configuration file");
	}

	return config;
}

__attribute__ ((warn_unused_result))
static char* password_read(char* const s, size_t const size) {
	struct termios original_termios;
	int termattr_result = tcgetattr(STDIN_FILENO, &original_termios);

	if (termattr_result == 0) {
		struct termios modified_termios = original_termios;
		modified_termios.c_lflag &= ~(unsigned int)ECHO;
		termattr_result = tcsetattr(STDIN_FILENO, TCSAFLUSH, &modified_termios);
	}

	fputs("Password: ", stderr);

	char* const result = fgets(s, (int)size, stdin);

	if (termattr_result == 0) {
		putc('\n', stderr);
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &original_termios);
	}

	return result;
}

static void show_usage(void) {
	fputs("Usage: nosepass <site-name>\n", stderr);
}

int main(int const argc, char const* const argv[]) {
	if (argc != 2) {
		show_usage();
		return EXIT_FAILURE;
	}

	char const* const site_name = argv[1];

	struct schema schema;
	schema.count = DEFAULT_COUNT;
	schema.rounds = DEFAULT_ROUNDS;
	schema.increment = 0;
	schema.set_size = sizeof DEFAULT_SET - 1;
	_Static_assert(sizeof DEFAULT_SET - 1 > 0 && sizeof DEFAULT_SET - 1 <= sizeof schema.set, "default character set fits in schema");
	memcpy(schema.set, DEFAULT_SET, sizeof DEFAULT_SET - 1);

	{
		FILE* const config = open_config_file();

		if (config == NULL) {
			return EXIT_FAILURE;
		}

		if (!parse_schema("default", config, &schema)) {
			fclose(config);
			return EXIT_FAILURE;
		}

		if (fseek(config, 0L, SEEK_SET) != 0) {
			perror("failed to seek configuration file");
			fclose(config);
			return EXIT_FAILURE;
		}

		if (!parse_schema(site_name, config, &schema)) {
			fclose(config);
			return EXIT_FAILURE;
		}

		fclose(config);
	}

	{
		double const bits = schema.count * log2(schema.set_size);
		char const* const color =
			bits >= 128.0 ? "\x1b[32m" :
			bits >= 92.0 ? "\x1b[33m" :
			"\x1b[31m";

		fprintf(stderr, "%s●\x1b[0m generating password equivalent to %.0f bits\n", color, bits);
	}

	uint8_t key[32];

	{
		char password[1024];

		if (password_read(password, sizeof password) == NULL) {
			fputs("failed to read password\n", stderr);
			return EXIT_FAILURE;
		}

		size_t password_length = strlen(password);

		if (password[password_length - 1] == '\n') {
			password_length--;
		} else if (password_length > 1022) {
			/* avoid silent truncation at 1023 characters */
			fputs("the maximum password length is 1022 characters\n", stderr);
			return EXIT_FAILURE;
		}

		if (password_length == 0) {
			fputs("a password is required\n", stderr);
			return EXIT_FAILURE;
		}

		if (bcrypt_pbkdf(password, password_length, (unsigned char const*)site_name, strlen(site_name), key, sizeof key, schema.rounds) != 0) {
			fputs("bcrypt_pbkdf failed\n", stderr);
			return EXIT_FAILURE;
		}

		explicit_bzero(password, sizeof password);
	}

	uint8_t const nonce[8] = {
		(uint8_t)schema.increment,
		(uint8_t)(schema.increment >> 8),
		(uint8_t)(schema.increment >> 16),
		(uint8_t)(schema.increment >> 24),
		(uint8_t)(schema.increment >> 32),
		(uint8_t)(schema.increment >> 40),
		(uint8_t)(schema.increment >> 48),
		(uint8_t)(schema.increment >> 56),
	};

	ECRYPT_ctx ctx;

	ECRYPT_init();
	ECRYPT_keysetup(&ctx, key, 8 * sizeof key, 8 * sizeof nonce);
	ECRYPT_ivsetup(&ctx, nonce);

	size_t i = 0;
	uint8_t mask = get_mask(schema.set_size);

	char generated_password[MAX_COUNT_GENERATED];

	{
		uint8_t generated_bytes[ECRYPT_BLOCKLENGTH];

		while (i < schema.count) {
			ECRYPT_keystream_blocks(&ctx, generated_bytes, 1);

			for (size_t j = 0; j < ECRYPT_BLOCKLENGTH; j++) {
				uint8_t const character_index = mask & generated_bytes[j];

				if (character_index < schema.set_size) {
					generated_password[i] = schema.set[character_index];
					i++;

					if (i == schema.count) {
						break;
					}
				}
			}
		}

		explicit_bzero(generated_bytes, ECRYPT_BLOCKLENGTH);
	}

	size_t const written = fwrite(generated_password, sizeof(char), schema.count, stdout);

	explicit_bzero(generated_password, MAX_COUNT_GENERATED);

	if (written != schema.count) {
		fputs("failed to write output\n", stderr);
		return EXIT_FAILURE;
	}

	fflush(stdout);
	fputc('\n', stderr);
	return EXIT_SUCCESS;
}
