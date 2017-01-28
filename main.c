#include <inttypes.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define S_(x) #x
#define S(x) S_(x)

#define CONFIG_NAME "/.nosepass"

#define DEFAULT_SET "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
#define DEFAULT_COUNT 20
#define DEFAULT_WORK 13

#define MAX_COUNT_GENERATED 1024

#define PREFIX_COUNT "count="
#define PREFIX_SET "set="
#define PREFIX_WORK "work="
#define PREFIX_INCREMENT "increment="

_Static_assert(' ' == 32 && '~' == 126, "character set is normal");

struct schema {
	size_t count;
	size_t work;
	size_t increment;
	size_t set_size;
	char set[96];
};

__attribute__((warn_unused_result))
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

		if (n > SIZE_MAX / 10) {
			return NULL;
		}

		n = 10 * n + (size_t)(c - '0');
	}
}

__attribute__((warn_unused_result))
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

		if (c & 0x80) {
			fprintf(stderr, "expected printable ASCII but found '\\x%2x' instead\n", (unsigned int)(unsigned char)c);
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
				fprintf(stderr, "expected printable ASCII but found '\\x%2x' instead\n", (unsigned int)(unsigned char)end);
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

	result->set[result->set_size] = '\0';

	if (result->set_size < 2) {
		fputs("character set must contain at least two characters\n", stderr);
		return NULL;
	}

	return line;
}

__attribute__((warn_unused_result))
static int parse_schema_line(char const* line, struct schema* const result) {
	int has_count = 0;
	int has_set = 0;
	int has_work = 0;
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

			char const* const parse_end = parse_count(line + (sizeof PREFIX_COUNT - 1), &result->count);

			if (parse_end == NULL) {
				fprintf(stderr, "expected count, but found '%s' instead\n", line);
				return 0;
			}

			if (result->count == 0) {
				fputs("character count must be greater than 0\n", stderr);
				return 0;
			}

			if (result->count > MAX_COUNT_GENERATED) {
				fputs("character count must be at most " S(MAX_COUNT_GENERATED) "\n", stderr);
				return 0;
			}

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
		} else if (strncmp(line, PREFIX_WORK, sizeof PREFIX_WORK - 1) == 0) {
			if (has_work) {
				fputs("multiple settings for work factor\n", stderr);
				return 0;
			}

			has_work = 1;

			char const* const parse_end = parse_count(line + (sizeof PREFIX_WORK - 1), &result->work);

			if (parse_end == NULL) {
				fprintf(stderr, "expected work factor, but found '%s' instead\n", line);
				return 0;
			}

			if (result->work < 4) {
				fputs("work factor must be at least 4\n", stderr);
				return 0;
			}

			if (result->work > 31) {
				fputs("work factor must be at most 31\n", stderr);
				return 0;
			}

			line = parse_end;
		} else if (strncmp(line, PREFIX_INCREMENT, sizeof PREFIX_INCREMENT - 1) == 0) {
			if (has_increment) {
				fputs("multiple settings for increment\n", stderr);
				return 0;
			}

			has_increment = 1;

			char const* const parse_end = parse_count(line + (sizeof PREFIX_INCREMENT - 1), &result->increment);

			if (parse_end == NULL) {
				fprintf(stderr, "expected increment, but found '%s' instead\n", line);
				return 0;
			}

			if (result->increment > UINT64_MAX) {
				fprintf(stderr, "increment must be at most " PRIu64 "\n", UINT64_MAX);
				return 0;
			}

			line = parse_end;
		} else {
			fprintf(stderr, "expected one of " PREFIX_COUNT ", " PREFIX_SET ", " PREFIX_WORK ", or " PREFIX_INCREMENT ", but found '%s' instead\n", line);
			return 0;
		}
	}

	return 1;
}

__attribute__((warn_unused_result))
static int parse_schema(char const* const name, FILE* const input, struct schema* result) {
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

static void log_schema(struct schema const* const schema) {
	fprintf(
		stderr,
		"schema with count=%zd, work=%zd, increment=%zd, set_size=%zd, set=%s\n",
		schema->count, schema->work, schema->increment, schema->set_size, schema->set
	);
}

static void show_usage() {
	fputs("Usage: nosepass <site-name>\n", stderr);
}

__attribute__((warn_unused_result))
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

int main(int const argc, char const* const argv[]) {
	if (argc != 2) {
		show_usage();
		return EXIT_FAILURE;
	}

	struct schema schema;
	schema.count = DEFAULT_COUNT;
	schema.work = DEFAULT_WORK;
	schema.increment = 0;
	schema.set_size = sizeof DEFAULT_SET - 1;
	_Static_assert(sizeof DEFAULT_SET - 1 > 0 && sizeof DEFAULT_SET - 1 <= sizeof schema.set, "default character set fits in schema");
	memcpy(schema.set, DEFAULT_SET, sizeof DEFAULT_SET - 1);

	FILE* const config = open_config_file();

	if (config == NULL) {
		return EXIT_FAILURE;
	}

	if (!parse_schema("default", config, &schema)) {
		fclose(config);
		return EXIT_FAILURE;
	}

	if (!parse_schema(argv[1], config, &schema)) {
		fclose(config);
		return EXIT_FAILURE;
	}

	double const bits = schema.count * log2(schema.set_size);
	char const* const color =
		bits >= 128.0 ? "\x1b[32m" :
		bits >= 92.0 ? "\x1b[33m" :
		"\x1b[31m";

	fprintf(stderr, "%s●\x1b[0m generating password with maximum of %.2f bits\n", color, bits);

	fclose(config);

	log_schema(&schema);
	return EXIT_SUCCESS;
}
