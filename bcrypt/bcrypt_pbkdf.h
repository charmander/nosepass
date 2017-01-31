#include <stdint.h>
#include <stdlib.h>

__attribute__ ((warn_unused_result))
int bcrypt_pbkdf(
	char const* password,
	size_t password_length,
	uint8_t const* salt,
	size_t salt_length,
	uint8_t* key,
	size_t key_length,
	unsigned int rounds
);
