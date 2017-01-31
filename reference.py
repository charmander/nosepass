import itertools
from typing import Sequence

import bcrypt
from cffi import FFI


ffi = FFI()

ffi.cdef(
	"""
	int crypto_stream_chacha20_xor_ic(unsigned char *c, const unsigned char *m,
	                                  unsigned long long mlen,
	                                  const unsigned char *n, uint64_t ic,
	                                  const unsigned char *k);
	"""
)

lib = ffi.dlopen('sodium')


_PRINTABLE = bytes(range(33, 127)).decode('ascii')
_EMPTY_BLOCK = b'\0' * 64


def get_mask(n: int) -> int:
	return (1 << n.bit_length()) - 1


def get_password(kdf_rounds: int, character_set: Sequence[str], length: int, increment: int, site_name: str, master_password: str) -> str:
	set_size = len(character_set)
	mask = get_mask(set_size)
	nonce = increment.to_bytes(8, 'little')

	key = bcrypt.kdf(master_password.encode('utf-8'), site_name.encode('utf-8'), 32, kdf_rounds)
	block = ffi.new('unsigned char[64]')

	result = []

	for i in itertools.count():
		lib.crypto_stream_chacha20_xor_ic(block, _EMPTY_BLOCK, len(block), nonce, i, key)

		for c in block:
			character_index = c & mask

			if character_index < set_size:
				result.append(character_set[character_index])

				if len(result) == length:
					return ''.join(result)


if __name__ == '__main__':
	print(get_password(kdf_rounds=200, character_set=_PRINTABLE, length=20, increment=0, site_name='test', master_password='test'))
