void explicit_bzero(void*, size_t)
	__attribute__ ((__bounded__(__buffer__,1,2)));
