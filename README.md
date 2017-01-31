# nosepass

A small deterministic password generator! Produces unique passwords based on a master password and site name.

## Installation

```shellsession
$ make
$ sudo cp -i nosepass /usr/local/bin/
```

## Configuration

Copy the included `.nosepass` to your home directory. Its defaults are reasonable, and instructions are included.

## Use

```shellsession
$ nosepass test
● generating password equivalent to 131 bits
Password: ****
.,reHgb9^$Z|6.7)nNU>
```

A function like this might add convenience:

```zsh
np() {
	local p=$(nosepass "$@") || return 1
	echo 'Password copied!'
	printf '%s' "$p" | xsel -nbi || return 1
}
```

## Method

`bcrypt_pbkdf` is used to derive a 256-bit key from the master password with the site name as salt. The derived key is used with the increment as a nonce to generate a random stream with ChaCha20. The stream is filtered to bytes that fit in the provided character set and truncated to the requested password length.

A more specific [Python reference implementation][1] is included; install `bcrypt~=3.1.2`, `cffi~=1.9.1`, and libsodium to use it.


  [1]: reference.py
