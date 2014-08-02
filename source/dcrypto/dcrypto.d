module dcrypto.dcrypto;

import deimos.openssl.evp;

import std.random;

void fillRandom(T, D)(ref D dest) {
	foreach(ref token; dest) token = uniform!"[]"(T.min, T.max);
}

interface Encryptor {
	string encrypt(const string input);
}

interface Decryptor {
	string decrypt(const string input);
}

