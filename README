= dcrypto

== Summary

Wraps the openssl library to enable easy two way encryption. 

== Example

	import dcrypto.evp;

	// Create an AES key
	auto key = keyFromSecret("ZYXWVUTSRQPONMLKJIHGFEDCBA", "SALT");

	// Create an encryptor class based on the key.
	auto encryptor = new EVPEncryptor(key);

	// An encryptor class can be used to encrypt more than one string.
	auto encrypted = encryptor.encrypt("This is a decrypted string");
	auto encrypted2 = encryptor.encrypt("This is a second decrypted string");

	// Create a decryption class based on the key.
	auto decryptor = new EVPDecryptor(key);

	assert(decryptor.decrypt(encrypted2) == "This is a second decrypted string");
	assert(decryptor.decrypt(encrypted) == "This is a decrypted string");
	assert(decryptor.decrypt(encrypted2) == "This is a second decrypted string");
