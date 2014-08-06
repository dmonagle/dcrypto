# dcrypto

## Summary

Wraps the openssl library to enable easy two way encryption. 

## Example

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

## Encrypted Properties

There is a mixin which allows an encrypted string to be added to a structure or class with a properties for
automatic encryption and decryption.

If vibe.d is included, the accessor property is automatically ignored when serialized.

	struct User {
		string username;
		mixin (encryptedProperty("password", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
		mixin (encryptedProperty("creditCard", "ZYXWVUTSRXPONMLKJIHGFEDCBA"));
	}
	
	User user;
	user.username = "David";
	user.password = "SuperSecretPassword";
	user.creditCard = "1234 5258 4566 9789";
	
	assert(user.password_encrypted_ != "SuperSecretPassword");
	assert(user.password == "SuperSecretPassword");
	assert(user.creditCard == "1234 5258 4566 9789");
