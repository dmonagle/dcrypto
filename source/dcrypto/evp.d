module dcrypto.evp;

import std.string;

import deimos.openssl.evp;

import dcrypto.key;

class EVPEncryptDecryptBase {
public
	this() {
		EVP_CIPHER_CTX_init(&_context);
	}
	
	this(const ref Key key) {
		this();
		init(key);
	}

protected:
	EVP_CIPHER_CTX _context;

	abstract void init(const ref Key key, const EVP_CIPHER *algorithm);
	public void init(const ref Key key) {
		init(key, EVP_aes_256_cbc());
	}
}

class EVPEncryptor : EVPEncryptDecryptBase {
	this() { super(); }
	this(const ref Key key) { super(key); }
	
	string encrypt(string input) {
		auto source = representation(input);
		auto buffer = new ubyte[](source.length + EVP_MAX_BLOCK_LENGTH);
		int length, lengthFinal;
		
		EVP_EncryptInit(&_context, null, null, null);
		EVP_EncryptUpdate(&_context, buffer.ptr, &length, source.ptr, cast(int)source.length);
		EVP_EncryptFinal_ex(&_context, buffer.ptr + length, &lengthFinal);
		
		return cast(string)buffer[0..length + lengthFinal];
	}

protected:
	override void init(const ref Key key, const EVP_CIPHER *algorithm) {
		EVP_EncryptInit(&_context, algorithm, key.key.ptr, key.iv.ptr);
	}
}

class EVPDecryptor : EVPEncryptDecryptBase {
	this() { super(); }
	this(const ref Key key) { super(key); }
	
	string decrypt(string input) {
		auto source = representation(input);
		auto buffer = new ubyte[](source.length + EVP_MAX_BLOCK_LENGTH);
		int length, lengthFinal;
		
		EVP_DecryptInit(&_context, null, null, null);
		EVP_DecryptUpdate(&_context, buffer.ptr, &length, source.ptr, cast(int)source.length);
		EVP_DecryptFinal_ex(&_context, buffer.ptr + length, &lengthFinal);
		
		return cast(string)buffer[0..length + lengthFinal];
	}
protected:
	override void init(const ref Key key, const EVP_CIPHER *algorithm) {
		EVP_DecryptInit(&_context, algorithm, key.key.ptr, key.iv.ptr);
	}
}

unittest {
	auto key = keyFromSecret("ZYXWVUTSRQPONMLKJIHGFEDCBA", "SALT");
	auto encryptor = new EVPEncryptor(key);
	auto decryptor = new EVPDecryptor(key);

	auto encrypted = encryptor.encrypt("This is a decrypted string");
	auto encrypted2 = encryptor.encrypt("This is a second decrypted string");

	assert(decryptor.decrypt(encrypted2) == "This is a second decrypted string");
	assert(decryptor.decrypt(encrypted) == "This is a decrypted string");
	assert(decryptor.decrypt(encrypted2) == "This is a second decrypted string");

	auto key2 = keyFromSecret("ZYXWVUTSRQPONMLKJIHGFEDCBA");
	auto decryptor2 = new EVPDecryptor(key2);
	assert(decryptor2.decrypt(encrypted2) != "This is a second decrypted string");
}