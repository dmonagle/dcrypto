module dcrypto.properties;

import dcrypto.evp;
import std.string;
import std.typecons;

version (Have_vibe_d) {
	import vibe.data.json;
}

string encryptProperty(const string value, const string secret) {
	auto key = keyFromSecret(secret);
	auto encrypter = new EVPEncryptor(key);
	
	return cast(string)key.salt ~ encrypter.encrypt(value);
}

string decryptProperty(const string value, const string secret) {
	auto key = keyFromSecret(secret, value[0..8]);
	auto decrypter = new EVPDecryptor(key);
	
	return decrypter.decrypt(value[8..$]);
}

string encryptedProperty(string name, string secret) {
	string code;
	
	code ~= format("string %s_encrypted_;", name);
	
	version (Have_vibe_d) {
		auto ignore = "@ignore ";
	} else {
		auto ignore = "";
	}
	code ~= format("%s@property string %s() { ", ignore, name);
	code ~= format("return decryptProperty(%s_encrypted_, \"%s\");", name, secret);
	code ~= "}";
	
	code ~= format("@property void %s(string value) { ", name);
	code ~= format("%s_encrypted_ = encryptProperty(value, \"%s\");", name, secret);
	code ~= "}";
	
	return code;
}

unittest {
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
}
