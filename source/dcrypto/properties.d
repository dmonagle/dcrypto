module dcrypto.properties;

import dcrypto.evp;
import std.string;
import std.typecons;
import std.base64;

version (Have_vibe_d) {
	import vibe.data.json;
}

string encryptProperty(const string value, const string secret) {
	auto key = keyFromSecret(secret);
	auto encrypter = new EVPEncryptor(key);
	
	auto joined = key.salt ~ representation(encrypter.encrypt(value));
	
	return Base64.encode(joined);
}

string decryptProperty(const string value, const string secret) {
	auto data = cast(string)Base64.decode(value);
	assert(data.length > 8, "The value for the encrypted property is not long enough");
	auto key = keyFromSecret(secret, data[0..8]);
	auto decrypter = new EVPDecryptor(key);
	
	return decrypter.decrypt(data[8..$]);
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
	
	auto output = Base64.encode(representation(user.password_encrypted_));

	assert(user.password_encrypted_ != "SuperSecretPassword");
	assert(user.password == "SuperSecretPassword");
	assert(user.creditCard == "1234 5258 4566 9789");
}
