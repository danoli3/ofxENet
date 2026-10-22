#include "ofxENetCrypto.h"

#include "ofLog.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <memory>
#include <stdexcept>

namespace ofxENet {
namespace crypto {

namespace {

const unsigned char MAGIC[2] = { 'O', 'R' };
const unsigned char VERSION = 1;

using CipherContext = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

const unsigned char * bytes(const std::string & s) {
	return reinterpret_cast<const unsigned char *>(s.data());
}

} // namespace

std::string randomBytes(size_t count) {
	std::string out(count, '\0');
	if (count > 0 && RAND_bytes(reinterpret_cast<unsigned char *>(out.data()), static_cast<int>(count)) != 1) {
		throw std::runtime_error("ofxENet: RAND_bytes failed");
	}
	return out;
}

std::string sha256(const std::string & data) {
	std::string out(32, '\0');
	unsigned int length = 0;
	EVP_Digest(data.data(), data.size(), reinterpret_cast<unsigned char *>(out.data()), &length, EVP_sha256(), nullptr);
	out.resize(length);
	return out;
}

std::string toHex(const std::string & raw) {
	static const char * digits = "0123456789abcdef";
	std::string out;
	out.reserve(raw.size() * 2);
	for (unsigned char c : raw) {
		out += digits[c >> 4];
		out += digits[c & 15];
	}
	return out;
}

std::string deriveKey(const std::string & passphrase, const std::string & salt, int iterations, size_t keyLength) {
	std::string key(keyLength, '\0');
	if (PKCS5_PBKDF2_HMAC(passphrase.data(), static_cast<int>(passphrase.size()), bytes(salt), static_cast<int>(salt.size()),
			iterations, EVP_sha256(), static_cast<int>(keyLength), reinterpret_cast<unsigned char *>(key.data())) != 1) {
		throw std::runtime_error("ofxENet: PBKDF2 failed");
	}
	return key;
}

void Cipher::setPassphrase(const std::string & newPassphrase, int newIterations) {
	passphrase = newPassphrase;
	iterations = newIterations;
	keysBySalt.clear();
	salt.clear();
	key.clear();
	fingerprint.clear();
	if (passphrase.empty()) {
		return;
	}
	salt = randomBytes(SALT_SIZE);
	key = deriveKey(passphrase, salt, iterations);
	keysBySalt[salt] = key;
	// a fixed, public salt: the same passphrase gives the same fingerprint everywhere
	fingerprint = toHex(sha256(deriveKey(passphrase, "ofxENet fingerprint", iterations))).substr(0, 12);
}

bool Cipher::isEnvelope(const std::string & data) {
	return data.size() >= OVERHEAD && static_cast<unsigned char>(data[0]) == MAGIC[0]
		&& static_cast<unsigned char>(data[1]) == MAGIC[1] && static_cast<unsigned char>(data[2]) == VERSION;
}

std::string Cipher::encrypt(const std::string & plaintext) {
	if (!isEnabled()) {
		return "";
	}
	const std::string nonce = randomBytes(NONCE_SIZE);
	std::string out;
	out.reserve(OVERHEAD + plaintext.size());
	out.append(reinterpret_cast<const char *>(MAGIC), 2);
	out += static_cast<char>(VERSION);
	out += salt;
	out += nonce;

	CipherContext ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
	std::string ciphertext(plaintext.size(), '\0');
	int length = 0;
	if (!ctx
		|| EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1
		|| EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, nullptr) != 1
		|| EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, bytes(key), bytes(nonce)) != 1
		// the header (magic, version, salt, nonce) is authenticated too
		|| EVP_EncryptUpdate(ctx.get(), nullptr, &length, bytes(out), static_cast<int>(out.size())) != 1
		|| (!plaintext.empty() && EVP_EncryptUpdate(ctx.get(), reinterpret_cast<unsigned char *>(ciphertext.data()), &length,
			bytes(plaintext), static_cast<int>(plaintext.size())) != 1)
		|| EVP_EncryptFinal_ex(ctx.get(), nullptr, &length) != 1) {
		ofLogError("ofxENet") << "encryption failed";
		return "";
	}
	std::string tag(TAG_SIZE, '\0');
	if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag.data()) != 1) {
		ofLogError("ofxENet") << "encryption failed (tag)";
		return "";
	}
	out += ciphertext;
	out += tag;
	return out;
}

std::optional<std::string> Cipher::decrypt(const std::string & envelope) {
	if (!isEnabled() || !isEnvelope(envelope)) {
		return std::nullopt;
	}
	const std::string header = envelope.substr(0, HEADER_SIZE);
	const std::string senderSalt = envelope.substr(3, SALT_SIZE);
	const std::string nonce = envelope.substr(3 + SALT_SIZE, NONCE_SIZE);
	const std::string ciphertext = envelope.substr(HEADER_SIZE, envelope.size() - OVERHEAD);
	std::string tag = envelope.substr(envelope.size() - TAG_SIZE);

	auto found = keysBySalt.find(senderSalt);
	if (found == keysBySalt.end()) {
		if (keysBySalt.size() > 256) keysBySalt.clear(); // bound the cache
		found = keysBySalt.emplace(senderSalt, deriveKey(passphrase, senderSalt, iterations)).first;
	}

	CipherContext ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
	std::string plaintext(ciphertext.size(), '\0');
	int length = 0;
	if (!ctx
		|| EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1
		|| EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, nullptr) != 1
		|| EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, bytes(found->second), bytes(nonce)) != 1
		|| EVP_DecryptUpdate(ctx.get(), nullptr, &length, bytes(header), static_cast<int>(header.size())) != 1
		|| (!ciphertext.empty() && EVP_DecryptUpdate(ctx.get(), reinterpret_cast<unsigned char *>(plaintext.data()), &length,
			bytes(ciphertext), static_cast<int>(ciphertext.size())) != 1)
		|| EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag.data()) != 1
		|| EVP_DecryptFinal_ex(ctx.get(), nullptr, &length) != 1) {
		return std::nullopt; // wrong passphrase, or changed on the way
	}
	return plaintext;
}

} // namespace crypto
} // namespace ofxENet
