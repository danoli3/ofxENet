#pragma once

// Message encryption for ofxENet, on openFrameworks' OpenSSL.
//
// A shared passphrase becomes an AES-256 key with PBKDF2-HMAC-SHA256 and a
// random salt; every message is sealed with AES-256-GCM under a fresh random
// nonce. GCM authenticates the message: a wrong passphrase or any change on
// the way makes decrypt() fail instead of returning garbage.
//
// Envelope (bytes): 'O' 'R' version(1) | salt(16) | nonce(12) | ciphertext | tag(16)
//
// What it does and doesn't do:
// - hides the content and detects tampering, end to end between peers that
//   share the passphrase (a relaying server needs it too, to read and re-send)
// - doesn't hide the message type byte, the size, or who talks to whom
// - no forward secrecy: anyone who learns the passphrase can read recorded traffic
// - a weak passphrase can be guessed offline; PBKDF2 only slows that down

#include <cstdint>
#include <map>
#include <optional>
#include <string>

namespace ofxENet {
namespace crypto {

/// Cryptographically secure random bytes (OpenSSL RAND_bytes).
std::string randomBytes(size_t count);
/// SHA-256 digest (32 raw bytes).
std::string sha256(const std::string & data);
/// Lowercase hex of raw bytes.
std::string toHex(const std::string & bytes);
/// PBKDF2-HMAC-SHA256: a keyLength byte key from a passphrase and salt.
std::string deriveKey(const std::string & passphrase, const std::string & salt,
	int iterations = 200000, size_t keyLength = 32);

class Cipher {
public:
	static constexpr size_t SALT_SIZE = 16;
	static constexpr size_t NONCE_SIZE = 12;
	static constexpr size_t TAG_SIZE = 16;
	static constexpr size_t HEADER_SIZE = 3 + SALT_SIZE + NONCE_SIZE;
	static constexpr size_t OVERHEAD = HEADER_SIZE + TAG_SIZE;

	/// Sets the passphrase: picks a new random salt for what this side sends
	/// and derives its key. Empty turns encryption off.
	void setPassphrase(const std::string & passphrase, int iterations = 200000);
	bool isEnabled() const { return !passphrase.empty(); }

	/// AES-256-GCM sealed envelope (see above). Empty if not enabled.
	std::string encrypt(const std::string & plaintext);
	/// The plaintext, or nothing if the envelope is malformed, was made with
	/// another passphrase, or was changed. Keys for other senders' salts are
	/// derived once and cached.
	std::optional<std::string> decrypt(const std::string & envelope);
	/// True if data starts like an envelope (it may still fail to decrypt).
	static bool isEnvelope(const std::string & data);

	/// SHA-256 based fingerprint of the passphrase (12 hex chars), the same on
	/// every machine with the same passphrase: compare it to check you typed
	/// the same one, without revealing it.
	std::string getFingerprint() const { return fingerprint; }

private:
	std::string passphrase;
	int iterations = 200000;
	std::string salt;
	std::string key;
	std::string fingerprint;
	std::map<std::string, std::string> keysBySalt;
};

} // namespace crypto
} // namespace ofxENet
