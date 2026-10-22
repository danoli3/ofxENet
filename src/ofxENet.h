#pragma once

// ofxENet: reliable UDP networking for openFrameworks, on ENet
// (https://github.com/zpl-c/enet, the maintained single-header fork, IPv4 and IPv6).
//
// ofxENet::Peer has the same API as ofxRakNet::Peer: start a server or a
// client, send messages, and get connection / message events from update(),
// on the main thread. Optional AES-256-GCM encryption with setPassphrase().

#include "ofEvents.h"
#include "ofFileUtils.h"
#include "ofJson.h"
#include "ofxENetCrypto.h"

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

struct _ENetHost;
struct _ENetPeer;

namespace ofxENet {

/// A connected system: a random 64-bit id each peer picks when it starts and
/// announces in the handshake, so it's the same on both ends of a connection.
using PeerId = uint64_t;

/// How a message is delivered.
enum class Reliability {
	Unreliable,          ///< may be lost, duplicated or out of order (ENet unsequenced)
	UnreliableSequenced, ///< may be lost; older ones are dropped (ENet unreliable)
	Reliable,            ///< arrives (in order on its channel: ENet reliable is ordered)
	ReliableOrdered,     ///< arrives, in the order sent (default; chat, state)
	ReliableSequenced,   ///< same as ReliableOrdered in ENet
};

/// Kept for ofxRakNet compatibility: ENet has no send priorities, so it's ignored.
enum class Priority { Immediate, High, Medium, Low };

struct ConnectionEvent {
	PeerId peer = 0;
	std::string address; ///< "ip|port"
};

struct DisconnectionEvent {
	enum class Reason {
		Disconnected,        ///< the other side closed the connection
		Lost,                ///< timed out
		ConnectFailed,       ///< connect() got no answer
		ServerFull,
		InvalidPassword,
		Banned,              ///< (not used by ENet; kept for ofxRakNet compatibility)
		IncompatibleProtocol,
		AlreadyConnected,    ///< (not used by ENet)
	};
	PeerId peer = 0;
	std::string address;
	Reason reason = Reason::Disconnected;
};

struct MessageEvent {
	PeerId peer = 0;
	std::string address;
	/// The type given to send() (0 .. 255).
	uint8_t type = 0;
	/// The channel it was sent on.
	uint8_t channel = 0;
	/// The payload, without the type byte (decrypted if it was encrypted).
	ofBuffer data;
	/// The message was encrypted (see Peer::setPassphrase).
	bool encrypted = false;
	/// Encrypted, and decrypted and verified with our passphrase. False for
	/// plain messages, and for encrypted ones that failed (data is then empty).
	bool authentic = false;

	std::string getText() const { return data.getText(); }
	/// The payload parsed as JSON (null if it isn't).
	ofJson getJson() const;
};

std::string toString(DisconnectionEvent::Reason reason);

class Peer {
public:
	/// Largest message type. Unlike ofxRakNet, ENet reserves none (the handshake
	/// uses its own channel), so all 256 values are yours.
	static const uint8_t MAX_MESSAGE_TYPE;
	/// Channels 0 .. CHANNELS-1 are for messages (each one is ordered on its own).
	static const uint8_t CHANNELS;

	Peer();
	~Peer();
	Peer(const Peer &) = delete;
	Peer & operator=(const Peer &) = delete;

	/// Listens on port (0: any free port) for up to maxConnections peers (and can also connect out).
	bool startServer(uint16_t port, unsigned int maxConnections = 32, const std::string & password = "");
	/// Starts without accepting connections; then connect().
	bool startClient();
	/// Connects to a server; onConnect or onDisconnect (ConnectFailed, ...) follows.
	bool connect(const std::string & host, uint16_t port, const std::string & password = "");
	/// Closes one connection (the other side gets Disconnected).
	void disconnect(PeerId peer);
	/// Closes every connection and stops (also done by the destructor).
	void stop();

	bool isRunning() const { return host != nullptr; }
	bool isServer() const { return server; }
	/// The port this peer is bound to (0 when not running).
	uint16_t getPort() const;

	/// Sends to one peer. type: 0 .. 255, given back in MessageEvent::type.
	bool send(PeerId peer, uint8_t type, const void * data, size_t size,
		Reliability reliability = Reliability::ReliableOrdered, Priority priority = Priority::High, uint8_t channel = 0);
	bool send(PeerId peer, uint8_t type, const std::string & text,
		Reliability reliability = Reliability::ReliableOrdered, Priority priority = Priority::High, uint8_t channel = 0);
	bool send(PeerId peer, uint8_t type, const ofBuffer & buffer,
		Reliability reliability = Reliability::ReliableOrdered, Priority priority = Priority::High, uint8_t channel = 0);
	bool send(PeerId peer, uint8_t type, const ofJson & json,
		Reliability reliability = Reliability::ReliableOrdered, Priority priority = Priority::High, uint8_t channel = 0);

	/// Sends to every connected peer, except `except` (0: none).
	bool broadcast(uint8_t type, const void * data, size_t size, PeerId except = 0,
		Reliability reliability = Reliability::ReliableOrdered, Priority priority = Priority::High, uint8_t channel = 0);
	bool broadcast(uint8_t type, const std::string & text, PeerId except = 0,
		Reliability reliability = Reliability::ReliableOrdered, Priority priority = Priority::High, uint8_t channel = 0);
	bool broadcast(uint8_t type, const ofJson & json, PeerId except = 0,
		Reliability reliability = Reliability::ReliableOrdered, Priority priority = Priority::High, uint8_t channel = 0);

	/// Sends and receives (ENet does its networking here, not on a thread):
	/// call every frame, or setAutoUpdate(true). Notifies the events.
	void update();
	/// Calls update() from ofEvents().update, before ofApp::update.
	void setAutoUpdate(bool autoUpdate);

	/// Encrypts every message sent with AES-256-GCM, under a key derived from
	/// the passphrase (PBKDF2-HMAC-SHA256, random salt), and decrypts what
	/// arrives (see ofxENetCrypto.h). Every peer needs the same passphrase.
	/// Empty turns it off.
	void setPassphrase(const std::string & passphrase);
	bool isEncrypting() const { return cipher.isEnabled(); }
	std::string getFingerprint() const { return cipher.getFingerprint(); }
	/// With a passphrase set: drop messages that aren't encrypted with it.
	bool requireEncryption = false;

	std::vector<PeerId> getConnections() const;
	size_t getNumConnections() const;
	std::string getAddress(PeerId peer) const;
	/// Mean round trip in milliseconds, or -1.
	int getPing(PeerId peer) const;
	PeerId getMyId() const { return myId; }

	ofEvent<ConnectionEvent> onConnect;
	ofEvent<DisconnectionEvent> onDisconnect;
	ofEvent<MessageEvent> onMessage;

	/// The ENet host, for the rest of the ENet API (bandwidth limits, compression, ...).
	_ENetHost * getHost() const { return host; }

private:
	struct Remote {
		PeerId id = 0;
		std::string address;
		bool ready = false;     // handshake done
		bool initiated = false; // we called connect()
		uint64_t since = 0;     // ms, for the handshake timeout
	};

	_ENetHost * host = nullptr;
	bool server = false;
	unsigned int maxConnections = 0;
	std::string passwordDigest;
	std::string outgoingPasswordDigest;
	PeerId myId = 0;
	std::map<_ENetPeer *, Remote> remotes;
	ofEventListener updateListener;
	crypto::Cipher cipher;

	bool start(uint16_t port, size_t peerSlots);
	_ENetPeer * find(PeerId id) const;
	void sendHello(_ENetPeer * peer, const std::string & digest);
	void handleControl(_ENetPeer * peer, const unsigned char * data, size_t size);
	void handleDisconnect(_ENetPeer * peer, uint32_t code, bool timeout);
	bool sendPacket(_ENetPeer * only, PeerId except, uint8_t type, const void * data, size_t size,
		Reliability reliability, uint8_t channel);
};

} // namespace ofxENet
