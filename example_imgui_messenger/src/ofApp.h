#pragma once

#include "ofMain.h"
#include "ofxENet.h"
#include "ofxImGui.h"

// Sending and receiving with ofxENet, driven from Dear ImGui (needs ofxImGui,
// develop branch). Run two copies: the first starts a server on the port in
// bin/data/settings.json, the next ones connect to it (or use the Connection panel).
//
// - Connection: server / client, host, port, password, start / stop
// - Peers: everyone connected, with ping; pick who to send to; kick (server)
// - Compose: text or JSON, reliability, priority, channel; Send or Broadcast
// - Chat: the conversation, as name: text (names come from each peer's hello)
// - Log: everything sent and received, with filters
// - Encryption: a shared passphrase encrypts every message (AES-256-GCM, key from
//   PBKDF2-HMAC-SHA256 with a random salt); the log shows each message's SHA-256
// - Relay: a server can pass each client's messages on to the other clients.
//   Relayed messages carry the original sender's id in front of the payload.
class ofApp : public ofBaseApp {
public:
	void setup() override;
	void update() override;
	void draw() override;
	void exit() override;

	// message types (0 .. ofxENet::Peer::MAX_MESSAGE_TYPE)
	enum Type : uint8_t {
		TEXT = 0,       // UTF-8 text
		JSON = 1,       // JSON text
		RELAY_TEXT = 2, // 8 byte original sender id + TEXT payload (server -> clients)
		RELAY_JSON = 3, // 8 byte original sender id + JSON payload
	};

	struct LogEntry {
		float time;
		bool sent;
		ofxENet::PeerId peer;   // to / from (0: everyone)
		ofxENet::PeerId origin; // original sender of a relayed message (0: direct)
		uint8_t type;
		std::string reliability;
		size_t bytes;
		std::string text;
		bool encrypted;
		bool authentic;
		std::string hash; // SHA-256 of the plaintext, hex
	};

	// networking
	void startServer();
	void startClient();
	void stop();
	void send(bool toEveryone);
	void sendTo(ofxENet::PeerId peer, uint8_t type, const std::string & payload, bool toEveryone, ofxENet::PeerId except = 0);
	void onConnect(ofxENet::ConnectionEvent & e);
	void onDisconnect(ofxENet::DisconnectionEvent & e);
	void onMessage(ofxENet::MessageEvent & e);
	void log(bool sent, ofxENet::PeerId peer, uint8_t type, const std::string & payload, ofxENet::PeerId origin = 0,
		bool encrypted = false, bool authentic = false);
	void info(const std::string & line);
	std::string shortId(ofxENet::PeerId id) const;

	// chat
	struct ChatLine {
		float time;
		std::string name;
		std::string text;
		bool me;
		bool system; // joined / left / renamed
		bool encrypted;
		bool failed; // couldn't decrypt
	};
	void chatLine(const std::string & name, const std::string & text, bool me = false, bool system = false,
		bool encrypted = false, bool failed = false);
	void chatMessage(ofxENet::PeerId sender, uint8_t type, const std::string & payload, bool encrypted = false);
	std::string displayName(ofxENet::PeerId id) const;
	void defaultName();
	void sendName();

	// panels
	void drawConnection();
	void drawEncryption();
	void drawPeers();
	void drawCompose();
	void drawLog();
	void drawChat();

	ofxENet::Peer peer;
	ofEventListeners listeners;
	ofxImGui::Gui gui;

	// connection settings
	int mode = 0; // 0 server, 1 client
	char host[128] = "127.0.0.1";
	int port = 60000;
	char password[64] = "";
	int maxConnections = 32;
	bool relay = true;
	bool greet = true;
	std::string status = "stopped";

	// compose
	int format = 0; // 0 text, 1 JSON
	int reliability = 3; // ReliableOrdered
	int priority = 1;    // High
	int channel = 0;
	char message[2048] = "hello from openFrameworks";
	ofxENet::PeerId target = 0; // 0: everyone

	// encryption
	char passphrase[128] = "";
	bool encrypt = false;
	bool requireEncrypted = false;
	std::string appliedPassphrase; // what the peer is using now
	bool showPassphrase = false;

	// chat
	char myName[64] = "";
	bool nameEdited = false;
	std::map<ofxENet::PeerId, std::string> names;
	std::deque<ChatLine> chat;

	// log
	std::deque<LogEntry> entries;
	std::deque<std::string> infos;
	bool showSent = true;
	bool showReceived = true;
	bool autoScroll = true;
	char filter[64] = "";
	size_t sentCount = 0, receivedCount = 0, sentBytes = 0, receivedBytes = 0;
};
