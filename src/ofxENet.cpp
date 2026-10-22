#define ENET_IMPLEMENTATION
#include "enet.h"

#include "ofxENet.h"

#include "ofLog.h"
#include "ofUtils.h"

#include <cstring>

namespace ofxENet {

namespace {

// channel 0 .. CHANNELS-1: messages; CONTROL: the handshake
constexpr uint8_t USER_CHANNELS = 32;
constexpr uint8_t CONTROL = USER_CHANNELS;

// handshake: 'H', version, sender id (8), password digest (32)
constexpr unsigned char HELLO = 'H';
constexpr unsigned char PROTOCOL_VERSION = 1;
constexpr size_t HELLO_SIZE = 2 + 8 + 32;
constexpr uint64_t HANDSHAKE_TIMEOUT_MS = 5000;

// enet_peer_disconnect codes, so the other side knows why
enum Code : uint32_t {
	CODE_NONE = 0,
	CODE_SERVER_FULL = 0x0F0E0001,
	CODE_INVALID_PASSWORD = 0x0F0E0002,
	CODE_INCOMPATIBLE = 0x0F0E0003,
};

int initCount = 0;

std::string passwordDigest(const std::string & password) {
	if (password.empty()) return std::string(32, '\0');
	return crypto::sha256("ofxENet password:" + password);
}

enet_uint32 flagsFor(Reliability r, size_t size, size_t mtu) {
	switch (r) {
	case Reliability::Unreliable:
		return ENET_PACKET_FLAG_UNSEQUENCED | (size > mtu ? ENET_PACKET_FLAG_UNRELIABLE_FRAGMENT : 0);
	case Reliability::UnreliableSequenced:
		return size > mtu ? ENET_PACKET_FLAG_UNRELIABLE_FRAGMENT : 0;
	default:
		return ENET_PACKET_FLAG_RELIABLE;
	}
}

std::string peerAddress(ENetPeer * peer) {
	char ip[64] = { 0 };
	enet_peer_get_ip(peer, ip, sizeof(ip));
	std::string s = ip;
	// IPv4 peers show up IPv4-mapped in dual-stack mode
	if (s.rfind("::ffff:", 0) == 0) s = s.substr(7);
	return s + "|" + ofToString(enet_peer_get_port(peer));
}

} // namespace

const uint8_t Peer::MAX_MESSAGE_TYPE = 255;
const uint8_t Peer::CHANNELS = USER_CHANNELS;

ofJson MessageEvent::getJson() const {
	return ofJson::parse(data.getText(), nullptr, false);
}

std::string toString(DisconnectionEvent::Reason reason) {
	switch (reason) {
	case DisconnectionEvent::Reason::Disconnected: return "disconnected";
	case DisconnectionEvent::Reason::Lost: return "connection lost";
	case DisconnectionEvent::Reason::ConnectFailed: return "connection attempt failed";
	case DisconnectionEvent::Reason::ServerFull: return "server full";
	case DisconnectionEvent::Reason::InvalidPassword: return "invalid password";
	case DisconnectionEvent::Reason::Banned: return "banned";
	case DisconnectionEvent::Reason::IncompatibleProtocol: return "incompatible protocol";
	case DisconnectionEvent::Reason::AlreadyConnected: return "already connected";
	}
	return "unknown";
}

Peer::Peer() {
	if (initCount++ == 0 && enet_initialize() != 0) {
		ofLogError("ofxENet") << "enet_initialize failed";
	}
}

Peer::~Peer() {
	stop();
	if (--initCount == 0) {
		enet_deinitialize();
	}
}

bool Peer::start(uint16_t port, size_t peerSlots) {
	stop();
	ENetAddress address {};
	address.host = ENET_HOST_ANY;
	address.port = port;
	host = enet_host_create(server ? &address : nullptr, peerSlots, USER_CHANNELS + 1, 0, 0);
	if (!host) {
		ofLogError("ofxENet") << "couldn't start" << (server ? " on port " + ofToString(port) : std::string());
		server = false;
		return false;
	}
	std::string id = crypto::randomBytes(sizeof(PeerId));
	std::memcpy(&myId, id.data(), sizeof(myId));
	if (myId == 0) myId = 1;
	return true;
}

bool Peer::startServer(uint16_t port, unsigned int max, const std::string & password) {
	server = true;
	maxConnections = max;
	passwordDigest = ofxENet::passwordDigest(password);
	// one spare slot, so a connection over the limit can be told the server is full
	if (!start(port, size_t(max) + 1)) {
		return false;
	}
	return true;
}

bool Peer::startClient() {
	server = false;
	maxConnections = 0;
	passwordDigest = ofxENet::passwordDigest("");
	return start(0, 8);
}

bool Peer::connect(const std::string & hostName, uint16_t port, const std::string & password) {
	if (!host && !startClient()) {
		return false;
	}
	ENetAddress address {};
	if (enet_address_set_host(&address, hostName.c_str()) != 0) {
		ofLogError("ofxENet") << "couldn't resolve " << hostName;
		return false;
	}
	address.port = port;
	auto * peer = enet_host_connect(host, &address, USER_CHANNELS + 1, 0);
	if (!peer) {
		ofLogError("ofxENet") << "couldn't connect to " << hostName << ":" << port << " (no free peer slot)";
		return false;
	}
	outgoingPasswordDigest = ofxENet::passwordDigest(password);
	Remote r;
	r.initiated = true;
	r.since = ofGetElapsedTimeMillis();
	r.address = hostName + "|" + ofToString(port);
	remotes[peer] = r;
	return true;
}

void Peer::disconnect(PeerId id) {
	if (auto * peer = find(id)) {
		enet_peer_disconnect(peer, CODE_NONE);
	}
}

void Peer::stop() {
	if (!host) return;
	for (auto & [peer, remote] : remotes) {
		enet_peer_disconnect(peer, CODE_NONE);
	}
	// let the disconnects go out (like RakNet's Shutdown(300))
	auto start = ofGetElapsedTimeMillis();
	ENetEvent event;
	while (!remotes.empty() && ofGetElapsedTimeMillis() - start < 300) {
		while (enet_host_service(host, &event, 10) > 0) {
			if (event.type == ENET_EVENT_TYPE_RECEIVE) enet_packet_destroy(event.packet);
			if (event.type == ENET_EVENT_TYPE_DISCONNECT || event.type == ENET_EVENT_TYPE_DISCONNECT_TIMEOUT) {
				remotes.erase(event.peer);
			}
		}
	}
	enet_host_flush(host);
	enet_host_destroy(host);
	host = nullptr;
	remotes.clear();
	server = false;
}

uint16_t Peer::getPort() const {
	if (!host) return 0;
	ENetAddress address {};
	if (enet_socket_get_address(host->socket, &address) == 0) return address.port;
	return host->address.port;
}

ENetPeer * Peer::find(PeerId id) const {
	for (auto & [peer, remote] : remotes) {
		if (remote.ready && remote.id == id) return peer;
	}
	return nullptr;
}

void Peer::sendHello(ENetPeer * peer, const std::string & digest) {
	unsigned char hello[HELLO_SIZE];
	hello[0] = HELLO;
	hello[1] = PROTOCOL_VERSION;
	std::memcpy(hello + 2, &myId, 8);
	std::memcpy(hello + 10, digest.data(), 32);
	enet_peer_send(peer, CONTROL, enet_packet_create(hello, sizeof(hello), ENET_PACKET_FLAG_RELIABLE));
}

void Peer::handleControl(ENetPeer * peer, const unsigned char * data, size_t size) {
	auto it = remotes.find(peer);
	if (it == remotes.end() || it->second.ready) return;
	auto & remote = it->second;
	if (size != HELLO_SIZE || data[0] != HELLO || data[1] != PROTOCOL_VERSION) {
		enet_peer_disconnect(peer, CODE_INCOMPATIBLE);
		return;
	}
	PeerId id;
	std::memcpy(&id, data + 2, 8);
	if (!remote.initiated) {
		// we're accepting: check the password and the connection limit, then answer
		if (std::memcmp(data + 10, passwordDigest.data(), 32) != 0) {
			enet_peer_disconnect(peer, CODE_INVALID_PASSWORD);
			return;
		}
		size_t accepted = 0;
		for (auto & [p, r] : remotes) {
			if (r.ready && !r.initiated) accepted++;
		}
		if (!server || accepted >= maxConnections) {
			enet_peer_disconnect(peer, CODE_SERVER_FULL);
			return;
		}
		sendHello(peer, std::string(32, '\0'));
	}
	remote.id = id;
	remote.ready = true;
	ConnectionEvent e { id, remote.address };
	ofNotifyEvent(onConnect, e, this);
}

void Peer::handleDisconnect(ENetPeer * peer, uint32_t code, bool timeout) {
	auto it = remotes.find(peer);
	if (it == remotes.end()) return;
	Remote remote = it->second;
	remotes.erase(it);

	DisconnectionEvent e;
	e.peer = remote.id;
	e.address = remote.address;
	if (remote.ready) {
		e.reason = timeout ? DisconnectionEvent::Reason::Lost : DisconnectionEvent::Reason::Disconnected;
	} else if (remote.initiated) {
		switch (code) {
		case CODE_SERVER_FULL: e.reason = DisconnectionEvent::Reason::ServerFull; break;
		case CODE_INVALID_PASSWORD: e.reason = DisconnectionEvent::Reason::InvalidPassword; break;
		case CODE_INCOMPATIBLE: e.reason = DisconnectionEvent::Reason::IncompatibleProtocol; break;
		default: e.reason = DisconnectionEvent::Reason::ConnectFailed; break;
		}
	} else {
		return; // an incoming connection that never finished its handshake
	}
	ofNotifyEvent(onDisconnect, e, this);
}

void Peer::update() {
	if (!host) return;
	ENetEvent event;
	while (host && enet_host_service(host, &event, 0) > 0) {
		switch (event.type) {
		case ENET_EVENT_TYPE_CONNECT: {
			auto & remote = remotes[event.peer];
			remote.address = peerAddress(event.peer);
			remote.since = ofGetElapsedTimeMillis();
			if (remote.initiated) sendHello(event.peer, outgoingPasswordDigest);
			break;
		}
		case ENET_EVENT_TYPE_RECEIVE: {
			auto it = remotes.find(event.peer);
			if (event.channelID == CONTROL) {
				handleControl(event.peer, event.packet->data, event.packet->dataLength);
			} else if (it != remotes.end() && it->second.ready && event.packet->dataLength >= 1) {
				MessageEvent e;
				e.peer = it->second.id;
				e.address = it->second.address;
				e.type = event.packet->data[0];
				e.channel = event.channelID;
				std::string payload(reinterpret_cast<const char *>(event.packet->data + 1), event.packet->dataLength - 1);
				e.encrypted = crypto::Cipher::isEnvelope(payload);
				if (e.encrypted) {
					auto plain = cipher.decrypt(payload);
					e.authentic = plain.has_value();
					if (plain) e.data.set(plain->data(), plain->size());
				} else {
					e.data.set(payload.data(), payload.size());
				}
				enet_packet_destroy(event.packet);
				if (!(cipher.isEnabled() && requireEncryption && !e.authentic)) {
					ofNotifyEvent(onMessage, e, this);
				}
				continue;
			}
			enet_packet_destroy(event.packet);
			break;
		}
		case ENET_EVENT_TYPE_DISCONNECT:
			handleDisconnect(event.peer, event.data, false);
			break;
		case ENET_EVENT_TYPE_DISCONNECT_TIMEOUT:
			handleDisconnect(event.peer, event.data, true);
			break;
		default:
			break;
		}
	}
	// drop incoming connections that never send a valid handshake
	if (!host) return;
	auto now = ofGetElapsedTimeMillis();
	for (auto it = remotes.begin(); it != remotes.end();) {
		if (!it->second.ready && !it->second.initiated && now - it->second.since > HANDSHAKE_TIMEOUT_MS) {
			enet_peer_disconnect_now(it->first, CODE_INCOMPATIBLE);
			it = remotes.erase(it);
		} else {
			++it;
		}
	}
}

bool Peer::sendPacket(ENetPeer * only, PeerId except, uint8_t type, const void * data, size_t size,
	Reliability reliability, uint8_t channel) {
	if (!host) {
		ofLogWarning("ofxENet") << "send before startServer() / startClient()";
		return false;
	}
	if (channel >= USER_CHANNELS) {
		ofLogError("ofxENet") << "channel " << int(channel) << " is above " << int(USER_CHANNELS - 1);
		return false;
	}
	std::string sealed;
	if (cipher.isEnabled()) {
		sealed = cipher.encrypt(std::string(static_cast<const char *>(data), size));
		if (sealed.empty()) return false;
		data = sealed.data();
		size = sealed.size();
	}
	if (size + 1 > host->maximumPacketSize) {
		ofLogError("ofxENet") << "message too large: " << size << " bytes (max " << host->maximumPacketSize << ")";
		return false;
	}
	auto * packet = enet_packet_create(nullptr, size + 1, flagsFor(reliability, size + 1, enet_host_get_mtu(host)));
	if (!packet) return false;
	packet->data[0] = type;
	if (size > 0) std::memcpy(packet->data + 1, data, size);

	size_t sent = 0;
	if (only) {
		if (enet_peer_send(only, channel, packet) == 0) sent++;
	} else {
		for (auto & [peer, remote] : remotes) {
			if (remote.ready && remote.id != except && enet_peer_send(peer, channel, packet) == 0) sent++;
		}
	}
	if (sent == 0) {
		enet_packet_destroy(packet);
	}
	return sent > 0;
}

bool Peer::send(PeerId id, uint8_t type, const void * data, size_t size, Reliability r, Priority, uint8_t channel) {
	auto * peer = find(id);
	if (!peer) {
		ofLogWarning("ofxENet") << "send: no connected peer " << ofToHex(id) << (id == 0 ? " (use broadcast())" : "");
		return false;
	}
	return sendPacket(peer, 0, type, data, size, r, channel);
}

bool Peer::send(PeerId id, uint8_t type, const std::string & text, Reliability r, Priority p, uint8_t channel) {
	return send(id, type, text.data(), text.size(), r, p, channel);
}

bool Peer::send(PeerId id, uint8_t type, const ofBuffer & buffer, Reliability r, Priority p, uint8_t channel) {
	return send(id, type, buffer.getData(), buffer.size(), r, p, channel);
}

bool Peer::send(PeerId id, uint8_t type, const ofJson & json, Reliability r, Priority p, uint8_t channel) {
	return send(id, type, json.dump(), r, p, channel);
}

bool Peer::broadcast(uint8_t type, const void * data, size_t size, PeerId except, Reliability r, Priority, uint8_t channel) {
	return sendPacket(nullptr, except, type, data, size, r, channel);
}

bool Peer::broadcast(uint8_t type, const std::string & text, PeerId except, Reliability r, Priority p, uint8_t channel) {
	return broadcast(type, text.data(), text.size(), except, r, p, channel);
}

bool Peer::broadcast(uint8_t type, const ofJson & json, PeerId except, Reliability r, Priority p, uint8_t channel) {
	return broadcast(type, json.dump(), except, r, p, channel);
}

void Peer::setPassphrase(const std::string & passphrase) {
	cipher.setPassphrase(passphrase);
}

void Peer::setAutoUpdate(bool autoUpdate) {
	if (autoUpdate) {
		updateListener = ofEvents().update.newListener([this](ofEventArgs &) { update(); }, OF_EVENT_ORDER_BEFORE_APP);
	} else {
		updateListener.unsubscribe();
	}
}

std::vector<PeerId> Peer::getConnections() const {
	std::vector<PeerId> result;
	for (auto & [peer, remote] : remotes) {
		if (remote.ready) result.push_back(remote.id);
	}
	return result;
}

size_t Peer::getNumConnections() const {
	return getConnections().size();
}

std::string Peer::getAddress(PeerId id) const {
	for (auto & [peer, remote] : remotes) {
		if (remote.ready && remote.id == id) return remote.address;
	}
	return "";
}

int Peer::getPing(PeerId id) const {
	auto * peer = find(id);
	return peer ? int(enet_peer_get_rtt(peer)) : -1;
}

} // namespace ofxENet
