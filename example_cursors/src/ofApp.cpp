#include "ofApp.h"

using namespace ofxENet;

void ofApp::setup() {
	ofBackground(25);
	ofSetFrameRate(60);
	auto settings = ofLoadJson("settings.json");
	std::string host = settings.value("host", "127.0.0.1");
	uint16_t port = settings.value("port", 60000);

	listeners.push(peer.onMessage.newListener(this, &ofApp::onMessage));
	listeners.push(peer.onConnect.newListener(this, &ofApp::onConnect));
	listeners.push(peer.onDisconnect.newListener(this, &ofApp::onDisconnect));

	// first copy: server; the port is taken for the next ones, so they connect
	if (peer.startServer(port, 32)) {
		status = "server on port " + ofToString(port);
	} else if (peer.connect(host, port)) {
		status = "connecting to " + host + ":" + ofToString(port);
	} else {
		status = "couldn't start";
	}
}

void ofApp::update() {
	peer.update();
	if (!peer.isRunning()) return;

	// our cursor, ~60 times a second: unreliable sequenced, so late ones are dropped
	Cursor mine { peer.getMyId(), float(ofGetMouseX()), float(ofGetMouseY()) };
	cursors[mine.peer] = { mine.x, mine.y };
	peer.broadcast(CURSOR, &mine, sizeof(mine), 0, Reliability::UnreliableSequenced);
}

void ofApp::onMessage(MessageEvent & e) {
	if (e.type == CURSOR && e.data.size() == sizeof(Cursor)) {
		Cursor cursor;
		std::memcpy(&cursor, e.data.getData(), sizeof(cursor));
		cursors[cursor.peer] = { cursor.x, cursor.y };
		// the server passes each client's cursor on to the others
		if (peer.isServer()) {
			peer.broadcast(CURSOR, &cursor, sizeof(cursor), e.peer, Reliability::UnreliableSequenced);
		}
	} else if (e.type == LEAVE && e.data.size() == sizeof(PeerId)) {
		PeerId left;
		std::memcpy(&left, e.data.getData(), sizeof(left));
		cursors.erase(left);
	}
}

void ofApp::onConnect(ConnectionEvent & e) {
	if (!peer.isServer()) {
		status = "connected to " + e.address;
	}
}

void ofApp::onDisconnect(DisconnectionEvent & e) {
	cursors.erase(e.peer);
	if (peer.isServer()) {
		// tell the others to drop that cursor
		peer.broadcast(LEAVE, &e.peer, sizeof(e.peer));
	} else {
		status = "disconnected: " + toString(e.reason);
		cursors.clear();
	}
}

void ofApp::draw() {
	for (auto & [id, position] : cursors) {
		ofColor color = ofColor::fromHsb((id * 2654435761ull >> 24) % 255, 180, 255);
		ofSetColor(color);
		ofDrawCircle(position, id == peer.getMyId() ? 14 : 10);
		auto hex = ofToHex(id);
		ofDrawBitmapString(hex.substr(hex.size() - 6), position + glm::vec2(16, 4));
	}
	ofSetColor(255);
	ofDrawBitmapStringHighlight(status + "\n" + ofToString(peer.getNumConnections()) + " connections, "
		+ ofToString(cursors.size()) + " cursors\nrun another copy to join", 10, 20);
}
