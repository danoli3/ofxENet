#include "ofApp.h"

using namespace ofxENet;

void ofApp::setup() {
	ofBackground(30);
	auto settings = ofLoadJson("settings.json");
	std::string host = settings.value("host", "127.0.0.1");
	uint16_t port = settings.value("port", 60000);

	listeners.push(peer.onMessage.newListener(this, &ofApp::onMessage));
	listeners.push(peer.onConnect.newListener(this, &ofApp::onConnect));
	listeners.push(peer.onDisconnect.newListener(this, &ofApp::onDisconnect));

	if (peer.startServer(port, 32)) {
		addLine("* server on port " + ofToString(port) + ", waiting for others");
	} else if (peer.connect(host, port)) {
		addLine("* connecting to " + host + ":" + ofToString(port));
	}
	auto hex = ofToHex(peer.getMyId());
	name = (peer.isServer() ? "server " : "client ") + hex.substr(hex.size() - 4);
}

void ofApp::update() {
	peer.update();
}

void ofApp::addLine(const std::string & line) {
	lines.push_back(line);
	while (lines.size() > 30) lines.pop_front();
}

void ofApp::onMessage(MessageEvent & e) {
	if (e.type != CHAT) return;
	auto json = e.getJson();
	if (!json.is_object()) return;
	addLine(json.value("from", "?") + ": " + json.value("text", ""));
	// the server relays each client's line to the other clients
	if (peer.isServer()) {
		peer.broadcast(CHAT, json, e.peer);
	}
}

void ofApp::onConnect(ConnectionEvent & e) {
	addLine("* connected: " + e.address);
}

void ofApp::onDisconnect(DisconnectionEvent & e) {
	addLine("* " + e.address + ": " + toString(e.reason));
}

void ofApp::keyPressed(int key) {
	if (key == OF_KEY_RETURN) {
		if (typing.empty()) return;
		ofJson message = { { "from", name }, { "text", typing } };
		peer.broadcast(CHAT, message);
		addLine(name + ": " + typing);
		typing.clear();
	} else if (key == OF_KEY_BACKSPACE) {
		if (!typing.empty()) typing.pop_back();
	} else if (key >= 32 && key < 127) {
		typing += char(key);
	}
}

void ofApp::draw() {
	ofSetColor(220);
	float y = 30;
	for (auto & line : lines) {
		ofDrawBitmapString(line, 20, y);
		y += 16;
	}
	ofDrawBitmapStringHighlight(name + " (" + ofToString(peer.getNumConnections()) + " connections)  > " + typing + "_",
		20, ofGetHeight() - 20);
}
