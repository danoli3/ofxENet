#pragma once

#include "ofMain.h"
#include "ofxENet.h"

// Run this example twice. The first copy becomes the server on the port in
// bin/data/settings.json; the next ones find the port taken and connect to it.
// Every copy sends its mouse position, the server relays them, and each window
// draws everyone's cursor.
class ofApp : public ofBaseApp {
public:
	void setup() override;
	void update() override;
	void draw() override;

	enum MessageType : uint8_t {
		CURSOR = 0, // Cursor payload
		LEAVE = 1,  // PeerId payload: that peer left (server -> clients)
	};

	struct Cursor {
		ofxENet::PeerId peer;
		float x, y;
	};

	void onMessage(ofxENet::MessageEvent & e);
	void onConnect(ofxENet::ConnectionEvent & e);
	void onDisconnect(ofxENet::DisconnectionEvent & e);

	ofxENet::Peer peer;
	ofEventListeners listeners;
	std::map<ofxENet::PeerId, glm::vec2> cursors;
	std::string status;
};
