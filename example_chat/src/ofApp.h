#pragma once

#include "ofMain.h"
#include "ofxENet.h"

// Run this example twice (or on two machines: set "host" in bin/data/settings.json).
// The first copy is the server; the others connect to it. Type and press Enter to
// send a line to everyone: messages are JSON, reliable and ordered.
class ofApp : public ofBaseApp {
public:
	void setup() override;
	void update() override;
	void draw() override;
	void keyPressed(int key) override;

	static constexpr uint8_t CHAT = 0;

	void onMessage(ofxENet::MessageEvent & e);
	void onConnect(ofxENet::ConnectionEvent & e);
	void onDisconnect(ofxENet::DisconnectionEvent & e);
	void addLine(const std::string & line);

	ofxENet::Peer peer;
	ofEventListeners listeners;
	std::string name;
	std::string typing;
	std::deque<std::string> lines;
};
