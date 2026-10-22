meta:
	ADDON_NAME = ofxENet
	ADDON_DESCRIPTION = Reliable UDP networking for openFrameworks on ENet (zpl-c/enet), with optional AES-256-GCM encryption; same API as ofxRakNet
	ADDON_AUTHOR = Dan Rosser
	ADDON_TAGS = "networking" "enet" "udp" "multiplayer" "encryption"
	ADDON_URL = https://github.com/danoli3/ofxENet

common:
	ADDON_INCLUDES = libs/enet/include
	ADDON_INCLUDES += src
	# ENet is header-only: ofxENet.cpp compiles it (ENET_IMPLEMENTATION).
	# Encryption uses openFrameworks' OpenSSL (libs/openssl, or the system's on Linux).
	# Visual Studio links ws2_32 and winmm from enet.h (#pragma comment).

msys2:
	ADDON_LDFLAGS = -lwinmm
