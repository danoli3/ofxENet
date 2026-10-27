# ofxENet

[![ofxENet](https://github.com/danoli3/ofxENet/actions/workflows/ci.yml/badge.svg)](https://github.com/danoli3/ofxENet/actions/workflows/ci.yml)

Reliable UDP networking for openFrameworks on [ENet](https://github.com/zpl-c/enet): servers and
clients, 32 channels, reliable and unreliable messages, text / `ofBuffer` / JSON, connection events and
messages on the main thread, and optional AES-256-GCM encryption.

ENet is small, fast and actively maintained. This is the [zpl-c](https://github.com/zpl-c/enet) fork
(v2.7.0, June 2026): a single header, IPv4 and IPv6. It's in `libs/enet` (MIT).

**Same API as [ofxRakNet](https://github.com/danoli3/ofxRakNet)**: an app moves over by changing
`ofxRakNet` to `ofxENet` (see [Coming from ofxRakNet](#coming-from-ofxraknet)).

## Quick start

```cpp
#include "ofxENet.h"

ofxENet::Peer peer;

// setup: a server...
peer.startServer(60000);
// ...or a client
peer.connect("192.168.1.10", 60000);

peer.onConnect.newListener([](ofxENet::ConnectionEvent & e) { ofLog() << "connected " << e.address; });
peer.onMessage.newListener([](ofxENet::MessageEvent & e) {
	if (e.type == 0) ofLog() << e.getText();
	if (e.type == 1) ofLog() << e.getJson().dump();
});

// update: ENet sends and receives here, and the events fire (main thread)
peer.update();

// send to one peer (ids come from onConnect / onMessage), or to everyone
peer.send(otherPeerId, 0, std::string("hello"));
peer.broadcast(1, ofJson { { "x", 10 }, { "y", 20 } });
peer.broadcast(2, &position, sizeof(position), 0, ofxENet::Reliability::UnreliableSequenced);
```

## Peer

| | |
|---|---|
| `startServer(port, maxConnections = 32, password = "")` | listen for peers (port 0: any free port; a server can also `connect`) |
| `startClient()` / `connect(host, port, password = "")` | connect (`connect` starts the client if needed); host names and IPv6 work |
| `disconnect(peer)`, `stop()` | close one connection, or everything (also on destruction) |
| `send(peer, type, data, reliability, priority, channel)` | `std::string`, `ofBuffer`, `ofJson`, or a pointer and size |
| `broadcast(type, data, except = 0, ...)` | to every connected peer, except one |
| `update()` / `setAutoUpdate(true)` | ENet does its networking here: call it every frame |
| `getConnections()`, `getNumConnections()`, `getAddress(peer)`, `getPing(peer)`, `getMyId()`, `getPort()` | |
| `getHost()` | the `ENetHost`, for the rest of ENet (bandwidth limits, compression, ...) |

Events: `onConnect`, `onDisconnect` (with a `Reason`: disconnected, lost, connect failed, server full,
invalid password, incompatible protocol), and `onMessage` (`peer`, `address`, `type`, `channel`, `data`,
`getText()`, `getJson()`, `encrypted`, `authentic`).

- **Message type** is yours: 0 to 255.
- **Channels** 0 to 31 (`Peer::CHANNELS`): each is ordered on its own, so a big reliable message on one
  doesn't hold up another.
- **Reliability:**
  - `Unreliable`: ENet unsequenced.
  - `UnreliableSequenced`: ENet unreliable; late ones are dropped.
  - `Reliable`, `ReliableOrdered` (default) and `ReliableSequenced`: ENet reliable, ordered on its channel.
  - Large unreliable messages are sent as unreliable fragments.
- **Priority** is accepted for ofxRakNet compatibility but ignored: ENet has no send priorities.
- **Messages** up to 32 MB.

### The handshake

ENet connections don't carry passwords or stable ids, so each connection starts with a small handshake
on an internal channel. The connecting side sends a protocol version, a random 64-bit peer id, and a
SHA-256 of the password. The server checks it, answers with its own id, or refuses with a reason (wrong
password, full, incompatible). `onConnect` only fires once that's done, so a `PeerId` is the same on
both ends and can be passed along (the messenger's relay does). Connections that never send a valid
handshake are dropped after 5 seconds. The password only gates who connects; it doesn't encrypt
anything. Use a passphrase for that.

## Encryption

```cpp
peer.setPassphrase("gallery-secret");   // every peer uses the same passphrase
peer.requireEncryption = true;          // optional: drop anything not encrypted with it
ofLog() << "key " << peer.getFingerprint();   // compare between machines
```

With a passphrase, every message's payload is encrypted with **AES-256-GCM** (openFrameworks'
OpenSSL), so the content is hidden and any change on the way is detected. The key comes from the
passphrase with **PBKDF2-HMAC-SHA256** (200,000 iterations) and a random 16 byte **salt** per session.
The salt travels with each message, and receivers derive each sender's key once and cache it. Every
message gets a fresh random 12 byte nonce. `MessageEvent::encrypted` and `authentic` say what happened.
`ofxENet::crypto` (`ofxENetCrypto.h`) has the pieces on their own: `Cipher`, `sha256`, `deriveKey`,
`randomBytes`, `toHex`.

Limits: the message type, channel and sizes aren't hidden; there's no forward secrecy (anyone who learns
the passphrase can read recorded traffic); a weak passphrase can be guessed offline, PBKDF2 only slows
that down; and a relaying server needs the passphrase to read and re-send.

## Examples

Run two copies of an example: the first becomes the server on the port in `bin/data/settings.json`,
the next find the port taken and connect to it. To connect across machines, set `"host"` there.

| Example | |
|---|---|
| `example_cursors` | every copy's mouse cursor in every window (unreliable sequenced, relayed by the server) |
| `example_chat` | type and press Enter: JSON lines to everyone (reliable ordered) |
| `example_imgui_messenger` | needs [ofxImGui](https://github.com/jvcleave/ofxImGui) (`develop`): connection settings, a passphrase for encryption (with key fingerprint), a peer list with ping (pick who to send to, kick), compose text or JSON with any reliability / channel, a chat view and a filterable log with each message's SHA-256, and server relay with the original sender framed in. Start encrypted with `"passphrase"` in `settings.json` or `OFXENET_PASSPHRASE` |
| `example_tests` | headless localhost checks: text, JSON, a 1 MB message, broadcast, passwords, full servers, channels, and encryption. The security checks refuse an empty or wrong password, a truncated or garbage envelope, a flipped authentication tag, a different passphrase, and a different PBKDF2 stretch |

Build them with projectGenerator, or copy `scripts/templates/<platform>/Makefile` and `config.make`
into the example folder.

## Coming from ofxRakNet

- `ofxRakNet::` becomes `ofxENet::`, and `#include "ofxRakNet.h"` becomes `#include "ofxENet.h"`. The
  `Peer` API, the events and the encryption are the same.
- Message types: 0-255 instead of 0-121. Channels: 0-31.
- `Priority` is ignored. `getRakPeer()` becomes `getHost()` (an `ENetHost`). `onPacket` is gone (there are
  no other RakNet packets).
- ENet does its networking in `update()` rather than on a thread, so call it every frame. Pings are
  measured from `update()`, so at 60 fps they include up to a frame of waiting.
- The two don't talk to each other: both ends need the same addon.

## Platforms

Supported openFrameworks release: **0.12.1**. GitHub Actions clones current
`openframeworks/openFrameworks` master, prints that version and commit on the job summary, builds the
examples, and runs `example_tests` on Linux and macOS. The security checks stay on localhost.

Tested on macOS (Apple Silicon) with the openFrameworks makefiles, projectGenerator / Xcode, and
AddressSanitizer. ENet itself supports Windows, Linux, macOS, iOS and Android. Visual Studio links
`ws2_32` and `winmm` from `enet.h`; MSYS2 gets `-lwinmm` from `addon_config.mk`. OpenSSL (for
encryption and the password hash) comes from openFrameworks.

## License

ofxENet: MIT, Dan Rosser. ENet: MIT, Lee Salzman and the zpl-c contributors (`libs/enet/license`).
