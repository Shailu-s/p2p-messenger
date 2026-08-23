# p2p-chat

A minimal Waku-style P2P messaging node in Go: libp2p transport, gossipsub
routing, a persistent peer book, store-and-forward history for nodes that were
offline, and end-to-end encryption with a Double Ratchet.

Relaying nodes forward and store ciphertext they cannot read. Each message uses
a fresh key, so stealing one opens exactly one message and nothing before or
after it.

Deliberately out of scope: RLN and discovery hardening. The aim was depth on
store-and-forward, forward-secret encryption, and the relay/store/filter split
rather than a shallow clone of go-waku.

```sh
go test ./...                                             # 31 tests, no network needed
go test ./internal/crypto -run TestDemoEavesdropper -v     # watch the encryption work
```

The second command prints what a relaying node actually sees, then shows a
stolen message key opening exactly one message while replay and bit-flips are
rejected.

## How it works

A message travels through four layers, each solving a problem the previous one
creates.

**Transport and routing.** Nodes connect over libp2p and publish on gossipsub,
so there is no destination address on the wire: a node forwards to its peers and
a seen-cache stops the loop. Messages reach peers that were never directly
connected. Nodes remember every peer they meet in a persistent address book and
redial it continuously, because in a P2P network rejoining is an ongoing effort
rather than a startup step.

**Encryption.** Two peers derive a shared secret with X25519 and run a Double
Ratchet over it. Every message gets a fresh key from a one-way KDF chain, and
each round trip mixes in new DH material. Compromising one key opens one
message; compromising current state does not open the past, and stops opening
the future after the next ratchet step.

**Store-and-forward.** Gossip only reaches nodes that are online, so every node
also stores what it relays. A node that was offline reconnects and queries a
peer for what it missed. Because relays hold ciphertext under pairwise content
topics rather than clear recipient IDs, a store node can serve history it cannot
read and cannot attribute to a recipient.

**Light clients.** A node that does not want to join gossipsub can subscribe to
selected content topics from a full node over a filter protocol, or ask for all
topics so its narrower interest is not revealed.

## Problems worth reading about

The parts where the obvious implementation is wrong.

**The sync cursor could not be a timestamp.** Message timestamps are the
*receiver's* clock, deliberately, so a lying sender cannot forge ordering. That
makes them useless for paging: one node's clock compared against another's drifts
and drops or duplicates messages at the page boundary. The fix is an opaque
per-peer cursor token that the client stores and never interprets, which is what
go-waku does. See `internal/store/cursor.go`.

**A passing security test that never reached its check.** The test bounding how
many message keys a peer can force us to derive was passing for the wrong
reason: the forged header defaulted `N` to 0, so nothing was skipped and the
bound never fired. It failed a different assertion and looked green. A security
test that never reaches the check it names is worse than no test.
See `TestMaxSkipEnforced` in `internal/crypto/session_test.go`.

**Inbound connections record the wrong address.** When B dials A, the remote
address A sees is B's ephemeral source port, which nothing listens on, so
redialing it always fails. The peer book waits for libp2p's identify protocol to
report the peer's real listen addresses before saving. See `internal/node/peers.go`.

**Persisting ratchet state weakens the guarantee it provides.** Keys that would
otherwise be gone from memory have to survive on disk, or store-and-forward
messages become permanently unreadable after a restart. Resolved in favour of
availability, with the state encrypted at rest and the trade-off stated rather
than hidden. See `internal/crypto/state.go`.

## Layout

```
cmd/p2pchat        entrypoint and the interactive loop
internal/crypto    X25519, HKDF, symmetric chain, Double Ratchet session,
                   long-term identity, session state encrypted at rest
internal/store     message store, eviction, opaque sync cursors
internal/node      libp2p host, peer book, store and filter protocols,
                   per-peer session manager
internal/fsatomic  atomic file writes, shared by crypto and store
```

Dependencies point one way: `node` uses `crypto` and `store`; neither of those
knows the other exists. `Session` keeps its root and chain keys unexported and
serialises itself, so no caller can assign a chain key directly and silently
rewind the ratchet.

## Running the 3-node test

One terminal per node, all commands from the repo root.

### Setup (once per shell)

```sh
go build -o p2pchat ./cmd/p2pchat
```

Rebuild after every code change. `go run ./cmd/p2pchat` also works but is slower
to start, which matters when you are racing to type a message before a node
reconnects.

### Command shape

```
./p2pchat <my-port> [peer-multiaddr]
```

- `<my-port>` — the TCP port this node listens on. Also names its state files.
- `[peer-multiaddr]` — optional. Only needed the first time a node meets a peer;
  after that the address book handles it.

Light client mode uses the filter protocol instead of joining gossipsub:

```
./p2pchat light <my-port> <full-node-multiaddr> (--all|<content-topic> [content-topic...])
```

`--all` asks the full node for every stored topic. Passing one or more content
topics tells the full node exactly which topics this light client wants.

### Start three nodes, chained A—B—C

A and C are never connected directly. That is the point: gossip has to carry
messages through B.

**Terminal 1 — node A (9000):**

```sh
./p2pchat 9000
```

It prints its dial addresses. Copy the `127.0.0.1` one, which looks like:

```
dial me at: /ip4/127.0.0.1/tcp/9000/p2p/12D3KooW...
```

Ignore the LAN address (`192.168.x.x`) unless you are testing across machines.

**Terminal 2 — node B (9001), dialing A:**

```sh
./p2pchat 9001 /ip4/127.0.0.1/tcp/9000/p2p/12D3KooWAEuo8Jjjp18D6QDqxpMdQ9KyoL7s8k2zBNxbEroiXVLc
```

**Terminal 3 — node C (9002), dialing B — not A:**

```sh
./p2pchat 9002 /ip4/127.0.0.1/tcp/9001/p2p/12D3KooWDT9j5AHw6zonRYT7XYnwFP8kQvAe5WLgHhtvKm1pJHEd
```

### Test 1 — gossip through the middle

Type a message in A's terminal and press enter. It should appear in **both** B
and C, even though C never connected to A.

Each node also prints `[stored: N]` after every message, so you can watch the
three stores stay in step.

### Test 2 — store-and-forward (the Stage 3 test)

1. Kill C (`Ctrl-C` in terminal 3).
2. Type 3 messages in A. B receives them; C is offline and misses all three.
3. Restart C **with no peer argument at all**:

   ```sh
   ./p2pchat 9002
   ```

   It reloads `peers-9002.json`, redials B on its own, then queries B for
   history.

Expect within ~5 seconds:

- C: `[peers] reconnected to 12D3KooW...`
- B: `[store] served 3 messages to 12D3KooW...`
- C: three `[history] ...` lines, then `[history] asked 1 peers, got 3, new 3, total 3`

If C shows `new 0`, it already had them — reset and retry (see below).

### Test 3 — partition

Kill B. A and C can no longer reach each other; messages typed in A never
arrive at C. Restart B and they reconnect on their own within ~5 seconds,
because `KeepConnected` retries the address book forever rather than giving up
at boot.

### State files, and resetting

Written into the working directory, named by port:

| File | What it holds | Delete to... |
|---|---|---|
| `node-<port>.key` | private key = the node's permanent identity | give the node a brand new PeerID |
| `ident-<port>.x25519` | long-term X25519 identity key | reset encrypted-session identity |
| `peers-<port>.json` | multiaddrs of peers met so far | force it to need a peer argument again |
| `store-<port>.json` | persisted ciphertext store | clear local message history |
| `cursors-<port>.json` | opaque per-peer/per-topic store cursors | force history queries to restart from the beginning |
| `sessions-<port>.json.enc` | encrypted ratchet session state | drop decryptability for ongoing sessions |
| `state-<port>.key` | local key that encrypts session state at rest | make the encrypted session file unreadable |

Full reset to a clean three-node run:

```sh
rm -f node-*.key ident-*.x25519 peers-*.json store-*.json cursors-*.json sessions-*.json.enc state-*.key
```

Keep the `.key` files if you want stable PeerIDs across restarts — deleting them
means re-copying multiaddrs into every terminal.

### Notes on what you will see

- Startup prints **two** dial addresses: loopback and your LAN interface. Same
  node, two network paths.
- Chat ciphertexts are stored under pairwise content topics, not clear recipient
  peer IDs. `/chat/filter/1.0.0` lets a light node subscribe to selected topics
  from a full node, or request all topics to avoid revealing a narrower interest.
- Your own messages are not echoed back to you, but they are stored — the
  `[stored: N]` counter still moves.
- A duplicate arriving by a second gossip path prints
  `(duplicate ignored: <id>)`. The content hash caught it.
- History fetch retries every 3 seconds for about 36 seconds after boot, since
  at startup there is usually nobody connected yet to ask.
- Ratchet sessions are encrypted at rest with `state-<port>.key`. If an attacker
  steals both that key and `sessions-<port>.json.enc`, they can recover current
  session state; encrypting the file protects against casual disk disclosure,
  not full machine compromise.

### Tests

The crypto tests in `internal/crypto` are pure unit tests and need no running
nodes. The `internal/node` tests start real in-process libp2p hosts on loopback.

## Design limitations

These are known and deliberate. Each one is a place the design stops, not a
place it was left unfinished by accident.

**Key exchange is unauthenticated on first contact.** Peers learn each other's
long-term X25519 keys from a `KeyAnnounce` broadcast. Nothing binds that key to
a real identity, so an attacker positioned between two peers on their first
exchange can substitute its own key and sit in the middle. Diffie-Hellman gives
a secret channel with *somebody*; it does not say who. The mitigation is
trust-on-first-use plus a warning when a known peer's key changes, which is the
same position Signal is in before users compare safety numbers. X3DH with
published prekeys is where this would be fixed properly, and it would also
remove the requirement that both peers be online simultaneously at least once.

**Broadcast costs N ciphertexts.** Sessions are pairwise, so a message to N
peers is encrypted N times and published N times. This is the honest cost of
every recipient having their own ratchet, and it does not scale to large group
chats. Real group messaging uses sender keys or a tree-based construction such
as MLS.

**Metadata is not protected.** Message headers travel in the clear because the
receiver needs the sender's ratchet public key to derive the key that would
decrypt them. An observer learns message counts, timing, and conversation
rhythm, though not content. Ciphertexts are addressed by pairwise content topic
rather than by recipient peer ID, which avoids the most direct leak, but traffic
analysis still works.

**The address book only holds peers met directly.** A node learns addresses from
connections it has actually made, so in a chain A—B—C, A never learns C's
address. Peer exchange or DHT discovery would fix this; both were out of scope.

**No spam or Sybil resistance.** Anything that connects can publish. Waku uses
RLN for rate limiting without identities; that is deliberately not implemented
here.

**Session state at rest is only as safe as the local key.** Ratchet state is
encrypted with `state-<port>.key`, stored beside it. That protects against
casual disk disclosure, not against an attacker who has the machine. Persisting
ratchet state also weakens forward secrecy: keys that would otherwise be gone
from memory survive on disk so that store-and-forward messages remain readable
after a restart. That is a real trade-off between availability and forward
secrecy, resolved here in favour of availability because store-and-forward is
the headline feature.

**Store queries trust the serving peer.** A node fetching history has no way to
verify that a peer returned everything it should have. A malicious store node
can withhold messages silently.
