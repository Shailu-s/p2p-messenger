# p2p-chat

A minimal Waku-style P2P messaging node in Go: libp2p transport, gossipsub
routing, a persistent peer book, store-and-forward history for nodes that were
offline, and end-to-end encryption with a Double Ratchet.

Relaying nodes forward and store ciphertext they cannot read. Each message uses
a fresh key, so stealing one opens exactly one message and nothing before or
after it.

Deliberately out of scope: RLN, discovery hardening, and light-client
protocols. The aim was depth on store-and-forward and forward-secret
encryption rather than a shallow clone of go-waku.

### Seeing the encryption work

```sh
cd node
go test -run TestDemoEavesdropper -v
```

Prints what a relaying node actually sees, then shows a stolen message key
opening exactly one message, and replay and bit-flips being rejected.

## Running the 3-node test

The node source lives in `node/`. Everything below runs from there, one
terminal per node.

### Setup (once per shell)

```sh
cd node
go build -o p2pchat .
```

Rebuild after every code change. `go run .` also works but is slower to start,
which matters when you are racing to type a message before a node reconnects.

### Command shape

```
./p2pchat <my-port> [peer-multiaddr]
```

- `<my-port>` — the TCP port this node listens on. Also names its state files.
- `[peer-multiaddr]` — optional. Only needed the first time a node meets a peer;
  after that the address book handles it.

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

Written into `node/`, named by port:

| File | What it holds | Delete to... |
|---|---|---|
| `node-<port>.key` | private key = the node's permanent identity | give the node a brand new PeerID |
| `peers-<port>.json` | multiaddrs of peers met so far | force it to need a peer argument again |

Full reset to a clean three-node run:

```sh
rm -f node-*.key peers-*.json
```

Keep the `.key` files if you want stable PeerIDs across restarts — deleting them
means re-copying multiaddrs into every terminal.

### Notes on what you will see

- Startup prints **two** dial addresses: loopback and your LAN interface. Same
  node, two network paths.
- Your own messages are not echoed back to you, but they are stored — the
  `[stored: N]` counter still moves.
- A duplicate arriving by a second gossip path prints
  `(duplicate ignored: <id>)`. The content hash caught it.
- History fetch retries every 3 seconds for about 36 seconds after boot, since
  at startup there is usually nobody connected yet to ask.

### Running the tests

```sh
go test ./...
```

The crypto tests (`crypto_test.go`, `ratchet_test.go`, `session_test.go`) are
pure unit tests and need no running nodes.
