# System Design, Store, And Paging

How the node fits together as a system, and how the store-and-forward path
works end to end.

## 1. System Design Diagram

```text
                         ┌──────────────────────────────┐
                         │          Full Node A          │
                         │                              │
                         │ libp2p host                  │
                         │ gossipsub relay              │
                         │ SessionManager               │
                         │ local Store                  │
                         └──────────────┬───────────────┘
                                        │
                         gossipsub topic: chat-room
                         payload: encrypted envelope
                                        │
                ┌───────────────────────▼───────────────────────┐
                │                  Full Node B                   │
                │                                               │
                │ libp2p host                                   │
                │ peer book: peers-<port>.json                  │
                │ store: store-<port>.json                      │
                │ session state: sessions-<port>.json.enc       │
                │ store protocol:  /chat/store/1.0.0            │
                │ filter protocol: /chat/filter/1.0.0           │
                └───────────────┬─────────────────┬─────────────┘
                                │                 │
        store query + cursor    │                 │ filter stream
        after reconnect         │                 │ selected topics or --all
                                │                 │
                ┌───────────────▼──────────┐    ┌──▼────────────────┐
                │        Full Node C        │   │   Light Client     │
                │                           │   │                    │
                │ can go offline            │   │ does not join      │
                │ reconnects by peer book   │   │ gossipsub          │
                │ fetches missed ciphertext │   │ reads from B       │
                │ decrypts if topic is its  │   │ via filter stream  │
                └───────────────────────────┘   └───────────────────┘
```

## 2. Component Map

| Component | Code | Job |
|---|---|---|
| libp2p host | `main.go` | Owns node identity, listens on TCP, connects to peers. |
| Peer book | `peers.go` | Remembers known multiaddrs and keeps redialing. |
| Gossip relay | `main.go` | Broadcasts encrypted envelopes on `chat-room`. |
| Key announcements | `sessions.go`, `main.go` | Publishes long-term X25519 public keys on `chat-keys`. |
| Session manager | `sessions.go` | Tracks pairwise ratchet sessions and content topics. |
| Store | `store.go` | Persists ciphertexts, dedups by content hash, pages by cursor. |
| Store protocol | `storeproto.go` | Request/response history fetch over `/chat/store/1.0.0`. |
| Cursor book | `cursor.go` | Remembers each remote peer's opaque cursor per topic. |
| Filter protocol | `filter.go` | Streams selected topics from a full node to a light client. |

## 3. Message Send Path

When the user types a line in a full node:

```text
stdin line
  -> SessionManager.EncryptToAll
  -> one ciphertext per known peer
  -> each envelope has:
       From: sender peer ID
       Topic: pairwise content topic
       Wire: encrypted ratchet envelope
  -> publish each blob to gossipsub topic "chat-room"
```

Important design point:

```text
N recipients = N ciphertexts
```

That is simple and correct for pairwise ratchets. It is not scalable group
messaging. This is the interview trade-off: real group messaging would use
sender keys or MLS.

## 4. Receive Path

Every full node receives gossipsub messages from `chat-room`.

The node always stores first:

longest substring without repeating characters : 
I used a sliding window with a map from character to its last index: O(n) time, O(min(n, charset)) space, every character enters and leaves the window once.

The space-cheaper version is brute force — check every substring for duplicates with two pointers and no map, O(1) space but O(n²) or worse in time. I would only pick that if the alphabet were huge and memory was the hard constraint; for normal input the map is worth it.

```text
gossip message arrives
  -> compute content hash ID
  -> extract content topic from outer envelope
  -> Store.Put(ciphertext)
  -> if duplicate, ignore
  -> TryDecrypt
       if topic belongs to us: decrypt and print
       otherwise: print opaque relay message
```

Why store before decrypt?

Because a relay node is allowed to hold mail it cannot read. That is the core
store-and-forward property.

## 5. Store Data Model

`StoredMessage` is the durable record:

```go
type StoredMessage struct {
    Seq       uint64
    ID        string
    Topic     string
    Timestamp int64
    Payload   []byte
}
```

Meaning:

| Field | Meaning |
|---|---|
| `Seq` | Local append sequence assigned by this store. Used for paging. |
| `ID` | SHA-256 of payload. Used for dedup. |
| `Topic` | Content topic used for filtering/history queries. |
| `Timestamp` | Local receive time. Evidence only, not sync state. |
| `Payload` | Ciphertext bytes. Store nodes do not decrypt this. |

## 6. Why Timestamp Is Not The Cursor

Bad design:

```text
C asks B: give me messages since timestamp 12345
```

That sounds natural, but it is wrong here.

`Timestamp` is the receiver's clock. If A sends one message, B and C may store
the same ciphertext with different timestamps:

```text
B receives at 10:00:01.100
C receives at 10:00:04.900
```

If C later sends its timestamp to B, C is comparing C's clock against B's clock.
That causes duplicates or missed messages near the boundary.

Correct design:

```text
C does not interpret the cursor.
C stores B's nextCursor and sends it back to B next time.
B decides what that cursor means.
```

In this implementation, B's cursor encodes B's local `Seq`. The client treats it
as an opaque string.

## 7. Store Paging Flow

First fetch:

```text
C -> B:
{
  "topic": "/chat/2/abc...",
  "cursor": "",
  "limit": 100
}

B:
  after = 0
  return messages where Topic matches and Seq > 0
  nextCursor = cursor(last returned Seq)

C:
  store returned messages locally
  save B's nextCursor in cursors-<port>.json
```

Second fetch:

```text
C -> B:
{
  "topic": "/chat/2/abc...",
  "cursor": "opaque-token-from-B",
  "limit": 100
}

B:
  decode its own cursor
  return only messages after that Seq
```

Interview sentence:

> The cursor belongs to the server that created it. The client only stores and
> returns it.

## 8. Code Walkthrough: Store.Put

Read `internal/store/store.go`.

The important path:

```text
Put(m)
  lock store
  if ID already seen:
      return duplicate
  if Timestamp missing:
      assign local receive time
  assign local Seq
  add to byID map
  append to ordered list
  evict old messages if over maxItems
  save store to disk
  notify filter subscribers
```

Why both `byID` and `ordered`?

| Structure | Reason |
|---|---|
| `byID` map | O(1) duplicate detection. |
| `ordered` slice | Stable history order and paging scan. |

## 9. Code Walkthrough: Store.Query

Read `internal/store/store.go`, then `internal/node/storeproto.go`.

The important path:

```text
Query(q)
  decode q.Cursor into after Seq
  limit = clamp(q.Limit)
  scan ordered messages
  skip wrong topic
  skip Seq <= after
  append until limit
  return messages + nextCursor
```

Notice what does not happen:

```text
No timestamp comparison.
No sender-supplied clock.
No client-side cursor interpretation.
```

That is the correctness story.

## 10. Restart Scenario

This is the demo that proves the store system:

```text
1. A -- B -- C are connected.
2. C goes offline.
3. A sends three messages.
4. B stores ciphertexts for C's content topic.
5. C restarts.
6. C reconnects to B from peers-<port>.json.
7. C asks B for history using C's cursor for B/topic.
8. B returns the three missed messages.
9. C stores them locally and decrypts them using persisted session state.
10. C saves B's nextCursor.
11. C restarts again.
12. C asks B with the saved cursor and gets zero duplicates.
```

Expected logs:

```text
[history] asked 1 peers, got 3, new 3, total 3
[history] asked 1 peers, got 0, new 0, total 3
```

## 11. What To Say In A System Design Interview

Use this answer:

> The full nodes form a gossip network for live delivery, but offline recovery
> is request/response through a store protocol. Every relay stores ciphertext
> by content topic. On reconnect, a node queries each peer/topic with an opaque
> cursor. The cursor is server-owned, so receiver timestamps never become sync
> state. Dedup is by content hash, and ratchet state is persisted encrypted so
> fetched ciphertext remains decryptable after restart.

## 12. Next Deep Dive

Next file order:

1. `internal/store/store.go`
2. `internal/node/storeproto.go`
3. `internal/store/cursor.go`
4. `cmd/p2pchat/main.go` receive loop
5. `internal/node/sessions.go` content topic and decrypt path

Checkpoint before moving on:

> Why do we need both content-hash dedup and cursor paging?

Short answer: cursor paging avoids refetching; content-hash dedup protects
against overlap, retries, multiple store peers, and duplicate gossip paths.
