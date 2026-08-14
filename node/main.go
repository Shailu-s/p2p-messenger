package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/peer"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: ./p2pchat <port> [peer-address]\n       ./p2pchat light <port> <full-peer-address> (--all|<topic> [topic...])")
	}

	ctx := context.Background()
	if os.Args[1] == "light" {
		runLight(ctx, os.Args[2:])
		return
	}
	runFull(ctx, os.Args[1:])
}

func runFull(ctx context.Context, args []string) {
	if len(args) < 1 {
		log.Fatal("usage: ./p2pchat <port> [peer-address]")
	}
	port := args[0]

	priv, err := loadOrCreateKey("node-" + port + ".key")
	if err != nil {
		log.Fatal(err)
	}

	// create host on the given port
	host, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/"+port),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer host.Close()

	ps, err := pubsub.NewGossipSub(ctx, host)
	if err != nil {
		log.Fatal(err)
	}
	topic, err := ps.Join("chat-room")
	if err != nil {
		log.Fatal(err)
	}
	sub, err := topic.Subscribe()
	if err != nil {
		log.Fatal(err)
	}

	store, err := OpenStore("store-"+port+".json", 1000)
	if err != nil {
		log.Fatal(err)
	}
	cursors, err := OpenCursorBook("cursors-" + port + ".json")
	if err != nil {
		log.Fatal(err)
	}
	RegisterStoreServer(host, store)
	RegisterFilterServer(host, store)

	// Long-term X25519 identity for encryption. Separate from the libp2p
	// Ed25519 host key: that one signs, this one does Diffie-Hellman.
	ident, err := loadOrCreateIdentity("ident-" + port + ".x25519")
	if err != nil {
		log.Fatal(err)
	}
	sm, err := OpenSessionManager(ident, host.ID(), "sessions-"+port+".json.enc", "state-"+port+".key")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("encryption key: %x\n", ident.Public[:8])

	// A second topic carries key announcements. Keeping it separate from chat
	// means a node can learn keys without having to parse every chat message.
	keyTopic, err := ps.Join("chat-keys")
	if err != nil {
		log.Fatal(err)
	}
	keySub, err := keyTopic.Subscribe()
	if err != nil {
		log.Fatal(err)
	}

	// Listen for peers announcing their keys.
	go func() {
		for {
			msg, err := keySub.Next(ctx)
			if err != nil {
				return
			}
			if msg.GetFrom() == host.ID() {
				continue
			}
			var ka KeyAnnounce
			if err := json.Unmarshal(msg.Data, &ka); err != nil {
				continue
			}
			p, err := peer.Decode(ka.PeerID)
			if err != nil {
				continue
			}
			if sm.LearnKey(p, ka.PublicKey) {
				fmt.Printf("\n[crypto] learned key for %s (%x)\n", short(p), ka.PublicKey[:6])
			}
		}
	}()

	// Announce our own key, repeatedly. A single announcement at boot is lost
	// on every peer that starts later -- the same lesson as KeepConnected:
	// in a P2P network, presence is continuous, not a startup event.
	go func() {
		ka, _ := json.Marshal(KeyAnnounce{PeerID: host.ID().String(), PublicKey: ident.Public})
		for {
			keyTopic.Publish(ctx, ka)
			time.Sleep(5 * time.Second)
		}
	}()

	go func() {
		for {
			msg, err := sub.Next(ctx)
			if err != nil {
				return
			}
			isMine := msg.GetFrom() == host.ID()

			m := StoredMessage{
				ID:        MessageID(msg.Data),
				Topic:     messageStoreTopic(msg.Data),
				Timestamp: time.Now().UnixMilli(),
				Payload:   msg.Data,
			}

			// Store FIRST, unconditionally, before knowing whether we can read
			// it. This is the whole point of store-and-forward: we hold mail
			// for peers whose content is none of our business.
			stored, err := store.Put(m)
			if err != nil {
				fmt.Printf("\n[store] write failed: %v\n", err)
				continue
			}

			if isMine {
				fmt.Printf("[stored: %d]\n", store.Count())
				continue
			}
			if !stored {
				fmt.Printf("\n(duplicate ignored: %s)[stored: %d]\n", m.ID[:8], store.Count())
				continue
			}

			if pt, ok := sm.TryDecrypt(msg.Data); ok {
				fmt.Printf("\n[%s] %s", short(msg.GetFrom()), string(pt))
			} else {
				// Not ours to read. We relay and store it anyway.
				fmt.Printf("\n[opaque] %d bytes from %s, not for me",
					len(msg.Data), short(msg.GetFrom()))
			}
			fmt.Printf("[stored: %d]\n", store.Count())
		}
	}()
	fmt.Println("my ID:", host.ID())
	for _, a := range host.Addrs() {
		fmt.Printf("dial me at: %s/p2p/%s\n", a, host.ID())
	}

	// 4. remember who we meet, so a restart can rejoin without arguments
	book := newPeerBook("peers-" + port + ".json")
	book.Watch(host) // learn about peers that dial US, not just ones we dial

	// dial the peer given on the command line, if any
	if len(args) > 1 {
		info, err := peer.AddrInfoFromString(args[1])
		if err != nil {
			log.Fatal(err)
		}
		if err := host.Connect(ctx, *info); err != nil {
			log.Fatal(err)
		}
		fmt.Println("connected to", info.ID)
		book.Remember(host, info.ID)
	}

	// Keep redialing the address book forever. A one-shot attempt at boot fails
	// whenever the other node happens to start later, which is most of the time.
	book.KeepConnected(ctx, host, 5*time.Second)

	// Catch up on missed messages once peers appear. We retry because at boot
	// there is usually nobody connected yet to ask.
	go func() {
		for i := 0; i < 12; i++ {
			time.Sleep(3 * time.Second)
			topics := sm.KnownContentTopics()
			if len(host.Network().Peers()) > 0 && len(topics) > 0 {
				FetchFromAllPeers(ctx, host, store, cursors, topics, sm)
				return
			}
		}
	}()

	// 5. type to publish — this also keeps the node alive
	fmt.Println("type a message and press enter:")
	stdin := bufio.NewReader(os.Stdin)
	for {
		line, err := stdin.ReadString('\n')
		if err != nil {
			return
		}
		text := strings.TrimRight(line, "\n")
		if text == "" {
			continue
		}

		// One ciphertext per known peer. Sessions are pairwise but the network
		// is broadcast, so N recipients means N copies on the wire. That cost
		// is the trade-off for every recipient having their own ratchet.
		blobs := sm.EncryptToAll([]byte(text))
		if len(blobs) == 0 {
			fmt.Println("(nobody to encrypt to yet — waiting for key announcements)")
			continue
		}
		for _, b := range blobs {
			if err := topic.Publish(ctx, b); err != nil {
				fmt.Println("publish error:", err)
			}
		}
		fmt.Printf("(sent %d encrypted copies)\n", len(blobs))
	}
}

func runLight(ctx context.Context, args []string) {
	if len(args) < 3 {
		log.Fatal("usage: ./p2pchat light <port> <full-peer-address> (--all|<topic> [topic...])")
	}
	port := args[0]
	fullAddr := args[1]
	topicArgs := args[2:]

	req := FilterRequest{}
	if len(topicArgs) == 1 && topicArgs[0] == "--all" {
		req.All = true
	} else {
		req.Topics = topicArgs
	}

	priv, err := loadOrCreateKey("node-" + port + ".key")
	if err != nil {
		log.Fatal(err)
	}
	host, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/"+port),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer host.Close()

	info, err := peer.AddrInfoFromString(fullAddr)
	if err != nil {
		log.Fatal(err)
	}
	if err := host.Connect(ctx, *info); err != nil {
		log.Fatal(err)
	}

	updates, err := SubscribeFilter(ctx, host, info.ID, req)
	if err != nil {
		log.Fatal(err)
	}
	if req.All {
		fmt.Println("[light] subscribed to all topics from", short(info.ID))
	} else {
		fmt.Printf("[light] subscribed to %d topics from %s\n", len(req.Topics), short(info.ID))
	}
	for m := range updates {
		fmt.Printf("\n[filter] %s %d bytes\n", m.Topic, len(m.Payload))
	}
}

func messageStoreTopic(payload []byte) string {
	if topic, ok := EnvelopeContentTopic(payload); ok {
		return topic
	}
	return "chat-room"
}
