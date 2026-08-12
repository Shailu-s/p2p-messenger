package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/peer"
)

func main() {
	// take port from command line
	if len(os.Args) < 2 {
		log.Fatal("usage: go run main.[peer-address]")
	}
	port := os.Args[1]
	ctx := context.Background()

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

	store := NewStore(1000)
	RegisterStoreServer(host, store)

	go func() {
		for {
			msg, err := sub.Next(ctx)
			if err != nil {
				return
			}
			isMine := msg.GetFrom() == host.ID()

			m := StoredMessage{
				ID:        MessageID(msg.Data),
				Topic:     "chat-room",
				Timestamp: time.Now().UnixMilli(),
				Payload:   msg.Data,
			}

			if store.Put(m) {
				if !isMine {
					fmt.Printf("\n[%s] %s", msg.GetFrom().String()[:12], string(msg.Data))
				}
			} else if !isMine {
				fmt.Printf("\n(duplicate ignored: %s)", m.ID[:8])
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
	if len(os.Args) > 2 {
		info, err := peer.AddrInfoFromString(os.Args[2])
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
			if len(host.Network().Peers()) > 0 {
				FetchFromAllPeers(ctx, host, store, 0)
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
		if err := topic.Publish(ctx, []byte(line)); err != nil {
			fmt.Println("publish error:", err)
		}
	}
}
