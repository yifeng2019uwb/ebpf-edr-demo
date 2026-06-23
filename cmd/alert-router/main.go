package main

import (
	"context"
	_ "embed"
	"log"
	"net/http"
	"sync"

	"cloud.google.com/go/pubsub/v2"
	"github.com/gorilla/websocket"
)

//go:embed index.html
var indexHTML string

const (
	projectID  = "ebpfagent"
	subID      = "edr-alerts-router-sub"
	listenAddr = ":8888"
)

const historySize = 100

// hub manages active WebSocket connections and a ring buffer of recent alerts.
type hub struct {
	mu      sync.Mutex
	clients map[*websocket.Conn]struct{}
	history [][]byte
}

func newHub() *hub {
	return &hub{clients: make(map[*websocket.Conn]struct{})}
}

// sendHistory replays stored alerts to a newly connected client.
func (h *hub) sendHistory(conn *websocket.Conn) {
	h.mu.Lock()
	msgs := make([][]byte, len(h.history))
	copy(msgs, h.history)
	h.mu.Unlock()
	for _, msg := range msgs {
		conn.WriteMessage(websocket.TextMessage, msg) //nolint:errcheck
	}
}

func (h *hub) add(conn *websocket.Conn) {
	h.mu.Lock()
	h.clients[conn] = struct{}{}
	h.mu.Unlock()
}

func (h *hub) remove(conn *websocket.Conn) {
	h.mu.Lock()
	delete(h.clients, conn)
	h.mu.Unlock()
	conn.Close()
}

func (h *hub) broadcast(data []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.history) >= historySize {
		h.history = h.history[1:]
	}
	h.history = append(h.history, data)
	for conn := range h.clients {
		if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
			log.Printf("broadcast write error: %v", err)
		}
	}
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func main() {
	ctx := context.Background()

	psClient, err := pubsub.NewClient(ctx, projectID)
	if err != nil {
		log.Fatalf("pubsub client init: %v", err)
	}

	h := newHub()

	// Pull from Pub/Sub and broadcast to all connected browsers.
	go func() {
		sub := psClient.Subscriber(subID)
		if err := sub.Receive(ctx, func(_ context.Context, msg *pubsub.Message) {
			h.broadcast(msg.Data)
			msg.Ack()
		}); err != nil && ctx.Err() == nil {
			log.Fatalf("pubsub receive: %v", err)
		}
	}()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(indexHTML))
	})

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("ws upgrade: %v", err)
			return
		}
		h.sendHistory(conn)
		h.add(conn)
		defer h.remove(conn)
		// Read loop — keeps connection alive; client sends no messages.
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				break
			}
		}
	})

	log.Printf("Alert Router listening on %s — open http://localhost%s", listenAddr, listenAddr)
	if err := http.ListenAndServe(listenAddr, nil); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

