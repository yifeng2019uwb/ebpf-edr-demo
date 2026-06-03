package main

import (
	"context"
	"log"
	"net/http"
	"sync"

	"cloud.google.com/go/pubsub/v2"
	"github.com/gorilla/websocket"
)

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

const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>eBPF EDR — Live Alerts</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Courier New', monospace; background: #111; color: #ddd; padding: 24px; }
  h1 { color: #fff; font-size: 20px; margin-bottom: 6px; }
  .subtitle { color: #666; font-size: 13px; margin-bottom: 20px; }
  .bar { display: flex; align-items: center; gap: 20px; margin-bottom: 16px; font-size: 13px; }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: #555; display: inline-block; margin-right: 6px; }
  .dot.ok { background: #22cc55; }
  .dot.err { background: #cc2222; }
  .count { color: #888; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; padding: 8px 10px; background: #222; color: #888; border-bottom: 2px solid #333;
       font-weight: normal; letter-spacing: 0.05em; text-transform: uppercase; font-size: 11px; }
  td { padding: 7px 10px; border-bottom: 1px solid #222; vertical-align: top; white-space: nowrap; }
  td.detail { white-space: normal; }
  .badge { display: inline-block; padding: 1px 7px; border-radius: 3px; font-size: 11px; font-weight: bold; letter-spacing: 0.05em; }
  .badge.CRITICAL      { background: #FF2C2C; color: #fff; }
  .badge.HIGH          { background: #FF7400; color: #fff; }
  .badge.MEDIUM        { background: #FFC100; color: #111; }
  .badge.kill_process  { background: #8B0000; color: #fff; }
  .badge.block_ip      { background: #7B00D4; color: #fff; }
  .rule   { color: #aaa; }
  .detail { color: #888; font-size: 12px; }
  .empty  { text-align: center; color: #444; padding: 40px; }
</style>
</head>
<body>
<h1>eBPF EDR &mdash; Live Alerts</h1>
<p class="subtitle">Kernel-level threat detection &middot; Docker VM + GKE</p>
<div class="bar">
  <span><span class="dot" id="dot"></span><span id="status">Connecting...</span></span>
  <span class="count">Alerts received: <strong id="count">0</strong></span>
</div>
<table>
  <thead>
    <tr>
      <th>Time (UTC)</th>
      <th>Severity</th>
      <th>Rule</th>
      <th>Service</th>
      <th>Pod</th>
      <th>Namespace</th>
      <th>Runtime</th>
      <th>Response</th>
      <th>Details</th>
    </tr>
  </thead>
  <tbody id="tbody">
    <tr><td colspan="9" class="empty">Waiting for alerts...</td></tr>
  </tbody>
</table>
<script>
  const tbody   = document.getElementById('tbody');
  const dot     = document.getElementById('dot');
  const status  = document.getElementById('status');
  const countEl = document.getElementById('count');
  let count = 0;

  function buildRow(a) {
    const details = a.filename
      ? a.filename
      : a.dst_ip ? a.dst_ip + ':' + a.dst_port
      : a.comm   ? a.comm
      : '—';
    const ts = a.ts ? a.ts.replace('T', ' ').replace('Z', '') : '—';
    const action = a.response_action && a.response_action !== 'none' ? a.response_action : '';
    const actionCell = action
      ? '<span class="badge ' + esc(action) + '">' + esc(action) + '</span>'
      : '—';
    const row = document.createElement('tr');
    row.innerHTML =
      '<td>' + esc(ts) + '</td>' +
      '<td><span class="badge ' + esc(a.level) + '">' + esc(a.level) + '</span></td>' +
      '<td class="rule">' + esc(a.rule) + '</td>' +
      '<td>' + esc(a.service   || '—') + '</td>' +
      '<td>' + esc(a.pod       || '—') + '</td>' +
      '<td>' + esc(a.namespace || '—') + '</td>' +
      '<td>' + esc(a.runtime   || '—') + '</td>' +
      '<td>' + actionCell + '</td>' +
      '<td class="detail">' + esc(details) + '</td>';
    return row;
  }

  function connect() {
    const ws = new WebSocket('ws://' + location.host + '/ws');

    ws.onopen = () => {
      dot.className = 'dot ok';
      status.textContent = 'Connected';
    };

    ws.onclose = () => {
      dot.className = 'dot err';
      status.textContent = 'Disconnected — reconnecting...';
      setTimeout(connect, 2000);
    };

    ws.onmessage = (evt) => {
      const a = JSON.parse(evt.data);
      if (count === 0) tbody.innerHTML = '';
      count++;
      countEl.textContent = count;
      tbody.insertBefore(buildRow(a), tbody.firstChild);
    };
  }

  function esc(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  connect();
</script>
</body>
</html>`
