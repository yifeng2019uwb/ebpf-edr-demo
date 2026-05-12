package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"
)

func main() {
	http.HandleFunc("/telemetry", handleTelemetry)
	log.Println("telemetry-collector listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleTelemetry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		log.Printf("[%s] invalid JSON: %v", ts(), err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	log.Printf("[%s] %s", ts(), string(body))
	w.WriteHeader(http.StatusOK)
}

func ts() string { return time.Now().UTC().Format(time.RFC3339) }
