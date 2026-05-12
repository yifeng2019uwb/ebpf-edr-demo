package main

import (
	"bytes"
	"encoding/json"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"
)

const certDir = "/etc/sensor/tls"

func main() {
	sensorType := os.Getenv("SENSOR_TYPE")
	if sensorType == "" {
		log.Fatal("SENSOR_TYPE must be set")
	}
	collectorURL := os.Getenv("COLLECTOR_URL")
	if collectorURL == "" {
		collectorURL = "http://telemetry-collector:8080/telemetry"
	}

	// Open cert files — eBPF agent observes these file opens as expected baseline behavior.
	for _, f := range []string{certDir + "/device.key", certDir + "/device.crt", certDir + "/ca.crt"} {
		if _, err := os.ReadFile(f); err != nil {
			log.Fatalf("read %s: %v", f, err)
		}
	}
	log.Printf("sensor=%s certs loaded, posting to %s", sensorType, collectorURL)

	client := &http.Client{Timeout: 5 * time.Second}
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for {
		payload, interval := buildPayload(sensorType, rng)
		post(client, collectorURL, sensorType, payload)
		time.Sleep(interval)
	}
}

func buildPayload(sensorType string, rng *rand.Rand) (map[string]any, time.Duration) {
	switch sensorType {
	case "env-sensor":
		return map[string]any{
			"temp_c":       20.0 + rng.Float64()*15.0,
			"humidity_pct": 40.0 + rng.Float64()*40.0,
			"pressure_hpa": 980.0 + rng.Float64()*60.0,
		}, 30 * time.Second
	case "gps-tracker":
		return map[string]any{
			"lat":         37.0 + rng.Float64()*5.0,
			"lon":         -122.0 + rng.Float64()*5.0,
			"speed_kmh":   rng.Float64() * 120.0,
			"heading_deg": rng.Float64() * 360.0,
			"altitude_m":  rng.Float64() * 500.0,
		}, 2 * time.Second
	case "device-health":
		return map[string]any{
			"battery_pct":  float64(20 + rng.Intn(80)),
			"rssi_dbm":     float64(-90 + rng.Intn(60)),
			"firmware_ver": "1.4.2",
		}, 5 * time.Minute
	default:
		log.Fatalf("unknown SENSOR_TYPE: %s", sensorType)
		return nil, 0
	}
}

func post(client *http.Client, url, sensorType string, data map[string]any) {
	body, _ := json.Marshal(map[string]any{
		"sensor_type": sensorType,
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
		"data":        data,
	})
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("post error: %v", err)
		return
	}
	resp.Body.Close()
	log.Printf("sent sensor_type=%s", sensorType)
}
