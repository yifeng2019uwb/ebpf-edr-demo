#!/bin/bash
set -euo pipefail

REGISTRY="us-west1-docker.pkg.dev/ebpfagent/ebpf-edr"

# ── Docker + Compose ─────────────────────────────────────────────────────────
curl -fsSL https://get.docker.com | sh
apt-get install -y --no-install-recommends docker-compose-plugin
usermod -aG docker ubuntu

# ── Device certs from instance metadata ─────────────────────────────────────
METADATA="http://metadata.google.internal/computeMetadata/v1/instance/attributes"
H="Metadata-Flavor: Google"

for SENSOR in env-sensor gps-tracker device-health; do
    mkdir -p /etc/sensor/$SENSOR/tls
    curl -sf -H "$H" "$METADATA/$SENSOR-device-key"  > /etc/sensor/$SENSOR/tls/device.key
    curl -sf -H "$H" "$METADATA/$SENSOR-device-cert" > /etc/sensor/$SENSOR/tls/device.crt
    curl -sf -H "$H" "$METADATA/ca-cert"             > /etc/sensor/$SENSOR/tls/ca.crt
    chmod 600 /etc/sensor/$SENSOR/tls/device.key
done

# ── Artifact Registry auth ───────────────────────────────────────────────────
# Get OAuth token from GCE metadata server directly — no gcloud account needed.
TOKEN=$(curl -sf -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
echo "$TOKEN" | docker login -u oauth2accesstoken --password-stdin https://us-west1-docker.pkg.dev

# ── eBPF agent (systemd service) ─────────────────────────────────────────────
AGENT_IMAGE="$REGISTRY/ebpf-edr:latest"
docker pull "$AGENT_IMAGE"
CONTAINER_ID=$(docker create "$AGENT_IMAGE")
docker cp "$CONTAINER_ID:/usr/local/bin/ebpf-edr-demo" /usr/local/bin/ebpf-edr-demo
docker rm "$CONTAINER_ID"

cat > /etc/systemd/system/ebpf-edr.service << 'EOF'
[Unit]
Description=eBPF EDR Agent
After=docker.service
Requires=docker.service

[Service]
Type=simple
ExecStart=/usr/local/bin/ebpf-edr-demo --runtime=docker
Restart=on-failure
RestartSec=5
Environment=GOOGLE_CLOUD_PROJECT=ebpfagent

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ebpf-edr
systemctl start ebpf-edr

# ── Sensor containers ────────────────────────────────────────────────────────
mkdir -p /opt/sensor
cat > /opt/sensor/docker-compose.yml << EOF
networks:
  sensor-net:
    driver: bridge

services:
  telemetry-collector:
    image: ${REGISTRY}/collector:latest
    networks: [sensor-net]
    ports:
      - "8080:8080"

  env-sensor:
    image: ${REGISTRY}/sensor:latest
    environment:
      SENSOR_TYPE: env-sensor
      COLLECTOR_URL: http://telemetry-collector:8080/telemetry
    volumes:
      - /etc/sensor/env-sensor/tls:/etc/sensor/tls:ro
    networks: [sensor-net]
    depends_on: [telemetry-collector]

  gps-tracker:
    image: ${REGISTRY}/sensor:latest
    environment:
      SENSOR_TYPE: gps-tracker
      COLLECTOR_URL: http://telemetry-collector:8080/telemetry
    volumes:
      - /etc/sensor/gps-tracker/tls:/etc/sensor/tls:ro
    networks: [sensor-net]
    depends_on: [telemetry-collector]

  device-health:
    image: ${REGISTRY}/sensor:latest
    environment:
      SENSOR_TYPE: device-health
      COLLECTOR_URL: http://telemetry-collector:8080/telemetry
    volumes:
      - /etc/sensor/device-health/tls:/etc/sensor/tls:ro
    networks: [sensor-net]
    depends_on: [telemetry-collector]
EOF

docker compose -f /opt/sensor/docker-compose.yml up -d
