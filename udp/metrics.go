// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package udpgw

import (
	gw "github.com/varwof/gateway-core"
)

var (
	// PacketsTotal total UDP packet count.
	PacketsTotal = gw.NewMetricCounter(
		"pki_gateway_udp_packets_total",
		"Total UDP packets processed",
	)

	// PacketDroppedTotal dropped UDP packet count.
	PacketDroppedTotal = gw.NewMetricCounter(
		"pki_gateway_udp_packets_dropped_total",
		"Total UDP packets dropped",
	)

	// BytesToTargetTotal bytes forwarded to backend.
	BytesToTargetTotal = gw.NewMetricCounter(
		"pki_gateway_udp_bytes_to_target_total",
		"Bytes forwarded from client to target, by listener and cert serial",
		"listener", "cert_serial",
	)

	// BytesToClientTotal bytes returned to client.
	BytesToClientTotal = gw.NewMetricCounter(
		"pki_gateway_udp_bytes_to_client_total",
		"Bytes returned from target to client, by listener and cert serial",
		"listener", "cert_serial",
	)

	// ConnectionsAccepted total accepted DTLS/QUIC connections.
	ConnectionsAccepted = gw.NewMetricCounter(
		"pki_gateway_udp_connections_accepted_total",
		"Total accepted connections (DTLS/QUIC)",
		"listener",
	)

	// ActiveClients currently active unique source IP count.
	ActiveClients = gw.NewMetricGauge(
		"pki_gateway_udp_active_clients",
		"Current active unique source IPs",
	)

	// ListenerUp listener running status (1=running, 0=stopped).
	ListenerUp = gw.NewMetricGauge(
		"pki_gateway_udp_up",
		"Listener is running (1) or not (0)",
	)

	// ProxyLatency UDP proxy latency distribution.
	ProxyLatency = gw.NewMetricHistogram(
		"pki_gateway_udp_proxy_latency_seconds",
		"UDP proxy round-trip latency in seconds (packet forward → response)",
		[]string{"listener", "mode"},
		0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5,
	)

	buildInfo = "pki_gateway_udp_build_info{version=\"" + version + "\"} 1"
)

// DurationTracker is the latency tracker, alias for gw.DurationTracker.
type DurationTracker = gw.DurationTracker

func init() {
	gw.RegisterCounter(PacketsTotal)
	gw.RegisterCounter(PacketDroppedTotal)
	gw.RegisterCounter(BytesToTargetTotal)
	gw.RegisterCounter(BytesToClientTotal)
	gw.RegisterCounter(ConnectionsAccepted)
	gw.RegisterGauge(ActiveClients)
	gw.RegisterGauge(ListenerUp)
	gw.RegisterHistogram(ProxyLatency)
}
