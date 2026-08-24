// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package tcpgw

import (
	gw "github.com/varwof/gateway-core"
)

var (
	// ConnectionsActive is the current active connection count.
	ConnectionsActive = gw.NewMetricGauge(
		"pki_gateway_mapping_connections_active",
		"Current active connections per mapping",
		"mapping",
	)

	// ConnectionsTotal is the total connection count.
	ConnectionsTotal = gw.NewMetricCounter(
		"pki_gateway_mapping_connections_total",
		"Total connections per mapping",
		"mapping",
	)

	// ConnectionDuration is the TCP connection latency distribution.
	ConnectionDuration = gw.NewMetricHistogram(
		"pki_gateway_mapping_connection_duration_seconds",
		"TCP connection duration in seconds",
		[]string{"mapping"},
		0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30, 60, 300, 3600,
	)

	// MappingUp is the mapping running status (1=running, 0=stopped).
	MappingUp = gw.NewMetricGauge(
		"pki_gateway_mapping_up",
		"Mapping is running (1) or not (0)",
		"mapping",
	)

	// ConnectionsAccepted is the total accepted TCP connection count.
	ConnectionsAccepted = gw.NewMetricCounter(
		"pki_gateway_mapping_connections_accepted_total",
		"Total accepted TCP connections",
		"mapping",
	)

	// MeshRequestsReceived is the total mesh forwarding request count.
	MeshRequestsReceived = gw.NewMetricCounter(
		"pki_gateway_mesh_requests_received_total",
		"Total mesh forwarding requests received from peers",
	)

	// MeshConnectionsActive is the current active outbound mesh connection count.
	MeshConnectionsActive = gw.NewMetricGauge(
		"pki_gateway_mesh_connections_active",
		"Current active outbound mesh peer connections",
		"peer",
	)

	// MeshDialErrors is the mesh dial failure count.
	MeshDialErrors = gw.NewMetricCounter(
		"pki_gateway_mesh_dial_errors_total",
		"Failed outbound mesh peer dial attempts",
		"peer",
	)

	// MeshTargetRejected is the inbound mesh forwarding request count rejected by target allowlist.
	MeshTargetRejected = gw.NewMetricCounter(
		"pki_gateway_mesh_target_rejected_total",
		"Inbound mesh forwarding requests rejected by target allowlist",
	)

	buildInfo = "pki_gateway_build_info{version=\"" + version + "\"} 1"
)

// DurationTracker is the latency tracker, alias of gw.DurationTracker.
type DurationTracker = gw.DurationTracker

func init() {
	gw.RegisterCounter(ConnectionsTotal)
	gw.RegisterCounter(ConnectionsAccepted)
	gw.RegisterCounter(MeshRequestsReceived)
	gw.RegisterCounter(MeshDialErrors)
	gw.RegisterCounter(MeshTargetRejected)
	gw.RegisterGauge(ConnectionsActive)
	gw.RegisterGauge(MappingUp)
	gw.RegisterGauge(MeshConnectionsActive)
	gw.RegisterHistogram(ConnectionDuration)
}
