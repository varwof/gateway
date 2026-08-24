// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package httpgw

import (
	gw "github.com/varwof/gateway-core"
)

var (
	// HTTPRequestsTotal is the total HTTP request count.
	HTTPRequestsTotal = gw.NewMetricCounter(
		"pki_gateway_http_requests_total",
		"Total HTTP requests processed",
		"listener", "route", "method", "status",
	)

	// HTTPRequestDuration is the HTTP request latency distribution.
	HTTPRequestDuration = gw.NewMetricHistogram(
		"pki_gateway_http_request_duration_seconds",
		"HTTP request duration in seconds",
		[]string{"listener", "route"},
		0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
	)

	// WSConnectionsActive is the current active WebSocket connection count.
	WSConnectionsActive = gw.NewMetricGauge(
		"pki_gateway_http_ws_connections_active",
		"Current active WebSocket connections",
		"listener",
	)

	// WSConnectionsTotal is the total WebSocket connection count.
	WSConnectionsTotal = gw.NewMetricCounter(
		"pki_gateway_http_ws_connections_total",
		"Total WebSocket connections established",
		"listener",
	)

	// ListenerUp is the listener running status (1=running, 0=stopped).
	ListenerUp = gw.NewMetricGauge(
		"pki_gateway_http_up",
		"Listener is running (1) or not (0)",
		"listener",
	)

	// ConnectionsAccepted is the total accepted HTTP connection count.
	ConnectionsAccepted = gw.NewMetricCounter(
		"pki_gateway_http_connections_accepted_total",
		"Total accepted HTTP connections",
		"listener",
	)

	buildInfo = "pki_gateway_http_build_info{version=\"" + version + "\"} 1"
)

// DurationTracker is the latency tracker, an alias for gw.DurationTracker.
type DurationTracker = gw.DurationTracker

func init() {
	gw.RegisterCounter(HTTPRequestsTotal)
	gw.RegisterCounter(WSConnectionsTotal)
	gw.RegisterCounter(ConnectionsAccepted)
	gw.RegisterGauge(WSConnectionsActive)
	gw.RegisterGauge(ListenerUp)
	gw.RegisterHistogram(HTTPRequestDuration)
}
