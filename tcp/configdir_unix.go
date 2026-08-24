// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package tcpgw

import "path/filepath"

func DefaultConfigDir() string {
	return "/etc/varwof/gateway-tcp"
}

func DefaultConfigFile() string {
	return filepath.Join(DefaultConfigDir(), "gateway-tcp.json")
}
