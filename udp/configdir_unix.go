// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package udpgw

import "path/filepath"

func DefaultConfigDir() string {
	return "/etc/varwof/gateway-udp"
}

func DefaultConfigFile() string {
	return filepath.Join(DefaultConfigDir(), "gateway-udp.json")
}
