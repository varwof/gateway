// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package httpgw

import (
	"os"
	"path/filepath"
)

func DefaultConfigDir() string {
	progData := os.Getenv("ProgramData")
	if progData == "" {
		progData = `C:\ProgramData`
	}
	return filepath.Join(progData, "varwof", "gateway-http")
}

func DefaultConfigFile() string {
	return filepath.Join(DefaultConfigDir(), "gateway-http.json")
}
