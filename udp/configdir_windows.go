//go:build windows

package udpgw

import (
	"os"
	"path/filepath"
)

func DefaultConfigDir() string {
	progData := os.Getenv("ProgramData")
	if progData == "" {
		progData = `C:\ProgramData`
	}
	return filepath.Join(progData, "varwof", "gateway-udp")
}

func DefaultConfigFile() string {
	return filepath.Join(DefaultConfigDir(), "gateway-udp.json")
}
