//go:build !windows

package httpgw

import "path/filepath"

func DefaultConfigDir() string {
	return "/etc/varwof/gateway-http"
}

func DefaultConfigFile() string {
	return filepath.Join(DefaultConfigDir(), "gateway-http.json")
}
