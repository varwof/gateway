package main

import (
	"fmt"
	"runtime"
)

// Set via -ldflags -X main.version=x.y.z (CI/CD) or hardcoded default.
var version = "0.1.0"

// Set via -ldflags -X main.commit=<git rev> -X main.buildTime=<ISO8601>.
var commit = "unknown"
var buildTime = "unknown"

func versionString() string {
	return fmt.Sprintf("varwof-gateway-udp %s %s/%s %s (rev %s, %s)",
		version, runtime.GOOS, runtime.GOARCH, runtime.Version(), commit, buildTime)
}
