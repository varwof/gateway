package httpgw

import (
	"crypto/x509"

	gw "github.com/varwof/gateway-core"
	"github.com/varwof/register/ruleexec"
)

// RegisterRulePlugins loads signed rules from a published rule
// directory (as produced by the register rule publisher:
// outDir/<scheme>/default.json + .p7s) into the gateway's capability
// plugin registry, one phase-two plugin per scheme. Signature
// verification is mandatory; any failure aborts registration
// (fail-closed). handler executes rule flow operations (nil when
// rules carry no flow).
func RegisterRulePlugins(reg *gw.PluginRegistry, dir string, trustRoots []*x509.Certificate, handler ruleexec.OpHandler) ([]string, error) {
	return ruleexec.RegisterRulePluginsFromDir(reg, dir, trustRoots, handler)
}
