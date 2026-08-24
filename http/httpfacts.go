// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package httpgw

import (
	"net/http"

	gw "github.com/varwof/gateway-core"
)

// httpFactsFor extracts per-request HTTP facts for capability plugins
// (client identity comes from the verified client certificate via the
// admission pipeline; the rule conditions additionally see method/path/
// query/headers).
func httpFactsFor(r *http.Request) *gw.HTTPFacts {
	headers := make(map[string]string, len(r.Header))
	for k, vs := range r.Header {
		if len(vs) > 0 {
			headers[k] = vs[0]
		}
	}
	return &gw.HTTPFacts{
		Method:  r.Method,
		Path:    r.URL.Path,
		Query:   r.URL.Query(),
		Headers: headers,
	}
}
