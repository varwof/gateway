package httpgw

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"
)

//go:embed locales/*.json
var localesFS embed.FS

// Bundle is the internationalization translation bundle, managing multi-language text loading and lookup.
type Bundle struct {
	data map[string]map[string]string
}

// NewBundle creates a translation bundle, loading from embedded locale JSON files.
func NewBundle() *Bundle {
	b := &Bundle{data: make(map[string]map[string]string)}
	for _, lang := range []string{"en", "zh"} {
		raw, err := localesFS.ReadFile("locales/" + lang + ".json")
		if err != nil {
			continue
		}
		var nested map[string]any
		if err := json.Unmarshal(raw, &nested); err != nil {
			continue
		}
		flat := make(map[string]string)
		flattenJSON("", nested, flat)
		b.data[lang] = flat
	}
	return b
}

// T translates the text for the specified language, supporting format parameters.
func (b *Bundle) T(lang, key string, args ...any) string {
	if b == nil {
		if len(args) > 0 {
			return fmt.Sprintf(key, args...)
		}
		return key
	}
	m, ok := b.data[lang]
	if !ok {
		m = b.data["en"]
	}
	text, ok := m[key]
	if !ok {
		return key
	}
	if len(args) > 0 {
		return fmt.Sprintf(text, args...)
	}
	return text
}

// Ef translates the text and wraps it as an error.
func (b *Bundle) Ef(lang, key string, args ...any) error {
	return fmt.Errorf("%s", b.T(lang, key, args...))
}

func flattenJSON(prefix string, v any, out map[string]string) {
	switch m := v.(type) {
	case map[string]any:
		for k, child := range m {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			flattenJSON(p, child, out)
		}
	case string:
		out[prefix] = m
	}
}

// DetectLang detects the language from CLI parameters, configuration, and environment variables in order.
func DetectLang(cliLang, cfgLocale, envLang string) string {
	for _, s := range []string{cliLang, cfgLocale, envLang} {
		switch {
		case s == "zh", strings.HasPrefix(s, "zh_"):
			return "zh"
		case s == "en", strings.HasPrefix(s, "en_"):
			return "en"
		}
	}
	return "en"
}
