// Copyright 2025 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"encoding/json"
	"net/url"
	"strings"
)

// RedactPairs redacts selected values in an application/x-www-form-urlencoded
// string or URL query while preserving every unmatched byte. Both & and ;
// separators are preserved.
func RedactPairs(s string, m *Matcher, target Container) string {
	if m == nil || !m.Enabled() || s == "" {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))
	for s != "" {
		sep := ""
		pair := s
		if i := strings.IndexAny(s, "&;"); i >= 0 {
			pair = s[:i]
			sep = s[i : i+1]
			s = s[i+1:]
		} else {
			s = ""
		}

		keyRaw, _, hasEq := strings.Cut(pair, "=")
		key := keyRaw
		if decoded, err := url.QueryUnescape(keyRaw); err == nil {
			key = decoded
		}
		if m.ShouldRedact(target, key) {
			b.WriteString(keyRaw)
			if hasEq {
				b.WriteByte('=')
				b.WriteString(m.Replacement())
			}
		} else {
			b.WriteString(pair)
		}
		b.WriteString(sep)
	}
	return b.String()
}

// RedactCookieHeader redacts selected cookie pairs in a Cookie or Set-Cookie
// header value. For Set-Cookie attributes are preserved. If the whole header
// name is selected by the Headers container, callers should replace the full
// value before calling this helper.
func RedactCookieHeader(headerName, headerValue string, m *Matcher) string {
	if m == nil || !m.Enabled() || headerValue == "" {
		return headerValue
	}
	isSetCookie := strings.EqualFold(headerName, "Set-Cookie")
	parts := strings.Split(headerValue, ";")
	for i, part := range parts {
		// Set-Cookie's first element is name=value and later elements are
		// attributes. Cookie headers contain only name=value pairs.
		if isSetCookie && i > 0 {
			continue
		}
		name, _, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		trimmedName := strings.TrimSpace(name)
		if m.ShouldRedact(Cookie, trimmedName) || m.ShouldRedact(Headers, trimmedName) {
			parts[i] = name + "=" + m.Replacement()
		}
	}
	return strings.Join(parts, ";")
}

type span struct {
	start int
	end   int
}

func jsonReplacement(m *Matcher) string {
	b, _ := json.Marshal(m.Replacement())
	return string(b)
}

// RedactJSON redacts selected JSON object values. It is token based and
// preserves all bytes outside replaced values, including whitespace, key
// order, duplicate keys and encoding.
func RedactJSON(data string, m *Matcher) string {
	if m == nil || !m.Enabled() || !strings.ContainsAny(data, "{[") {
		return data
	}

	src := []byte(data)
	dec := json.NewDecoder(strings.NewReader(data))
	dec.UseNumber()
	var spans []span

	var walk func(path string) error
	walk = func(path string) error {
		pre := dec.InputOffset()
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				for dec.More() {
					kt, err := dec.Token()
					if err != nil {
						return err
					}
					key, _ := kt.(string)
					keyPath := joinPath(path, key)

					colon := skipJSONSpace(src, int(dec.InputOffset()))
					if colon < len(src) && src[colon] == ':' {
						colon++
					}
					valueStart := skipJSONSpace(src, colon)

					if m.ShouldRedact(JSON, keyPath) {
						var raw json.RawMessage
						if err := dec.Decode(&raw); err != nil {
							return err
						}
						valueEnd := valueStart + len(raw)
						spans = append(spans, span{valueStart, valueEnd})
						continue
					}
					if err := walk(keyPath); err != nil {
						return err
					}
				}
				_, err := dec.Token()
				return err
			case '[':
				i := 0
				for dec.More() {
					if err := walk(path + "[" + itoa(i) + "]"); err != nil {
						return err
					}
					i++
				}
				_, err := dec.Token()
				return err
			default:
				return nil
			}
		default:
			_ = pre
			return nil
		}
	}

	if err := walk(""); err != nil {
		// Invalid or truncated JSON is handled by callers' literal sweep of
		// parsed ARGS values. Returning the original here avoids inventing a
		// replacement that could shift later offsets.
		return data
	}

	// Replace from right to left so offsets remain valid without sorting.
	for i := len(spans) - 1; i >= 0; i-- {
		sp := spans[i]
		data = data[:sp.start] + jsonReplacement(m) + data[sp.end:]
	}
	return data
}

func joinPath(parent, key string) string {
	if parent == "" {
		return key
	}
	return parent + "." + key
}

func skipJSONSpace(src []byte, off int) int {
	i := off
	for i < len(src) {
		switch src[i] {
		case ' ', '\t', '\r', '\n':
			i++
		default:
			return i
		}
	}
	return i
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}
