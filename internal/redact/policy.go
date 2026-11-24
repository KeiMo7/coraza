// Copyright 2025 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// Package redact implements versioned audit-record redaction policies.
package redact

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Replacement is the irreversible value substituted for sensitive data.
const Replacement = "[REDACTED]"

// Container identifies a place in an audit record where a field can occur.
type Container string

// Supported containers. Headers covers request and response headers. Params is
// an alias for query and form parameters; Body is an alias for every structured
// or encoded body container.
const (
	Headers Container = "headers"
	Query   Container = "query"
	Form    Container = "form"
	JSON    Container = "json"
	XML     Container = "xml"
	Cookie  Container = "cookie"
	Params  Container = "params"
	Body    Container = "body"
)

// FieldRule selects field names and, optionally, the containers in which the
// rule applies. An empty Containers list applies the name to every container.
type FieldRule struct {
	Name       string      `json:"name"`
	Containers []Container `json:"containers,omitempty"`

	pattern *regexp.Regexp `json:"-"`
}

// UnmarshalJSON accepts either a bare field name ("password") or a rule object.
func (r *FieldRule) UnmarshalJSON(data []byte) error {
	var name string
	if err := json.Unmarshal(data, &name); err == nil {
		r.Name = name
		r.Containers = nil
		return nil
	}

	type alias FieldRule
	var rule alias
	if err := json.Unmarshal(data, &rule); err != nil {
		return err
	}
	*r = FieldRule(rule)
	return nil
}

// Policy is the redaction manifest released together with a ruleset.
type Policy struct {
	RulesetID   string      `json:"ruleset_id"`
	Version     string      `json:"version"`
	Replacement string      `json:"replacement,omitempty"`
	Fields      []FieldRule `json:"fields"`
	Retain      []string    `json:"retain,omitempty"`

	retain []*regexp.Regexp
}

// ParsePolicyJSON parses a policy and rejects unknown JSON fields. Unknown
// containers and invalid name patterns are reported with their manifest path.
func ParsePolicyJSON(data []byte) (*Policy, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("invalid redaction policy: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("invalid redaction policy: multiple JSON documents")
	}
	if err := p.Compile(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Compile validates and compiles name patterns. It is called automatically by
// ParsePolicyJSON and is safe to call on a programmatically constructed policy.
func (p *Policy) Compile() error {
	if p == nil {
		return fmt.Errorf("redaction policy is required")
	}
	if p.Replacement == "" {
		p.Replacement = Replacement
	}
	for i := range p.Fields {
		f := &p.Fields[i]
		if strings.TrimSpace(f.Name) == "" {
			return fmt.Errorf("redaction.fields[%d].name: field name is required", i)
		}
		pat, err := compilePattern(f.Name)
		if err != nil {
			return fmt.Errorf("redaction.fields[%d].name %q: %w", i, f.Name, err)
		}
		f.pattern = pat
		for j, c := range f.Containers {
			if _, err := normalizeContainer(c); err != nil {
				return fmt.Errorf("redaction.fields[%d].containers[%d]: %w", i, j, err)
			}
		}
	}
	p.retain = make([]*regexp.Regexp, 0, len(p.Retain))
	for i, name := range p.Retain {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("redaction.retain[%d]: field name is required", i)
		}
		pat, err := compilePattern(name)
		if err != nil {
			return fmt.Errorf("redaction.retain[%d] %q: %w", i, name, err)
		}
		p.retain = append(p.retain, pat)
	}
	return nil
}

// Matcher returns a value that can answer redaction questions for p.
func (p *Policy) Matcher() *Matcher {
	if p == nil {
		return &Matcher{replacement: Replacement}
	}
	if len(p.Fields) > 0 && p.Fields[0].pattern == nil {
		_ = p.Compile()
	}
	return &Matcher{policy: p, replacement: p.Replacement}
}

// Matcher applies a compiled Policy.
type Matcher struct {
	policy      *Policy
	replacement string
}

// Replacement returns the replacement token.
func (m *Matcher) Replacement() string {
	if m == nil || m.replacement == "" {
		return Replacement
	}
	return m.replacement
}

// Enabled reports whether any field can be redacted.
func (m *Matcher) Enabled() bool {
	return m != nil && m.policy != nil && len(m.policy.Fields) > 0
}

// ShouldRedact reports whether key in container is selected by the policy and
// not overridden by the retain list.
func (m *Matcher) ShouldRedact(container Container, key string) bool {
	if !m.Enabled() || key == "" {
		return false
	}
	key = strings.ToLower(key)
	leaf := LeafName(key)

	for _, re := range m.policy.retain {
		if re.MatchString(key) || re.MatchString(leaf) {
			return false
		}
	}

	targets := containerSet(container)
	for _, f := range m.policy.Fields {
		if !containerAllowed(f.Containers, targets) {
			continue
		}
		if f.pattern == nil {
			pat, err := compilePattern(f.Name)
			if err != nil {
				continue
			}
			f.pattern = pat
		}
		if f.pattern.MatchString(key) || f.pattern.MatchString(leaf) {
			return true
		}
	}
	return false
}

func containerAllowed(rules []Container, targets map[Container]struct{}) bool {
	if len(rules) == 0 {
		return true
	}
	for _, raw := range rules {
		c, err := normalizeContainer(raw)
		if err != nil {
			continue
		}
		if _, ok := targets[c]; ok {
			return true
		}
		// Broad aliases are handled by expanding the target set too.
		if _, ok := targets[raw]; ok {
			return true
		}
	}
	return false
}

func containerSet(c Container) map[Container]struct{} {
	c, _ = normalizeContainer(c)
	set := map[Container]struct{}{c: {}}
	switch c {
	case Query:
		set[Params] = struct{}{}
	case Form:
		set[Params] = struct{}{}
		set[Body] = struct{}{}
	case JSON, XML:
		set[Body] = struct{}{}
	case Cookie:
		set[Headers] = struct{}{}
	}
	return set
}

func normalizeContainer(c Container) (Container, error) {
	switch Container(strings.ToLower(strings.TrimSpace(string(c)))) {
	case Headers, "header", "request_headers", "response_headers", "request_header", "response_header":
		return Headers, nil
	case Query, "queries", "querystring", "query_string", "url_query":
		return Query, nil
	case Form, "forms", "post", "urlencoded", "url_encoded", "multipart", "multipart_form":
		return Form, nil
	case JSON:
		return JSON, nil
	case XML:
		return XML, nil
	case Cookie, "cookies":
		return Cookie, nil
	case Params, "param", "parameters", "args", "arguments":
		return Params, nil
	case Body, "bodies", "structured", "structured_body":
		return Body, nil
	default:
		return "", fmt.Errorf("unknown container %q", c)
	}
}

// LeafName returns the final field name from dot, bracket and Coraza-flattened
// paths. Array indexes are returned when they are the final component.
func LeafName(key string) string {
	key = strings.ToLower(key)
	if i := strings.LastIndex(key, "."); i >= 0 {
		key = key[i+1:]
	}
	if strings.HasSuffix(key, "]") {
		if i := strings.LastIndex(key, "["); i >= 0 {
			key = key[i+1 : len(key)-1]
		}
	}
	return strings.Trim(key, `"'`)
}

func compilePattern(pattern string) (*regexp.Regexp, error) {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if pattern == "" {
		return nil, fmt.Errorf("pattern is empty")
	}
	var b strings.Builder
	b.WriteString("^")
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil, fmt.Errorf("invalid field pattern: %w", err)
	}
	return re, nil
}

// ScrubLiteral replaces every occurrence of secret and its common URL/JSON
// encodings in s. It is used as a final sweep for macro-expanded hit data and
// error text, where a value can escape its original field representation.
func ScrubLiteral(s, secret, replacement string) string {
	if secret == "" || len(secret) < 2 {
		// A one-byte secret is too likely to collide with unrelated bytes. It is
		// still removed by the structural field redactors before this sweep.
		return s
	}
	variants := map[string]struct{}{secret: {}}
	if enc := jsonStringEscape(secret); enc != secret {
		variants[enc] = struct{}{}
	}
	if enc := urlQueryEscape(secret); enc != secret {
		variants[enc] = struct{}{}
	}
	for v := range variants {
		if len(v) >= 2 {
			s = strings.ReplaceAll(s, v, replacement)
		}
	}
	return s
}

func jsonStringEscape(s string) string {
	b, err := json.Marshal(s)
	if err != nil || len(b) < 2 {
		return s
	}
	return string(b[1 : len(b)-1])
}

func urlQueryEscape(s string) string {
	return url.QueryEscape(s)
}
