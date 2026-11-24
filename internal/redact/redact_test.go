// Copyright 2025 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"strings"
	"testing"
)

func TestMatcherShouldRedact(t *testing.T) {
	policy := &Policy{
		Fields: []FieldRule{
			{Name: "password", Containers: []Container{Form}},
			{Name: "token", Containers: []Container{Query, JSON}},
			{Name: "*secret*", Containers: []Container{Headers}},
		},
		Retain: []string{"X-TLS-Fingerprint"},
	}
	if err := policy.Compile(); err != nil {
		t.Fatal(err)
	}
	m := policy.Matcher()

	tests := []struct {
		name      string
		container Container
		key       string
		want      bool
	}{
		{"case insensitive form field", Form, "PASSWORD", true},
		{"nested bracket leaf", Form, "users[0][password]", true},
		{"nested dot leaf", JSON, "json.users.0.token", true},
		{"query token", Query, "access_token", false},
		{"wildcard header", Headers, "X-My-Secret-Key", true},
		{"retained association field", Headers, "X-TLS-Fingerprint", false},
		{"different container", Query, "password", false},
		{"unrelated field", Form, "username", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := m.ShouldRedact(tt.container, tt.key); got != tt.want {
				t.Fatalf("ShouldRedact(%s,%q)=%v want %v", tt.container, tt.key, got, tt.want)
			}
		})
	}
}

func TestRedactPairs(t *testing.T) {
	policy := &Policy{Fields: []FieldRule{{Name: "token", Containers: []Container{Params}}}}
	m := policy.Matcher()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "duplicate and nested keys preserve unmatched bytes",
			in:   "token=secret1&token=secret2&user=alice&items%5B0%5D%5Btoken%5D=nested",
			want: "token=[REDACTED]&token=[REDACTED]&user=alice&items%5B0%5D%5Btoken%5D=[REDACTED]",
		},
		{
			name: "semicolon separator",
			in:   "token=secret;user=alice",
			want: "token=[REDACTED];user=alice",
		},
		{
			name: "unmatched input unchanged",
			in:   "user=alice&count=2",
			want: "user=alice&count=2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RedactPairs(tt.in, m, Form); got != tt.want {
				t.Fatalf("RedactPairs()=%q want %q", got, tt.want)
			}
		})
	}
}

func TestRedactStructuredBodies(t *testing.T) {
	policy := &Policy{Fields: []FieldRule{
		{Name: "password", Containers: []Container{JSON, XML}},
		{Name: "token", Containers: []Container{JSON, XML}},
	}}
	m := policy.Matcher()

	t.Run("json nested arrays and duplicate keys", func(t *testing.T) {
		in := `{"password":"p1","user":{"name":"alice"},"items":[{"token":"t1"},{"token":"t2"}],"d":{"token":"a","token":"b"}}`
		got := RedactJSON(in, m)
		want := `{"password":"[REDACTED]","user":{"name":"alice"},"items":[{"token":"[REDACTED]"},{"token":"[REDACTED]"}],"d":{"token":"[REDACTED]","token":"[REDACTED]"}}`
		if got != want {
			t.Fatalf("JSON redaction mismatch\n got: %s\nwant: %s", got, want)
		}
	})

	t.Run("xml elements", func(t *testing.T) {
		in := `<root password="attrSecret"><password>secret</password><user>alice</user><nested><token>t</token></nested></root>`
		got := RedactXML(in, m)
		if got == in || strings.Contains(got, "secret") || strings.Contains(got, "attrSecret") || strings.Contains(got, ">t<") {
			t.Fatalf("XML redaction leaked: %s", got)
		}
		if !strings.Contains(got, "<user>alice</user>") {
			t.Fatalf("XML unmatched data changed: %s", got)
		}
	})
}

func TestRedactMultipart(t *testing.T) {
	policy := &Policy{Fields: []FieldRule{{Name: "password", Containers: []Container{Form}}}}
	m := policy.Matcher()
	in := "--B\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nmultipartSecret\r\n--B\r\n" +
		"Content-Disposition: form-data; name=\"user\"\r\n\r\nalice\r\n--B--\r\n"
	got := RedactMultipart(in, "B", m)
	if strings.Contains(got, "multipartSecret") {
		t.Fatalf("multipart secret leaked: %s", got)
	}
	if !strings.Contains(got, "name=\"user\"") || !strings.Contains(got, "alice") {
		t.Fatalf("unmatched multipart part changed: %s", got)
	}
}

func TestParsePolicyJSONRejectsUnknownContainer(t *testing.T) {
	_, err := ParsePolicyJSON([]byte(`{"ruleset_id":"rs","version":"1","fields":[{"name":"x","containers":["bogus"]}]}`))
	if err == nil {
		t.Fatal("expected invalid container error")
	}
}
