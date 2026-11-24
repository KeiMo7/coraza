// Copyright 2025 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/auditlog"
	"github.com/corazawaf/coraza/v3/types"
)

type captureReleaseWriter struct {
	mu   sync.Mutex
	logs []plugintypes.AuditLog
}

func (w *captureReleaseWriter) Init(plugintypes.AuditLogConfig) error { return nil }
func (w *captureReleaseWriter) Close() error                          { return nil }
func (w *captureReleaseWriter) Write(al plugintypes.AuditLog) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.logs = append(w.logs, al)
	return nil
}
func (w *captureReleaseWriter) snapshot() []plugintypes.AuditLog {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]plugintypes.AuditLog, len(w.logs))
	copy(out, w.logs)
	return out
}

type failingReleaseWriter struct{ err error }

func (f *failingReleaseWriter) Init(plugintypes.AuditLogConfig) error { return nil }
func (f *failingReleaseWriter) Close() error                          { return nil }
func (f *failingReleaseWriter) Write(plugintypes.AuditLog) error      { return f.err }

func newReleaseTestWAF(t *testing.T, writer plugintypes.AuditLogWriter) WAF {
	t.Helper()
	cfg := NewWAFConfig().WithRequestBodyAccess().(*wafConfig)
	cfg.auditLog = &auditLogConfig{
		parts: types.AuditLogParts{
			types.AuditLogPartHeader,
			types.AuditLogPartRequestHeaders,
			types.AuditLogPartRequestBody,
			types.AuditLogPartResponseHeaders,
			types.AuditLogPartAuditLogTrailer,
			types.AuditLogPartRulesMatched,
			types.AuditLogPartEndMarker,
		},
		writer: writer,
	}
	waf, err := NewWAF(cfg)
	if err != nil {
		t.Fatalf("NewWAF: %v", err)
	}
	t.Cleanup(func() { _ = waf.(wafWrapper).Close() })
	return waf
}

func releaseRules(ruleID int) string {
	return fmt.Sprintf(`
SecRuleEngine On
SecRule REQUEST_HEADERS:X-Secret "@rx (?i)secret" "id:%d,phase:1,log,pass,msg:'header leak %%{MATCHED_VAR}',logdata:'data leak %%{MATCHED_VAR}'"
`, ruleID)
}

func testRedactionPolicy() *RedactionPolicy {
	return &RedactionPolicy{
		Fields: []RedactionField{
			{Name: "token", Containers: []RedactionContainer{RedactionQuery, RedactionForm, RedactionJSON}},
			{Name: "X-Secret", Containers: []RedactionContainer{RedactionHeaders}},
			{Name: "X-Token", Containers: []RedactionContainer{RedactionHeaders}},
			{Name: "session", Containers: []RedactionContainer{RedactionCookie}},
			{Name: "password", Containers: []RedactionContainer{RedactionForm}},
		},
	}
}

func sendVersionedRequest(t *testing.T, tx types.Transaction) {
	t.Helper()
	tx.ProcessConnection("192.0.2.10", 41000, "203.0.113.7", 443)
	tx.ProcessURI("/app?token=querySecret123&keep=same", "POST", "HTTP/1.1")
	tx.AddRequestHeader("Host", "app.example")
	tx.AddRequestHeader("X-Secret", "headerSecret456")
	tx.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded")
	tx.AddRequestHeader("Cookie", "session=cookieSecret789; tracking=retainme")
	if it := tx.ProcessRequestHeaders(); it != nil {
		t.Fatalf("unexpected interruption: %+v", it)
	}
	body := "password=formSecret999&user=alice&token=dupSecret1&token=dupSecret2&items%5B0%5D%5Btoken%5D=nestedSecretA&items%5B1%5D%5Btoken%5D=nestedSecretB"
	if it, _, err := tx.WriteRequestBody([]byte(body)); err != nil {
		t.Fatalf("WriteRequestBody: %v", err)
	} else if it != nil {
		t.Fatalf("unexpected body interruption: %+v", it)
	}
	if it, err := tx.ProcessRequestBody(); err != nil {
		t.Fatalf("ProcessRequestBody: %v", err)
	} else if it != nil {
		t.Fatalf("unexpected request body interruption: %+v", it)
	}
	tx.AddResponseHeader("X-Token", "responseSecret000")
	if it := tx.ProcessResponseHeaders(200, "HTTP/1.1"); it != nil {
		t.Fatalf("unexpected response interruption: %+v", it)
	}
	tx.ProcessLogging()
	if err := tx.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func publishV(t *testing.T, waf WAF, id int, version string, policy *RedactionPolicy) ReleaseInfo {
	t.Helper()
	rm, ok := AsReleaseManager(waf)
	if !ok {
		t.Fatal("WAF does not implement ReleaseManager")
	}
	p := policy
	if p == nil {
		p = testRedactionPolicy()
	}
	p.RulesetID = "rs"
	p.Version = version
	info, err := rm.PublishRelease(ReleaseBundle{
		RulesetID: "rs",
		Version:   version,
		Rules:     releaseRules(id),
		Redaction: p,
	})
	if err != nil {
		t.Fatalf("PublishRelease v%s: %v", version, err)
	}
	return info
}

func TestReleasePublishNegativeMatrixAndMonotonicVersion(t *testing.T) {
	writer := &captureReleaseWriter{}
	waf := newReleaseTestWAF(t, writer)
	first := publishV(t, waf, 1001, "2026-1", nil)
	if first.ReleaseID != "r1" || first.ID != 1 || first.RuleCount != 1 {
		t.Fatalf("unexpected first release: %+v", first)
	}

	rm := waf.(ReleaseManager)
	bad := []struct {
		name    string
		bundle  func() ReleaseBundle
		errPart string
	}{
		{
			name: "corrupt rules",
			bundle: func() ReleaseBundle {
				b := validBundle("2026-bad-rule")
				b.Rules = "SecRule REQUEST_HEADERS \"@rx [\" \"id:1101,phase:1,deny\""
				return b
			},
			errPart: "rejected",
		},
		{
			name: "missing rules",
			bundle: func() ReleaseBundle {
				b := validBundle("2026-missing-rules")
				b.Rules = "  "
				return b
			},
			errPart: "rule content is missing",
		},
		{
			name: "missing manifest",
			bundle: func() ReleaseBundle {
				b := validBundle("2026-missing-manifest")
				b.Redaction = nil
				return b
			},
			errPart: "redaction manifest is missing",
		},
		{
			name: "ruleset mismatch",
			bundle: func() ReleaseBundle {
				b := validBundle("2026-ruleset-mismatch")
				b.Redaction.RulesetID = "other"
				return b
			},
			errPart: "ruleset id",
		},
		{
			name: "version mismatch",
			bundle: func() ReleaseBundle {
				b := validBundle("2026-version-mismatch")
				b.Redaction.Version = "different"
				return b
			},
			errPart: "redaction version",
		},
		{
			name: "unknown container",
			bundle: func() ReleaseBundle {
				b := validBundle("2026-bad-container")
				b.Redaction.Fields = []RedactionField{{Name: "x", Containers: []RedactionContainer{"nope"}}}
				return b
			},
			errPart: "unknown container",
		},
	}

	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			_, err := rm.PublishRelease(tc.bundle())
			if err == nil || !strings.Contains(err.Error(), tc.errPart) {
				t.Fatalf("error = %v, want substring %q", err, tc.errPart)
			}
			cur, ok := rm.CurrentRelease()
			if !ok || cur.ID != 1 || cur.RuleCount != 1 {
				t.Fatalf("active release changed after failure: ok=%v cur=%+v", ok, cur)
			}
		})
	}

	// Strict manifest parsing locates unknown JSON fields.
	if _, err := ParseRedactionPolicyJSON([]byte(`{"ruleset_id":"rs","version":"x","bogus":true}`)); err == nil ||
		!strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("strict policy error = %v", err)
	}

	// Consecutive failures do not consume or accumulate version state.
	cur, _ := rm.CurrentRelease()
	if cur.ID != 1 || cur.ReleaseID != "r1" {
		t.Fatalf("version moved after failures: %+v", cur)
	}

	second := publishV(t, waf, 2002, "2026-2", nil)
	if second.ID != 2 || second.ReleaseID != "r2" {
		t.Fatalf("second release = %+v", second)
	}
	third := publishV(t, waf, 3003, "2026-3", nil)
	if third.ID != 3 || third.ReleaseID != "r3" || third.ID <= second.ID {
		t.Fatalf("versions are not monotonic: %+v after %+v", third, second)
	}
}

func validBundle(version string) ReleaseBundle {
	p := testRedactionPolicy()
	p.RulesetID = "rs"
	p.Version = version
	return ReleaseBundle{
		RulesetID: "rs",
		Version:   version,
		Rules:     releaseRules(9009),
		Redaction: p,
	}
}

func TestReleaseAuditRedactionAndVersionConsistency(t *testing.T) {
	writer := &captureReleaseWriter{}
	waf := newReleaseTestWAF(t, writer)
	info := publishV(t, waf, 1001, "2026-audit", nil)

	tx := waf.NewTransaction()
	sendVersionedRequest(t, tx)

	logs := writer.snapshot()
	if len(logs) != 1 {
		t.Fatalf("audit logs = %d, want 1", len(logs))
	}
	al, ok := logs[0].(*auditlog.Log)
	if !ok {
		t.Fatalf("writer received %T, want *auditlog.Log", logs[0])
	}
	assertReleaseRecord(t, al, info.ReleaseID, 1001)

	secrets := []string{
		"querySecret123", "headerSecret456", "cookieSecret789",
		"formSecret999", "dupSecret1", "dupSecret2",
		"nestedSecretA", "nestedSecretB", "responseSecret000",
	}
	formats := []string{"json", "jsonlegacy", "native", "ocsf"}
	for _, format := range formats {
		t.Run("format-"+format, func(t *testing.T) {
			f, err := auditlog.GetFormatter(format)
			if err != nil {
				t.Fatal(err)
			}
			out, err := f.Format(al)
			if err != nil {
				t.Fatal(err)
			}
			text := string(out)
			for _, secret := range secrets {
				if strings.Contains(text, secret) {
					t.Fatalf("format %s leaks %q in:\n%s", format, secret, text)
				}
			}
			if !strings.Contains(text, info.ReleaseID) {
				t.Fatalf("format %s does not contain release id %s:\n%s", format, info.ReleaseID, text)
			}
			preserved := []string{"tracking=retainme", "keep=same", "192.0.2.10"}
			if format != "jsonlegacy" {
				// The legacy schema intentionally has no request body field.
				preserved = append(preserved, "user=alice")
			}
			for _, value := range preserved {
				if !strings.Contains(text, value) {
					t.Fatalf("format %s lost unmatched value %q in:\n%s", format, value, text)
				}
			}
		})
	}
}

func assertReleaseRecord(t *testing.T, al *auditlog.Log, releaseID string, ruleID int) {
	t.Helper()
	if al.ReleaseID() != releaseID {
		t.Fatalf("top release = %q, want %q", al.ReleaseID(), releaseID)
	}
	if al.Transaction_.ReleaseID() != releaseID {
		t.Fatalf("header release = %q, want %q", al.Transaction_.ReleaseID(), releaseID)
	}
	if al.Transaction_.Producer_ == nil || al.Transaction_.Producer_.ReleaseID() != releaseID {
		t.Fatalf("trailer release = %+v", al.Transaction_.Producer_)
	}
	if len(al.Messages_) == 0 {
		t.Fatal("expected matched audit messages")
	}
	for i, msgIface := range al.Messages_ {
		msg, ok := msgIface.(auditlog.Message)
		if !ok {
			t.Fatalf("message %d type %T", i, msgIface)
		}
		if msg.ReleaseID() != releaseID {
			t.Fatalf("message %d release = %q", i, msg.ReleaseID())
		}
		if msg.Data_ == nil || msg.Data_.ReleaseID_ != releaseID {
			t.Fatalf("message %d data release = %+v", i, msg.Data_)
		}
		if msg.Data_.ID_ != ruleID {
			t.Fatalf("message %d rule id = %d, want %d", i, msg.Data_.ID_, ruleID)
		}
	}
}

func TestReleaseInFlightAndConcurrentAtomicSwitch(t *testing.T) {
	writer := &captureReleaseWriter{}
	waf := newReleaseTestWAF(t, writer)
	rm, _ := AsReleaseManager(waf)
	r1 := publishV(t, waf, 1001, "concurrent-1", nil)

	// A transaction created before commit is allowed to finish on r1.
	oldTx := waf.NewTransaction()
	oldTxID := oldTx.ID()
	r2 := publishV(t, waf, 2002, "concurrent-2", nil)
	newTx := waf.NewTransaction()
	newTxID := newTx.ID()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); sendVersionedRequest(t, oldTx) }()
	go func() { defer wg.Done(); sendVersionedRequest(t, newTx) }()
	wg.Wait()

	logs := writer.snapshot()
	if len(logs) != 2 {
		t.Fatalf("logs = %d", len(logs))
	}
	byTxID := map[string]*auditlog.Log{}
	for _, entry := range logs {
		al := entry.(*auditlog.Log)
		byTxID[al.Transaction().ID()] = al
	}
	assertReleaseRecord(t, byTxID[oldTxID], r1.ReleaseID, 1001)
	assertReleaseRecord(t, byTxID[newTxID], r2.ReleaseID, 2002)

	// Concurrent traffic around a third switch must never observe mixed rule IDs.
	r3 := publishV(t, waf, 3003, "concurrent-3", nil)
	stop := make(chan struct{})
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				tx := waf.NewTransaction()
				sendVersionedRequest(t, tx)
			}
		}()
	}

	r4Policy := testRedactionPolicy()
	r4Policy.RulesetID = "rs"
	r4Policy.Version = "concurrent-4"
	r4, err := rm.PublishRelease(ReleaseBundle{
		RulesetID: "rs", Version: "concurrent-4",
		Rules: releaseRules(4004), Redaction: r4Policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	close(stop)
	workers.Wait()

	for _, alIface := range writer.snapshot()[2:] {
		al := alIface.(*auditlog.Log)
		switch al.ReleaseID() {
		case r3.ReleaseID:
			assertReleaseRecord(t, al, r3.ReleaseID, 3003)
		case r4.ReleaseID:
			assertReleaseRecord(t, al, r4.ReleaseID, 4004)
		default:
			t.Fatalf("unexpected release %q", al.ReleaseID())
		}
		for _, msg := range al.Messages_ {
			id := msg.Data().ID()
			if id != 3003 && id != 4004 {
				t.Fatalf("mixed/unknown rule id %d in release %s", id, al.ReleaseID())
			}
		}
	}
}

func TestReleaseAuditTargetFailureIsolation(t *testing.T) {
	good := &captureReleaseWriter{}
	bad := &failingReleaseWriter{err: errors.New("simulated unavailable target")}
	multi := NewMultiAuditLogWriter(bad, good)
	waf := newReleaseTestWAF(t, multi)
	publishV(t, waf, 1001, "fault", nil)

	tx := waf.NewTransaction()
	sendVersionedRequest(t, tx)

	if logs := good.snapshot(); len(logs) != 1 {
		t.Fatalf("healthy target logs = %d, want 1", len(logs))
	}
	err := multi.Write(good.snapshot()[0])
	if err == nil || !strings.Contains(err.Error(), "simulated unavailable target") {
		t.Fatalf("multi write error = %v", err)
	}
	if strings.Contains(err.Error(), "Secret") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("error mentions sensitive-looking value: %v", err)
	}
}

func TestReleaseFormatterWriterMatrix(t *testing.T) {
	writer := &captureReleaseWriter{}
	waf := newReleaseTestWAF(t, writer)
	info := publishV(t, waf, 1001, "matrix", nil)
	tx := waf.NewTransaction()
	sendVersionedRequest(t, tx)
	logs := writer.snapshot()
	if len(logs) != 1 {
		t.Fatalf("logs=%d", len(logs))
	}
	al := logs[0].(*auditlog.Log)
	secrets := []string{
		"querySecret123", "headerSecret456", "cookieSecret789",
		"formSecret999", "dupSecret1", "dupSecret2",
		"nestedSecretA", "nestedSecretB", "responseSecret000",
	}

	for _, writerName := range []string{"serial", "concurrent", "https", "syslog"} {
		for _, formatName := range []string{"json", "jsonlegacy", "native", "ocsf"} {
			t.Run(writerName+"/"+formatName, func(t *testing.T) {
				formatter, err := auditlog.GetFormatter(formatName)
				if err != nil {
					t.Fatal(err)
				}
				output := writeReleaseThroughWriter(t, writerName, formatter, al)
				for _, secret := range secrets {
					if strings.Contains(output, secret) {
						t.Fatalf("%s/%s leaks %q:\n%s", writerName, formatName, secret, output)
					}
				}
				if !strings.Contains(output, info.ReleaseID) {
					t.Fatalf("%s/%s misses release id %s:\n%s", writerName, formatName, info.ReleaseID, output)
				}
			})
		}
	}
}

func writeReleaseThroughWriter(t *testing.T, name string, formatter plugintypes.AuditLogFormatter, al plugintypes.AuditLog) string {
	t.Helper()
	w, err := auditlog.GetWriter(name)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := plugintypes.AuditLogConfig{Formatter: formatter, FileMode: 0o600, Dir: dir, DirMode: 0o700}

	var httpBody <-chan []byte
	var syslogBody <-chan string
	switch name {
	case "serial":
		cfg.Target = filepath.Join(dir, "audit.log")
	case "concurrent":
		cfg.Target = filepath.Join(dir, "concurrent-index.log")
		cfg.Dir = filepath.Join(dir, "concurrent")
	case "https":
		bodyCh := make(chan []byte, 1)
		server := httptest.NewServer(&matrixHTTPHandler{bodyCh: bodyCh})
		t.Cleanup(server.Close)
		httpBody = bodyCh
		cfg.Target = server.URL
	case "syslog":
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		bodyCh := make(chan string, 1)
		syslogBody = bodyCh
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			b, _ := io.ReadAll(conn)
			bodyCh <- string(b)
		}()
		cfg.Target = listener.Addr().String()
	}

	if err := w.Init(cfg); err != nil {
		t.Fatalf("init %s: %v", name, err)
	}
	if err := w.Write(al); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}

	switch name {
	case "serial":
		closeWriterQuietly(w)
		b, err := os.ReadFile(cfg.Target)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	case "concurrent":
		closeWriterQuietly(w)
		var all strings.Builder
		err := filepath.WalkDir(cfg.Dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			all.Write(b)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return all.String()
	case "https":
		select {
		case b := <-httpBody:
			return string(b)
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for HTTPS writer payload")
			return ""
		}
	case "syslog":
		closeWriterQuietly(w)
		select {
		case b := <-syslogBody:
			return b
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for syslog payload")
			return ""
		}
	default:
		return ""
	}
}

type matrixHTTPHandler struct{ bodyCh chan<- []byte }

func (h *matrixHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	h.bodyCh <- b
	w.WriteHeader(204)
}

func closeWriterQuietly(w plugintypes.AuditLogWriter) {
	defer func() { _ = recover() }()
	_ = w.Close()
}

func TestReleaseJSONNestedAndRetainList(t *testing.T) {
	writer := &captureReleaseWriter{}
	waf := newReleaseTestWAF(t, writer)
	policy := &RedactionPolicy{Fields: []RedactionField{
		{Name: "access_token", Containers: []RedactionContainer{RedactionJSON}},
		{Name: "password", Containers: []RedactionContainer{RedactionJSON}},
		{Name: "token", Containers: []RedactionContainer{RedactionJSON}},
	}}
	publishV(t, waf, 1001, "json", policy)

	body := `{"access_token":"jsonSecretA","user":{"name":"alice","password":"jsonSecretB"},"items":[{"token":"arraySecretC"},{"token":"arraySecretD"}],"dup":{"token":"dupE","token":"dupF"}}`
	tx := waf.NewTransaction()
	tx.ProcessConnection("198.51.100.8", 5000, "192.0.2.1", 443)
	tx.ProcessURI("/json", "POST", "HTTP/1.1")
	tx.AddRequestHeader("Content-Type", "application/json")
	if it := tx.ProcessRequestHeaders(); it != nil {
		t.Fatalf("headers interruption: %+v", it)
	}
	if it, _, err := tx.WriteRequestBody([]byte(body)); err != nil || it != nil {
		t.Fatalf("write body err=%v it=%+v", err, it)
	}
	if it, err := tx.ProcessRequestBody(); err != nil || it != nil {
		t.Fatalf("process body err=%v it=%+v", err, it)
	}
	tx.ProcessLogging()
	_ = tx.Close()

	logs := writer.snapshot()
	if len(logs) != 1 {
		t.Fatalf("logs=%d", len(logs))
	}
	al := logs[0].(*auditlog.Log)
	out, err := auditlog.GetFormatter("json")
	if err != nil {
		t.Fatal(err)
	}
	formatted, err := out.Format(al)
	if err != nil {
		t.Fatal(err)
	}
	text := string(formatted)
	for _, secret := range []string{"jsonSecretA", "jsonSecretB", "arraySecretC", "arraySecretD", "dupE", "dupF"} {
		if strings.Contains(text, secret) {
			t.Fatalf("JSON body leaks %s:\n%s", secret, text)
		}
	}
	if !strings.Contains(text, `\"name\":\"alice\"`) {
		t.Fatalf("unmatched JSON field was not byte-preserved:\n%s", text)
	}
}

func TestReleaseWildcardHeadersAndRetainedAssociationFields(t *testing.T) {
	writer := &captureReleaseWriter{}
	waf := newReleaseTestWAF(t, writer)
	policy := &RedactionPolicy{
		Fields: []RedactionField{{Name: "*", Containers: []RedactionContainer{RedactionHeaders}}},
		Retain: []string{"X-TLS-Fingerprint"},
	}
	publishV(t, waf, 1001, "retain", policy)

	tx := waf.NewTransaction()
	tx.ProcessConnection("203.0.113.55", 51000, "198.51.100.2", 443)
	tx.ProcessURI("/", "GET", "HTTP/1.1")
	tx.AddRequestHeader("X-TLS-Fingerprint", "ja3:771,4865-4866")
	tx.AddRequestHeader("Authorization", "Bearer retainCredential123")
	tx.ProcessRequestHeaders()
	tx.ProcessLogging()
	_ = tx.Close()

	al := writer.snapshot()[0].(*auditlog.Log)
	out, _ := auditlog.GetFormatter("native")
	b, err := out.Format(al)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.Contains(text, "ja3:771,4865-4866") || !strings.Contains(text, "203.0.113.55") {
		t.Fatalf("retained association fields missing:\n%s", text)
	}
	if strings.Contains(text, "retainCredential123") {
		t.Fatalf("paired credential leaked:\n%s", text)
	}
}

func TestReleaseSecretsAbsentFromDebugAndErrorCallback(t *testing.T) {
	var debugBuf syncBuffer
	var callbackText syncBuffer
	cfg := NewWAFConfig().
		WithRequestBodyAccess().
		WithDebugLogger(debuglog.Default().WithOutput(&debugBuf).WithLevel(debuglog.LevelDebug)).(*wafConfig)
	writer := &captureReleaseWriter{}
	cfg.auditLog = &auditLogConfig{parts: types.AuditLogParts{types.AuditLogPartHeader, types.AuditLogPartAuditLogTrailer}, writer: writer}
	cfg.errorCallback = func(mr types.MatchedRule) {
		callbackText.WriteString(mr.ErrorLog())
		for _, md := range mr.MatchedDatas() {
			callbackText.WriteString(md.Value())
			callbackText.WriteString(md.Message())
			callbackText.WriteString(md.Data())
		}
	}
	waf, err := NewWAF(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = waf.(wafWrapper).Close() })
	publishV(t, waf, 1001, "debug-secrets", nil)

	tx := waf.NewTransaction()
	sendVersionedRequest(t, tx)

	combined := debugBuf.String() + callbackText.String()
	for _, secret := range []string{"headerSecret456", "querySecret123", "cookieSecret789", "formSecret999"} {
		if strings.Contains(combined, secret) {
			t.Fatalf("secret %q reached debug/callback output:\n%s", secret, combined)
		}
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) WriteString(s string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.WriteString(s)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type secretProbeFormatter struct{ t *testing.T }

func (f *secretProbeFormatter) Format(al plugintypes.AuditLog) ([]byte, error) {
	f.t.Helper()
	secrets := []string{"querySecret123", "headerSecret456", "cookieSecret789", "formSecret999"}
	var visible strings.Builder
	req := al.Transaction().Request()
	if req != nil {
		visible.WriteString(req.URI())
		visible.WriteString(req.Body())
		for _, values := range req.Headers() {
			for _, value := range values {
				visible.WriteString(value)
			}
		}
		if args := req.Args(); args != nil {
			for _, md := range args.FindAll() {
				visible.WriteString(md.Key())
				visible.WriteString(md.Value())
			}
		}
	}
	for _, msg := range al.Messages() {
		visible.WriteString(msg.Message())
		if withErr, ok := msg.(interface{ ErrorMessage() string }); ok {
			visible.WriteString(withErr.ErrorMessage())
		}
		if d := msg.Data(); d != nil {
			visible.WriteString(d.Msg())
			visible.WriteString(d.Data())
		}
	}
	for _, secret := range secrets {
		if strings.Contains(visible.String(), secret) {
			f.t.Errorf("custom formatter can see secret %q in %q", secret, visible.String())
		}
	}
	return []byte("custom-" + auditReleaseIDForTest(al)), nil
}
func (f *secretProbeFormatter) MIME() string { return "text/x-secret-probe" }

func auditReleaseIDForTest(al plugintypes.AuditLog) string {
	type releaser interface{ ReleaseID() string }
	if r, ok := al.(releaser); ok {
		return r.ReleaseID()
	}
	return ""
}

func TestReleaseCustomFormatterCannotSeeSecrets(t *testing.T) {
	writer := &captureReleaseWriter{}
	waf := newReleaseTestWAF(t, writer)
	info := publishV(t, waf, 1001, "custom", nil)
	tx := waf.NewTransaction()
	sendVersionedRequest(t, tx)
	al := writer.snapshot()[0]
	out, err := (&secretProbeFormatter{t: t}).Format(al)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "custom-"+info.ReleaseID {
		t.Fatalf("custom output = %q", out)
	}
}
