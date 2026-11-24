// Copyright 2025 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"fmt"
	"mime"
	"strings"

	"github.com/corazawaf/coraza/v3/internal/auditlog"
	"github.com/corazawaf/coraza/v3/internal/collections"
	"github.com/corazawaf/coraza/v3/internal/corazarules"
	"github.com/corazawaf/coraza/v3/internal/redact"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

const maxSensitiveLogPrefix = 280

func (tx *Transaction) redactionMatcher() *redact.Matcher {
	if tx.release == nil || tx.release.Policy() == nil {
		return nil
	}
	return tx.release.Policy().Matcher()
}

func (tx *Transaction) matchDataSensitive(md types.MatchData) bool {
	m := tx.redactionMatcher()
	if m == nil || !m.Enabled() || md == nil {
		return false
	}
	key := md.Key()
	switch md.Variable() {
	case variables.RequestHeaders:
		if m.ShouldRedact(redact.Headers, key) {
			return true
		}
		return strings.EqualFold(key, "cookie") && tx.cookieValueSensitive(m, md.Value())
	case variables.ResponseHeaders:
		return m.ShouldRedact(redact.Headers, key)
	case variables.RequestCookies:
		return m.ShouldRedact(redact.Cookie, key) || m.ShouldRedact(redact.Headers, key)
	case variables.ArgsGet:
		return m.ShouldRedact(redact.Query, key) || m.ShouldRedact(redact.Params, key)
	case variables.ArgsPost:
		return postFieldSensitive(m, key)
	case variables.Args, variables.ArgsPath:
		return m.ShouldRedact(redact.Params, key) ||
			m.ShouldRedact(redact.Query, key) ||
			postFieldSensitive(m, key)
	default:
		return false
	}
}

func postFieldSensitive(m *redact.Matcher, key string) bool {
	if m.ShouldRedact(redact.Form, key) || m.ShouldRedact(redact.Params, key) {
		return true
	}
	if strings.HasPrefix(strings.ToLower(key), "json.") {
		return m.ShouldRedact(redact.JSON, key)
	}
	return m.ShouldRedact(redact.Body, key)
}

func (tx *Transaction) cookieValueSensitive(m *redact.Matcher, headerValue string) bool {
	for _, pair := range strings.Split(headerValue, ";") {
		name, _, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if ok && (m.ShouldRedact(redact.Cookie, name) || m.ShouldRedact(redact.Headers, name)) {
			return true
		}
	}
	return false
}

func (tx *Transaction) collectSensitiveSecrets(m *redact.Matcher) []string {
	if m == nil || !m.Enabled() {
		return nil
	}
	var secrets []string
	addMatch := func(md types.MatchData) {
		if md == nil || !tx.matchDataSensitive(md) {
			return
		}
		if v := md.Value(); len(v) >= 2 {
			secrets = append(secrets, v)
		}
	}

	for _, md := range tx.variables.requestHeaders.FindAll() {
		if tx.matchDataSensitive(md) {
			addMatch(md)
		}
		// Cookie subfields are selected independently of the Cookie header.
		if strings.EqualFold(md.Key(), "cookie") {
			for _, pair := range strings.Split(md.Value(), ";") {
				name, value, ok := strings.Cut(strings.TrimSpace(pair), "=")
				if ok && (m.ShouldRedact(redact.Cookie, name) || m.ShouldRedact(redact.Headers, name)) && len(value) >= 2 {
					secrets = append(secrets, value)
				}
			}
		}
	}
	for _, md := range tx.variables.responseHeaders.FindAll() {
		addMatch(md)
	}
	for _, col := range []interface{ FindAll() []types.MatchData }{
		tx.variables.argsGet,
		tx.variables.argsPost,
		tx.variables.argsPath,
	} {
		for _, md := range col.FindAll() {
			addMatch(md)
		}
	}
	return secrets
}

func (tx *Transaction) scrubSensitiveText(s string, secrets []string) string {
	if s == "" || len(secrets) == 0 {
		return s
	}
	mask := tx.redactionMatcher().Replacement()
	for _, secret := range secrets {
		if len(secret) < 2 {
			continue
		}
		s = redact.ScrubLiteral(s, secret, mask)

		// Coraza log lines truncate msg/data to 280 bytes before formatting.
		// Scrub the surviving prefix and its Go %q escaping so a long secret
		// cannot leave a partial value in an error or audit line.
		n := len(secret)
		if n > maxSensitiveLogPrefix {
			n = maxSensitiveLogPrefix
			prefix := secret[:n]
			s = redact.ScrubLiteral(s, prefix, mask)
			quoted := fmt.Sprintf("%q", prefix)
			if len(quoted) >= 2 {
				s = strings.ReplaceAll(s, quoted[1:len(quoted)-1], mask)
			}
		}
	}
	return s
}

// sanitizeMatchedRuleForOutput returns a copy safe for error callbacks and
// audit construction. The transaction's original match data is left intact for
// the public MatchedRules API and any remaining rule processing.
func (tx *Transaction) sanitizeMatchedRuleForOutput(mr *corazarules.MatchedRule, secrets []string) *corazarules.MatchedRule {
	if mr == nil || tx.release == nil {
		return mr
	}
	m := tx.redactionMatcher()
	safe := *mr
	if m != nil {
		safe.URI_ = tx.redactURI(safe.URI_, m)
	}
	mds := make([]types.MatchData, 0, len(mr.MatchedDatas_))
	anySensitive := false
	for _, original := range mr.MatchedDatas_ {
		clone := original
		if cmd, ok := original.(*corazarules.MatchData); ok {
			c := *cmd
			clone = &c
		}
		if tx.matchDataSensitive(clone) {
			anySensitive = true
			if cmd, ok := clone.(*corazarules.MatchData); ok {
				cmd.Value_ = m.Replacement()
				cmd.Message_ = m.Replacement()
				cmd.Data_ = m.Replacement()
			}
		} else if cmd, ok := clone.(*corazarules.MatchData); ok {
			cmd.Message_ = tx.scrubSensitiveText(cmd.Message_, secrets)
			cmd.Data_ = tx.scrubSensitiveText(cmd.Data_, secrets)
		}
		mds = append(mds, clone)
	}
	safe.MatchedDatas_ = mds
	safe.Message_ = tx.scrubSensitiveText(safe.Message_, secrets)
	safe.Data_ = tx.scrubSensitiveText(safe.Data_, secrets)
	if anySensitive {
		// The top-level fields alias the first matched data's macro output.
		safe.Message_ = m.Replacement()
		safe.Data_ = m.Replacement()
	}
	return &safe
}

func (tx *Transaction) releaseAuditInfo() *auditlog.ReleaseInfo {
	r := tx.release
	if r == nil {
		return nil
	}
	return &auditlog.ReleaseInfo{
		Sequence:  r.ID(),
		ID:        r.Version(),
		RulesetID: r.RulesetID(),
		Version:   r.SourceVersion(),
	}
}

func (tx *Transaction) prepareVersionedAuditLog(al *auditlog.Log) *auditlog.Log {
	if tx.release == nil || al == nil {
		return al
	}
	info := tx.releaseAuditInfo()
	al.Release_ = info
	al.Transaction_.Release_ = info

	m := tx.redactionMatcher()
	secrets := tx.collectSensitiveSecrets(m)

	if al.Transaction_.Request_ != nil {
		req := al.Transaction_.Request_
		tx.redactHeaderMap(req.Headers_, m)
		req.URI_ = tx.redactURI(req.URI_, m)
		req.Body_ = tx.redactRequestBody(req.Body_, m)
		req.Args_ = tx.redactArgs(m)
	}
	if al.Transaction_.Response_ != nil {
		tx.redactHeaderMap(al.Transaction_.Response_.Headers_, m)
	}

	if al.Transaction_.Producer_ != nil {
		al.Transaction_.Producer_.Release_ = info
	}

	for i := range al.Messages_ {
		msg, ok := al.Messages_[i].(auditlog.Message)
		if !ok {
			continue
		}
		msg.Release_ = info
		msg.Message_ = tx.scrubSensitiveText(msg.Message_, secrets)
		msg.ErrorMessage_ = tx.scrubSensitiveText(msg.ErrorMessage_, secrets)
		msg.Actionset_ = tx.scrubSensitiveText(msg.Actionset_, secrets)
		if msg.Data_ != nil {
			msg.Data_.ReleaseID_ = info.ID
			msg.Data_.Msg_ = tx.scrubSensitiveText(msg.Data_.Msg_, secrets)
			msg.Data_.Data_ = tx.scrubSensitiveText(msg.Data_.Data_, secrets)
		}
		al.Messages_[i] = msg
	}
	return al
}

func (tx *Transaction) redactHeaderMap(headers map[string][]string, m *redact.Matcher) {
	for key, values := range headers {
		whole := m.ShouldRedact(redact.Headers, key)
		for i, value := range values {
			switch {
			case whole:
				values[i] = m.Replacement()
			case strings.EqualFold(key, "cookie") || strings.EqualFold(key, "set-cookie"):
				values[i] = redact.RedactCookieHeader(key, value, m)
			}
		}
	}
}

func (tx *Transaction) redactURI(uri string, m *redact.Matcher) string {
	if uri == "" {
		return uri
	}
	pathAndQuery, fragment, hasFragment := strings.Cut(uri, "#")
	path, query, hasQuery := strings.Cut(pathAndQuery, "?")
	if !hasQuery {
		return uri
	}
	query = redact.RedactPairs(query, m, redact.Query)
	out := path + "?" + query
	if hasFragment {
		out += "#" + fragment
	}
	return out
}

func (tx *Transaction) redactRequestBody(body string, m *redact.Matcher) string {
	if body == "" || m == nil {
		return body
	}
	processor := strings.ToLower(tx.variables.reqbodyProcessor.Get())
	contentType := ""
	if vals := tx.variables.requestHeaders.Get("content-type"); len(vals) > 0 {
		contentType = strings.ToLower(vals[0])
	}

	switch {
	case processor == "json" || strings.Contains(contentType, "json"):
		return redact.RedactJSON(body, m)
	case processor == "xml" || strings.Contains(contentType, "xml"):
		return redact.RedactXML(body, m)
	case processor == "urlencoded" || strings.Contains(contentType, "x-www-form-urlencoded"):
		return redact.RedactPairs(body, m, redact.Form)
	case strings.Contains(contentType, "multipart/form-data"):
		_, params, err := mime.ParseMediaType(contentType)
		if err == nil && params["boundary"] != "" {
			return redact.RedactMultipart(body, params["boundary"], m)
		}
		return body
	default:
		// Unknown/raw bodies cannot be field-selected structurally. Literal
		// secret sweeping still protects macro/error paths, while explicit
		// form/json/xml content types get byte-preserving field redaction.
		return body
	}
}

func (tx *Transaction) redactArgs(m *redact.Matcher) *collections.ConcatKeyed {
	safe := collections.NewMap(variables.Args)
	add := func(col interface{ FindAll() []types.MatchData }, target redact.Container) {
		for _, md := range col.FindAll() {
			value := md.Value()
			redacted := false
			switch target {
			case redact.Query:
				redacted = m.ShouldRedact(redact.Query, md.Key()) || m.ShouldRedact(redact.Params, md.Key())
			case redact.Form:
				redacted = postFieldSensitive(m, md.Key())
			default:
				redacted = m.ShouldRedact(redact.Params, md.Key()) ||
					m.ShouldRedact(redact.Query, md.Key()) ||
					postFieldSensitive(m, md.Key())
			}
			if redacted {
				value = m.Replacement()
			}
			safe.Add(md.Key(), value)
		}
	}
	add(tx.variables.argsGet, redact.Query)
	add(tx.variables.argsPost, redact.Form)
	add(tx.variables.argsPath, redact.Params)
	return collections.NewConcatKeyed(variables.Args, safe)
}
