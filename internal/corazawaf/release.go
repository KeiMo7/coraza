// Copyright 2025 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"strconv"
	"time"

	"github.com/corazawaf/coraza/v3/internal/redact"
	"github.com/corazawaf/coraza/v3/types"
)

// Release is an immutable, atomically published ruleset and redaction policy.
// A Transaction captures exactly one Release for its whole lifetime.
type Release struct {
	id            uint64
	rulesetID     string
	sourceVersion string
	rules         *RuleGroup
	policy        *redact.Policy
	compiledWAF   *WAF
	createdAt     time.Time
}

// ReleaseInfo is the public snapshot of a published release.
type ReleaseInfo struct {
	ID            uint64    `json:"id"`
	Version       string    `json:"version"`
	RulesetID     string    `json:"ruleset_id"`
	SourceVersion string    `json:"source_version"`
	RuleCount     int       `json:"rule_count"`
	CreatedAt     time.Time `json:"created_at"`
}

// SetForPublish populates an uncommitted release from the root composition
// layer, which owns SecLang parsing.
func (r *Release) SetForPublish(rulesetID, sourceVersion string, rules *RuleGroup, policy *redact.Policy, compiledWAF *WAF) {
	r.rulesetID = rulesetID
	r.sourceVersion = sourceVersion
	r.rules = rules
	r.policy = policy
	r.compiledWAF = compiledWAF
}

// ID returns the monotonic release sequence.
func (r *Release) ID() uint64 { return r.id }

// Version returns the stable, readable release identifier.
func (r *Release) Version() string {
	if r == nil {
		return ""
	}
	return releaseVersion(r.id)
}

// RulesetID returns the logical ruleset identifier.
func (r *Release) RulesetID() string { return r.rulesetID }

// SourceVersion returns the paired caller-supplied content/manifest version.
func (r *Release) SourceVersion() string { return r.sourceVersion }

// Policy returns the redaction policy.
func (r *Release) Policy() *redact.Policy { return r.policy }

// Rules returns the immutable rule group.
func (r *Release) Rules() *RuleGroup { return r.rules }

// CompiledWAF returns the throwaway WAF that owns directive-derived defaults.
func (r *Release) CompiledWAF() *WAF { return r.compiledWAF }

// Info returns an immutable release descriptor.
func (r *Release) Info() ReleaseInfo {
	if r == nil {
		return ReleaseInfo{}
	}
	count := 0
	if r.rules != nil {
		count = r.rules.Count()
	}
	return ReleaseInfo{
		ID:            r.id,
		Version:       r.Version(),
		RulesetID:     r.rulesetID,
		SourceVersion: r.sourceVersion,
		RuleCount:     count,
		CreatedAt:     r.createdAt,
	}
}

func releaseVersion(id uint64) string {
	return "r" + strconv.FormatUint(id, 10)
}

// NewCompilationWAF creates a throwaway WAF seeded with the active host
// configuration. Parsing a candidate ruleset into this value cannot affect the
// active release. The memoizer is shared because compiled patterns are
// content-addressed and owned by the parent WAF lifetime.
func (w *WAF) NewCompilationWAF() *WAF {
	c := NewWAF()
	c.Logger = w.Logger
	c.RuleEngine = w.RuleEngine
	c.RequestBodyAccess = w.RequestBodyAccess
	c.RequestBodyLimit = w.RequestBodyLimit
	c.RequestBodyJsonDepthLimit = w.RequestBodyJsonDepthLimit
	c.requestBodyInMemoryLimit = w.requestBodyInMemoryLimit
	c.RequestBodyNoFilesLimit = w.RequestBodyNoFilesLimit
	c.ResponseBodyAccess = w.ResponseBodyAccess
	c.ResponseBodyLimit = w.ResponseBodyLimit
	c.ResponseBodyJsonDepthLimit = w.ResponseBodyJsonDepthLimit
	c.ResponseBodyMimeTypes = append([]string(nil), w.ResponseBodyMimeTypes...)
	c.WebAppID = w.WebAppID
	c.ComponentNames = append([]string(nil), w.ComponentNames...)
	c.AbortOnRemoteRulesFail = w.AbortOnRemoteRulesFail
	c.ServerSignature = w.ServerSignature
	c.TmpDir = w.TmpDir
	c.SensorID = w.SensorID
	c.DataDir = w.DataDir
	c.UploadKeepFiles = w.UploadKeepFiles
	c.UploadFileMode = w.UploadFileMode
	c.UploadFileLimit = w.UploadFileLimit
	c.UploadDir = w.UploadDir
	c.ArgumentSeparator = w.ArgumentSeparator
	c.ProducerConnector = w.ProducerConnector
	c.ProducerConnectorVersion = w.ProducerConnectorVersion
	c.ErrorLogCb = w.ErrorLogCb
	c.AuditEngine = w.AuditEngine
	c.AuditLogParts = append(types.AuditLogParts(nil), w.AuditLogParts...)
	c.AuditLogFormat = w.AuditLogFormat
	c.AuditLogRelevantStatus = w.AuditLogRelevantStatus
	c.auditLogWriter = w.auditLogWriter
	c.AuditLogWriterConfig = w.AuditLogWriterConfig
	c.auditLogWriterInitialized = w.auditLogWriterInitialized
	c.ArgumentLimit = w.ArgumentLimit
	c.RxPreFilterEnabled = w.RxPreFilterEnabled
	c.memoizerID = w.memoizerID
	c.memoizer = w.memoizer
	return c
}

// ConfigWAF returns the immutable directive-derived configuration for the
// transaction's release, falling back to the owning WAF.
func (tx *Transaction) ConfigWAF() *WAF {
	if tx.release != nil && tx.release.compiledWAF != nil {
		return tx.release.compiledWAF
	}
	return tx.WAF
}

// ActiveRelease returns the currently published release, or nil when runtime
// versioned releases are not in use.
func (w *WAF) ActiveRelease() *Release {
	if w == nil {
		return nil
	}
	v, _ := w.activeRelease.Load().(*Release)
	return v
}

// CommitRelease assigns the next monotonic ID and atomically activates r. The
// publish mutex is intentionally separate from request processing: transactions
// perform one atomic load and never take this lock.
func (w *WAF) CommitRelease(r *Release) ReleaseInfo {
	w.releaseMu.Lock()
	defer w.releaseMu.Unlock()

	w.releaseSeq++
	r.id = w.releaseSeq
	if r.createdAt.IsZero() {
		r.createdAt = time.Now().UTC()
	}
	w.activeRelease.Store(r)
	return r.Info()
}

// CurrentReleaseInfo returns the active release descriptor.
func (w *WAF) CurrentReleaseInfo() (ReleaseInfo, bool) {
	r := w.ActiveRelease()
	if r == nil {
		return ReleaseInfo{}, false
	}
	return r.Info(), true
}

// SetActiveReleaseForTest installs a fully built release without changing the
// monotonic sequence. It is used by focused internal tests.
func (w *WAF) SetActiveReleaseForTest(r *Release) {
	w.activeRelease.Store(r)
}
