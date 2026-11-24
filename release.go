// Copyright 2025 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/internal/redact"
	"github.com/corazawaf/coraza/v3/internal/seclang"
)

// RedactionPolicy is the field-level redaction manifest released together
// with a ruleset.
type RedactionPolicy = redact.Policy

// RedactionField selects a field name and optional containers.
type RedactionField = redact.FieldRule

// RedactionContainer names an audit-record container.
type RedactionContainer = redact.Container

// Supported redaction containers.
const (
	RedactionHeaders = redact.Headers
	RedactionQuery   = redact.Query
	RedactionForm    = redact.Form
	RedactionJSON    = redact.JSON
	RedactionXML     = redact.XML
	RedactionCookie  = redact.Cookie
	RedactionParams  = redact.Params
	RedactionBody    = redact.Body
)

// ParseRedactionPolicyJSON parses a strict JSON redaction manifest.
func ParseRedactionPolicyJSON(data []byte) (*RedactionPolicy, error) {
	return redact.ParsePolicyJSON(data)
}

// ParseReleaseBundleJSON parses a strict JSON release bundle. The returned
// bundle still goes through PublishRelease's paired-version validation.
func ParseReleaseBundleJSON(data []byte) (ReleaseBundle, error) {
	var bundle ReleaseBundle
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&bundle); err != nil {
		return ReleaseBundle{}, fmt.Errorf("invalid release bundle: %w", err)
	}
	if dec.More() {
		return ReleaseBundle{}, fmt.Errorf("invalid release bundle: multiple JSON documents")
	}
	return bundle, nil
}

// ReleaseBundle is the atomic submission unit: rule content, logical ruleset identifier, paired version and field-level redaction manifest.
type ReleaseBundle struct {
	// RulesetID identifies the logical ruleset (for example "owasp-crs").
	RulesetID string `json:"ruleset_id"`

	// Version is the caller-controlled content/manifest revision. It must
	// match Redaction.Version and Redaction.RulesetID.
	Version string `json:"version"`

	// Rules is the complete SecLang ruleset for this release.
	Rules string `json:"rules"`

	// Redaction is the paired redaction manifest.
	Redaction *RedactionPolicy `json:"redaction"`
}

// ReleaseInfo describes a successfully activated release.
type ReleaseInfo struct {
	ID            uint64    `json:"id"`
	ReleaseID     string    `json:"release_id"`
	RulesetID     string    `json:"ruleset_id"`
	Version       string    `json:"version"`
	SourceVersion string    `json:"source_version"`
	RuleCount     int       `json:"rule_count"`
	CreatedAt     time.Time `json:"created_at"`
}

// ReleaseManager is the optional runtime atomic ruleset/redaction surface.
// Existing coraza.WAF creation and transaction APIs are unchanged.
type ReleaseManager interface {
	PublishRelease(bundle ReleaseBundle) (ReleaseInfo, error)
	CurrentRelease() (ReleaseInfo, bool)
}

// AsReleaseManager returns the optional release manager implemented by WAF
// instances created by this package.
func AsReleaseManager(waf WAF) (ReleaseManager, bool) {
	rm, ok := waf.(ReleaseManager)
	return rm, ok
}

// PublishRelease is a convenience wrapper around AsReleaseManager.
func PublishRelease(waf WAF, bundle ReleaseBundle) (ReleaseInfo, error) {
	rm, ok := AsReleaseManager(waf)
	if !ok {
		return ReleaseInfo{}, fmt.Errorf("coraza: WAF implementation %T does not support atomic releases", waf)
	}
	return rm.PublishRelease(bundle)
}

// PublishRelease compiles and validates a complete candidate before taking the
// release commit lock. A failure leaves the previous release active.
func (w wafWrapper) PublishRelease(bundle ReleaseBundle) (ReleaseInfo, error) {
	if err := validateBundle(bundle); err != nil {
		return ReleaseInfo{}, err
	}

	candidate := w.waf.NewCompilationWAF()
	parser := seclang.NewParser(candidate)
	// Release bundles are self-contained and must behave identically in
	// no-filesystem/TinyGo builds. Do not read Include paths from the host.
	parser.SetRoot(emptyReleaseFS{})
	if err := parser.FromString(bundle.Rules); err != nil {
		return ReleaseInfo{}, fmt.Errorf("release %q/%s rejected: %w", bundle.RulesetID, bundle.Version, err)
	}
	if err := candidate.Validate(); err != nil {
		return ReleaseInfo{}, fmt.Errorf("release %q/%s validation failed: %w", bundle.RulesetID, bundle.Version, err)
	}

	policy := *bundle.Redaction
	policy.RulesetID = bundle.RulesetID
	policy.Version = bundle.Version
	if err := policy.Compile(); err != nil {
		return ReleaseInfo{}, fmt.Errorf("release %q/%s rejected: %w", bundle.RulesetID, bundle.Version, err)
	}

	release := &corazawaf.Release{}
	release.SetForPublish(bundle.RulesetID, bundle.Version, &candidate.Rules, &policy, candidate)
	info := w.waf.CommitRelease(release)
	return toReleaseInfo(info), nil
}

// CurrentRelease returns the active release descriptor.
func (w wafWrapper) CurrentRelease() (ReleaseInfo, bool) {
	info, ok := w.waf.CurrentReleaseInfo()
	if !ok {
		return ReleaseInfo{}, false
	}
	return toReleaseInfo(info), true
}

func validateBundle(b ReleaseBundle) error {
	if strings.TrimSpace(b.RulesetID) == "" {
		return fmt.Errorf("release rejected: ruleset id is missing")
	}
	if strings.TrimSpace(b.Version) == "" {
		return fmt.Errorf("release %q rejected: version is missing", b.RulesetID)
	}
	if strings.TrimSpace(b.Rules) == "" {
		return fmt.Errorf("release %q/%s rejected: rule content is missing", b.RulesetID, b.Version)
	}
	if b.Redaction == nil {
		return fmt.Errorf("release %q/%s rejected: redaction manifest is missing", b.RulesetID, b.Version)
	}
	if strings.TrimSpace(b.Redaction.RulesetID) == "" {
		return fmt.Errorf("release %q/%s rejected: redaction ruleset id is missing", b.RulesetID, b.Version)
	}
	if strings.TrimSpace(b.Redaction.Version) == "" {
		return fmt.Errorf("release %q/%s rejected: redaction version is missing", b.RulesetID, b.Version)
	}
	if b.Redaction.RulesetID != b.RulesetID {
		return fmt.Errorf("release rejected: redaction ruleset id %q does not match %q", b.Redaction.RulesetID, b.RulesetID)
	}
	if b.Redaction.Version != b.Version {
		return fmt.Errorf("release %q rejected: redaction version %q does not match %q", b.RulesetID, b.Redaction.Version, b.Version)
	}
	if err := b.Redaction.Compile(); err != nil {
		return fmt.Errorf("release %q/%s rejected: %w", b.RulesetID, b.Version, err)
	}
	return nil
}

func toReleaseInfo(in corazawaf.ReleaseInfo) ReleaseInfo {
	return ReleaseInfo{
		ID:            in.ID,
		ReleaseID:     in.Version,
		RulesetID:     in.RulesetID,
		Version:       in.Version,
		SourceVersion: in.SourceVersion,
		RuleCount:     in.RuleCount,
		CreatedAt:     in.CreatedAt,
	}
}

type emptyReleaseFS struct{}

func (emptyReleaseFS) Open(name string) (fs.File, error) {
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}
