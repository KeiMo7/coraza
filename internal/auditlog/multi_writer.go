// Copyright 2025 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package auditlog

import (
	"errors"
	"fmt"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// MultiWriter fans one audit record out to several already-configured targets.
// Each target receives the same redacted AuditLog value exactly once; a failure
// from one target is joined with the others but never prevents their writes.
type MultiWriter struct {
	writers []plugintypes.AuditLogWriter
}

// NewMultiWriter creates a writer that fans out to writers in order.
func NewMultiWriter(writers ...plugintypes.AuditLogWriter) *MultiWriter {
	return &MultiWriter{writers: writers}
}

// Init initializes every target with the same configuration. Targets with
// distinct configurations should be initialized before NewMultiWriter.
func (m *MultiWriter) Init(cfg plugintypes.AuditLogConfig) error {
	var errs []error
	for i, w := range m.writers {
		if w == nil {
			continue
		}
		if err := w.Init(cfg); err != nil {
			errs = append(errs, fmt.Errorf("audit target %d init: %w", i, err))
		}
	}
	return errors.Join(errs...)
}

// Write delivers al once to every target and joins all target errors.
func (m *MultiWriter) Write(al plugintypes.AuditLog) error {
	var errs []error
	for i, w := range m.writers {
		if w == nil {
			continue
		}
		if err := w.Write(al); err != nil {
			errs = append(errs, fmt.Errorf("audit target %d: %w", i, err))
		}
	}
	return errors.Join(errs...)
}

// Close closes all targets and joins their errors.
func (m *MultiWriter) Close() error {
	var errs []error
	for i, w := range m.writers {
		if c, ok := w.(interface{ Close() error }); ok {
			if err := c.Close(); err != nil {
				errs = append(errs, fmt.Errorf("audit target %d close: %w", i, err))
			}
		}
	}
	return errors.Join(errs...)
}

var _ plugintypes.AuditLogWriter = (*MultiWriter)(nil)
