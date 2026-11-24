// Copyright 2025 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/auditlog"
)

// NewMultiAuditLogWriter fans one already-redacted audit record out to multiple
// targets. Each target's Write method is called exactly once per transaction;
// one failing target does not stop the others.
func NewMultiAuditLogWriter(writers ...plugintypes.AuditLogWriter) plugintypes.AuditLogWriter {
	return auditlog.NewMultiWriter(writers...)
}
