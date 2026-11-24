# ADR-0063: Atomic versioned ruleset and redaction releases

- **Status:** proposed
- **Date:** 2026-11-25 (expected)
- **Version:** unreleased
- **PR:** Not opened yet; implementation prepared in the task workspace
- **Issue(s):** No linked issue
- **Deciders:** Pending maintainer review
- **Category:** Feature

## Context and Problem

Audit retention and rule updates need to describe the same decision. Updating SecLang
rules in place can let a request evaluate a half-parsed or partially replaced
`RuleGroup`; updating redaction separately can apply a new field list to an
in-flight transaction. Audit records then cannot reliably state which rule set
matched the request or which redaction policy protected the stored bytes.

The required unit of release is therefore a paired bundle: complete rule content,
logical ruleset identifier, caller-supplied revision and field-level redaction
manifest. A rejected bundle must leave the previous service version active without
consuming or reusing its monotonic release identifier.

## Decision Drivers

- A transaction must observe exactly one release from rule evaluation through audit
  serialization.
- Publishing may serialize compilations, but request evaluation must not take a new
  global mutex.
- Existing `coraza.NewWAF`, transaction construction, configuration and audit APIs
  must remain source-compatible; the capability is optional.
- Existing audit JSON/native/legacy/OCSF gold samples must remain unchanged when no
  release is installed.
- Redaction must happen before built-in or custom audit formatters/writers receive
  the record.
- The implementation must remain pure Go and usable with `no_fs_access`/TinyGo-style
  constraints; release bundles are self-contained strings and manifests.

## Considered Options

1. **Mutate the active `WAF.Rules` value after parsing into the live WAF.** Rejected:
   parsing has directive side effects, failed parsing can leave partial state, and
   transactions that already loaded the rule group could observe replacement midway.
2. **Add a global RWMutex around every rule phase and audit write.** Rejected: this
   makes the request hot path contend with publishing and violates the no-global-wait
   constraint.
3. **Compile a candidate WAF and atomically publish an immutable `Release` snapshot.**
   Chosen: `WAF` stores an `atomic.Value`; each transaction performs one load at
   construction and then uses that release's `RuleGroup`, directive-derived settings
   and redaction policy for its whole lifetime. Publishing takes a separate mutex only
   to allocate the next monotonic sequence and commit the pointer.

## Decision Outcome

Chosen: **option 3**.

A `Release` contains the monotonic sequence, readable `rN` identifier, logical
ruleset ID, paired source revision, compiled `RuleGroup`, redaction policy and the
throwaway candidate WAF that owns directive-derived defaults. `PublishRelease`
validates the pair, compiles SecLang into the candidate, validates the candidate and
compiles the redaction policy before `CommitRelease`. Any error returns before the
atomic pointer changes.

Transactions store the selected `*Release`. Rule evaluation calls a small
`tx.evalRules` helper that uses the snapshot when present and otherwise preserves the
historical `tx.WAF.Rules.Eval` path. Audit construction adds the same release object
to the record header, matched-rule entries/data and producer trailer. New JSON fields
are `omitempty`, so records without versioned releases remain byte-compatible.

Redaction is applied to the concrete `auditlog.Log` before the writer is called:
header/response-header maps, URI query pairs, URL-encoded bodies, JSON and XML
bodies, multipart bodies, the `ARGS` view exposed to custom formatters, match
messages/data and error text. Sensitive matched fields are also masked in the debug
`arg` field and in the `MatchedRule` copy passed to error callbacks. The original
transaction match data remains available through the existing in-process API.

A small `MultiWriter` fans one already-redacted `AuditLog` value to multiple targets;
one target error is joined with target context and does not prevent other writes.

## Technical Discussion

No substantive technical discussion recorded beyond the task requirements and the
repository guidance in `AGENTS.md`; no external PR comment exists to quote.

## Participants

- KeiMo7 — workspace owner
- Claude Code — implementation and verification assistant

## Consequences

- **Positive:** atomic rollback/forward behavior; in-flight requests finish on their
  captured release; every audit section can carry one release ID; failed publishes do
  not alter rule count, version or redaction behavior.
- **Positive:** the request hot path adds one pointer field/load and no publish lock.
- **Negative / follow-up:** callers that want runtime releases must opt into the new
  `coraza.ReleaseManager` surface; there is intentionally no automatic filesystem
  polling or remote fetch in this change.
- **Negative / follow-up:** raw unknown body formats cannot be field-selected
  structurally; selected collection values are still swept from match/error text, but
  operators should use the matching JSON/XML/urlencoded/multipart container selectors.
- **Compatibility:** when no release is published, `release == nil` and the old rule,
  audit and formatting paths are retained.

## References

- Related ADRs: ADR-0035 (`WAFWithRules`), ADR-0043 (WAF close/memoizer ownership)
