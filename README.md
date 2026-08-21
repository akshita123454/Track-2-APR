# Core Innovation 1 — Evidence-First Blast Radius Analysis

## The Challenge

A vulnerable package can affect many services through deeply nested, transitive dependencies. A normal package scanner may say that a package name exists somewhere, but it often cannot answer the questions an incident responder actually needs:

```text
Which exact version is involved?
Which internal service is exposed?
Which dependency path proves the connection?
Is the result supported by real evidence?
Is the analysis complete or limited by missing data?
```

This is why a flat package list is not enough. Supply-chain exposure is a graph problem.

## Our Approach

HydraGuard performs deterministic reverse traversal over the persisted HydraDB dependency graph:

```text
Incident
→ Affected PackageVersion
→ Reverse Dependency Paths
→ Applications and Services
```

Every affected result is returned with an explainable proof path:

```text
Compromised Package Version
← Exact Resolved Dependency
← Application or Repository
← Internal Service
```

Instead of returning only “package found,” HydraGuard reconstructs **how the risk travelled** and where it reached.

## Technical Depth

- Exact package-version identities instead of package-name-only matching
- npm and lockfile-aware dependency ingestion
- Reverse dependency traversal from compromised version to affected service
- Deterministic path ordering for reproducible results
- Bounded traversal depth, fan-out, total paths, and traversal states
- Canonical dependency relationships as the source of truth
- Derived reverse relationships that cannot fabricate evidence
- Explicit warnings when a path is missing, incomplete, or truncated
- Evidence Funnel stages that separate structural candidates from stronger evidence
- Immutable graph inputs, ensuring analysis never alters original incident facts

## Security Result

HydraGuard helps teams distinguish these very different statements:

```text
“This package appears in a dependency graph.”
```

```text
“This exact malicious version was resolved through this verified path
and reached this internal service.”
```

That distinction reduces false alarms, improves explainability, and gives responders a defensible starting point for containment.

## Why It Matters

HydraGuard gives responders an answer they can inspect and act upon:

> “This service is affected because it resolved this exact version through this dependency path, supported by this evidence.”

This is stronger than an alert that only says a package name was found. It transforms package scanning into graph-backed incident investigation.

---

# Core Innovation 2 — Evidence-Backed Typosquat Radar

## The Challenge

Typosquatting is dangerous because attackers use package names that visually imitate trusted dependencies. However, name similarity alone does not prove malicious intent or real exposure.

Traditional typosquat detectors often generate too many alerts because they treat every similar-looking package as equally dangerous. This creates alert fatigue and makes analysts less likely to trust the system.

For example:

```text
A package may look similar to a trusted package,
but it may not be installed, resolved, or used at all.
```

## Our Approach

HydraGuard detects suspicious naming patterns through multiple transformation classes:

```text
Adjacent transposition
Insertion
Deletion
Substitution
Separator variation
Repeated characters
Scope impersonation
Unicode confusables
Prefix and suffix variation
```

But similarity is only the first signal. HydraGuard uses an evidence gate:

```text
Suspicious Name
→ Candidate Finding
→ Evidence Verification
→ Lockfile / Resolution Proof
→ Confirmed or Dismissed
```

A package is not elevated to confirmed exposure merely because its name looks suspicious. The graph must show meaningful supporting evidence, such as an actual lockfile resolution or environment relationship.

## Technical Depth

- Multiple typo and impersonation transformation classes
- Candidate, suspicious, verified, confirmed, and dismissed states
- Lockfile-aware resolution evidence
- Evidence-linked graph findings instead of isolated text scores
- Maintainer and infrastructure relationships for additional context
- Clear separation between suspicion and confirmed exposure
- Idempotent analyst-review workflows
- Structured evidence records for analyst decisions
- Fail-closed handling when required validation data is missing

## Security Result

HydraGuard separates:

```text
“This package name looks suspicious.”
```

from:

```text
“This suspicious package was actually resolved in our environment
and requires investigation.”
```

This reduces false alarms while preserving potentially important supply-chain signals.

## Why It Matters

The Typosquat Radar makes the system more practical for real teams. It does not overwhelm analysts with every similar name; it prioritizes candidates that have evidence of real relevance to the environment.

---

# Core Innovation 3 — Wave 2 Authority Propagation

## The Challenge

The impact of a compromised package may not stop at the immediate application or service.

If a compromised package reaches a workflow, build environment, or service, it may potentially expose:

```text
Credentials
Sensitive permissions
Publishing authority
Cloud-connected capabilities
Other packages sharing the same authority path
```

Most dependency tools stop after identifying affected services. They do not investigate the next question:

> “What sensitive authority could become reachable from this compromise path?”

## Our Approach

HydraGuard adds a second graph-analysis layer called **Wave 2 Authority Propagation**:

```text
Compromised Package
→ Affected Service or Workflow
→ Credential
→ Authority or Capability Target
```

Wave 2 extends dependency blast radius into authority and capability analysis. It helps teams understand the potential next stage of a supply-chain incident.

## Technical Depth

- First-class authority and capability graph entities
- Deterministic bounded traversal across authority paths
- Evidence-aware propagation from affected software to sensitive capabilities
- Candidate-only conclusions to avoid claiming unproven exploitation
- Explicit distinction between direct dependency exposure and authority exposure
- Controlled cycle handling and excessive fan-out protection
- Traversal, target, path, warning, and state limits
- Explicit truncation reporting rather than hidden incomplete analysis
- Immutable source graph and reproducible results
- Persisted graph readers and evidence validation before returning results

## Security Result

HydraGuard distinguishes:

```text
“An attacker definitely used this credential.”
```

from:

```text
“This evidence-backed graph path shows that this credential or authority
may be reachable and should be investigated or contained.”
```

This is an important security discipline: the system surfaces meaningful risk without overstating certainty.

## Why It Matters

HydraGuard answers both:

> “Which services are affected?”

and:

> “What credentials, permissions, publishing paths, or sensitive authority may become reachable through the affected path?”

This gives responders a wider and more realistic view of supply-chain risk than dependency analysis alone.

---

# Core Innovation 4 — Universal Release Influence Firewall

## The Challenge

A release can be published using valid OIDC and a trusted workflow while still being unsafe.

For example:

```text
Untrusted Pull Request
→ Untrusted Workflow
→ Shared Cache
→ Trusted Release Workflow Restores Cache
→ Compromised Artifact
→ Valid OIDC Publishes Release
```

The final publisher identity is trusted, but the published artifact was influenced by an unsafe path.

Traditional tools often focus on the end of the release process:

```text
Was the publisher trusted?
Was OIDC valid?
Was the release signed?
```

HydraGuard asks the deeper question:

```text
What influenced the artifact before it was published?
```

## Our Approach

HydraGuard introduces the **Universal Release Influence Firewall**.

Before a release is trusted, the firewall traces the full causal path:

```text
Source Change
→ Workflow Run
→ Cache Entry
→ Build
→ Credential
→ Attestation
→ Artifact
→ Published Release
```

It then returns one explainable decision:

| Verdict | Meaning | Action |
|:---:|---|---|
| `ALLOW` | Trusted and evidence-backed influence path | Release may proceed |
| `QUARANTINE` | Missing, unknown, or incomplete evidence | Hold for review |
| `BLOCK` | Untrusted influence reached the release path | Prevent publication |

## What the Firewall Detects

- Untrusted source-change influence
- Untrusted workflow influence
- Untrusted graph relationships
- Shared-cache poisoning across trust boundaries
- Unknown cache trust boundaries
- Missing node or relationship evidence
- Missing artifact-publication paths
- Unsafe causal paths despite valid OIDC
- Malformed or inconsistent release graphs
- Traversal truncation and incomplete influence visibility

## Technical Depth

- Universal ecosystem model: npm, PyPI, Maven, internal registries, and future ecosystems
- Strongly typed release, workflow, cache, artifact, credential, and attestation entities
- Deterministic bounded backward causal traversal
- `ALLOW`, `QUARANTINE`, and `BLOCK` verdicts
- Fail-closed unknown-trust and missing-evidence behavior
- Immutable input graph and immutable decision results
- Dedicated HydraDB release-influence snapshots
- Snapshot lifecycle: `writing → ready` or `failed`
- Duplicate snapshot protection and bounded node/edge limits
- Strict stored-data validation for schema, IDs, trust values, JSON, and graph integrity
- Persisted API endpoint for verified firewall evaluation
- Redacted API errors for missing, corrupt, unavailable, or incomplete snapshot data

## Key Security Principle

```text
Trusted publisher identity ≠ trusted artifact
```

A valid OIDC token cannot make an unsafe build path safe.

## Security Result

The firewall moves the security model from:

```text
Detect compromised packages after publication
```

to:

```text
Evaluate influence before publication
→ Allow trusted release
→ Quarantine uncertain release
→ Block unsafe release
```

## Why It Matters

The Release Influence Firewall is designed to prevent a TanStack-style cache-poisoning path from being treated as safe merely because the final release used valid OIDC.

It gives teams an explainable publish-gate decision and shows the exact unsafe causal path that led to the verdict.

---
