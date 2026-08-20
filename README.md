<div align="center">

# HydraGuard

### The Graph-Native Supply Chain Firewall & Defense Platform

**Evidence-first · HydraDB-powered · Fail-closed by design**

> **Trace the blast. Expose authority. Block poisoned releases.**

</div>

---

## 🎥 Demo Video

> **YouTube Demo:** [Add your YouTube video link here](YOUR_YOUTUBE_DEMO_LINK)

> **Live Dashboard / Evidence Console:** [Add dashboard link here](YOUR_DASHBOARD_LINK)

---

# The Problem We Are Solving

Modern applications depend on hundreds or thousands of third-party packages. When one package is compromised, typosquatted, or published through an unsafe build pipeline, security teams must answer difficult questions immediately:

1. Which **exact versions** are affected?
2. Which internal applications and services depend on them?
3. Through which dependency path did the risk spread?
4. Which findings are supported by real evidence, and which are only possible paths?
5. Could the compromise reach credentials, publishing access, or other sensitive authority?
6. What is the fastest and safest action to stop further spread?
7. Can a release be stopped **before** it reaches users?

Most existing tools solve only one part of this problem. They scan a manifest, match a package name against a vulnerability list, and produce an alert. They usually do not provide the full evidence-backed chain from package to service, service to authority, or unsafe build input to published artifact.

HydraGuard solves this as one connected **HydraDB security graph**.

```text
Package → Version → Dependency → Application → Service
                                      ↓
                         Workflow → Credential → Authority
                                      ↓
Source Change → Cache → Build → Artifact → Release
```

Instead of giving an unexplained risk score, HydraGuard shows the **exact path, evidence, impact, and response options**.

---

# Our Solution

HydraGuard is a graph-native software supply-chain security platform built on HydraDB. It brings together:

- Exact package and lockfile ingestion
- Dependency blast-radius analysis
- Evidence-backed path verification
- Typosquatting detection
- Authority and credential reachability analysis
- Immutable containment simulation
- Pre-publication Release Influence Firewall
- Explainable Fastify APIs and a visual dashboard

Our approach is not multiple disconnected mini-projects. Each capability is part of one security lifecycle:

```text
Detect suspicious package
→ Trace affected services
→ Verify evidence
→ Discover reachable authority
→ Simulate containment
→ Prevent unsafe release publication
```

---

# Why HydraDB Is Essential

HydraDB is not used only as storage. It is the central reasoning engine of HydraGuard.

We use HydraDB to store and connect:

```text
Packages, exact package versions, lockfiles, dependencies, services,
incidents, maintainers, evidence, workflows, caches, builds, artifacts,
credentials, permissions, authority paths, and releases.
```

This graph structure lets HydraGuard answer questions that flat package lists cannot answer:

```text
What was affected?
How was it reached?
Which exact path proves the relationship?
What evidence supports the path?
Which authority could become reachable?
What containment action reduces the exposure?
Why was a release allowed, quarantined, or blocked?
```

HydraDB enables us to perform graph-native traversal across dependency, evidence, authority, and release-influence relationships. It turns fragmented supply-chain data into one explainable security model.

---

# Core Innovation 1 — Evidence-First Blast Radius

## Problem

A compromised package may affect a service through many indirect dependencies. A simple vulnerability scan can say that a package exists, but it often cannot prove:

```text
Which service is affected?
Which exact package version is involved?
Which dependency path connects them?
What evidence supports the result?
```

## Our Approach

HydraGuard performs deterministic reverse graph traversal:

```text
Incident
→ Affected PackageVersion
→ Reverse dependency paths
→ Applications and Services
```

For every affected service, HydraGuard returns an explainable proof path instead of an opaque score.

```text
Compromised Version
← Dependency
← Application
← Service
```

## Technical Depth

- Exact package-version graph nodes
- Lockfile-aware dependency information
- Deterministic traversal order
- Bounded depth, fan-out, path, and state limits
- Canonical dependency relationships
- Warnings when analysis is incomplete or truncated
- Evidence Funnel to separate possible paths from verified paths

## Why It Matters

A security responder does not need only an alert. They need a defensible answer:

> “This service is affected because it resolved this exact version through this dependency path, supported by this evidence.”

---

# Core Innovation 2 — Evidence-Backed Typosquat Radar

## Problem

Package names that look similar are not automatically malicious. Basic typo detectors create too many false positives, causing analysts to ignore alerts.

## Our Approach

HydraGuard detects suspicious package names through multiple transformation patterns, including:

```text
Adjacent transposition
Insertion
Deletion
Substitution
Separator variation
Repeated characters
Scope impersonation
Unicode confusables
Prefix and suffix variations
```

However, name similarity alone is never treated as confirmed compromise.

HydraGuard uses an evidence gate:

```text
Suspicious name
→ Candidate
→ Evidence verification
→ Lockfile / resolution proof
→ Confirmed or dismissed finding
```

## Why It Matters

This separates:

```text
“This package looks suspicious”
```

from:

```text
“This suspicious package was actually resolved inside the environment”
```

That difference reduces alert fatigue and makes the output useful during real investigation.

---

# Core Innovation 3 — Wave 2 Authority Propagation

## Problem

A compromised dependency can be more dangerous than its immediate blast radius.

If a compromised package reaches a build workflow, service, or repository, it may also reach:

```text
Credentials
Sensitive permissions
Publishing access
Cloud capabilities
Operational authority
```

Traditional dependency scanners usually stop after reporting affected packages or services. They do not ask what sensitive access may become reachable next.

## Our Approach

HydraGuard adds a second analysis layer called **Wave 2 Authority Propagation**.

```text
Compromised Package
→ Affected Service or Workflow
→ Credential
→ Capability or Authority Target
```

This helps security teams investigate the next possible stage of an attack.

## Technical Depth

Wave 2 is intentionally designed to avoid overstating risk:

- Candidate authority paths are not claimed as proven exploitation
- Evidence is validated before conclusions are presented
- Traversal is deterministic and bounded
- Cycles and excessive fan-out are controlled
- Missing evidence is not silently treated as safety
- Truncation and uncertainty are explicitly surfaced
- Original graph inputs remain immutable

## Why It Matters

HydraGuard answers not only:

> “Which services are affected?”

but also:

> “What authority, credentials, or sensitive capability may become reachable through the affected path?”

This transforms package scanning into a more complete supply-chain security investigation.

---

# Core Innovation 4 — Universal Release Influence Firewall

## Problem

A release can be published by a trusted workflow with valid OIDC and still be unsafe.

For example:

```text
Untrusted pull request
→ Untrusted workflow
→ Shared build cache
→ Trusted release workflow restores cache
→ Compromised build artifact
→ Valid OIDC publishes release
```

The publishing identity is valid, but the artifact was influenced by an unsafe path.

Traditional tools often inspect the package only after publication. By then, downstream users may already be exposed.

## Our Approach

HydraGuard introduces a **Universal Release Influence Firewall**.

Before a release is trusted, the firewall traces backwards through the complete causal path:

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

The firewall returns one of three explainable decisions:

| Verdict | Meaning | Action |
|:---:|---|---|
| `ALLOW` | Trusted and evidence-backed causal path | Release may proceed |
| `QUARANTINE` | Missing, unknown, or incomplete evidence | Hold for review |
| `BLOCK` | Untrusted influence reached the release | Prevent publication |

## What It Detects

- Untrusted workflow influence
- Untrusted source changes
- Shared-cache poisoning across trust boundaries
- Missing artifact publication paths
- Missing or unknown evidence
- Invalid graph relationships
- Unsafe causal paths even when final OIDC is valid

## Key Security Principle

```text
Trusted publisher identity ≠ trusted artifact
```

A valid OIDC token cannot override an unsafe build or cache influence path.

## Why It Matters

The firewall is designed to move supply-chain security from:

```text
Detect after publication
```

to:

```text
Prevent before publication
```

It supports arbitrary ecosystems, including npm, PyPI, Maven, internal registries, and future package ecosystems.

---

# Fastest Path to Stop the Spread

HydraGuard does not only identify risk. It helps responders understand the quickest and most effective place to break the attack path.

The platform combines:

```text
Blast Radius
+ Evidence Verification
+ Authority Propagation
+ Containment Simulation
```

Containment actions are evaluated as immutable graph overlays:

```text
Original evidence graph
+ proposed containment action
= simulated remaining exposure
```

This lets teams compare actions such as:

- Isolating an affected service
- Blocking a dependency relationship
- Revoking or removing a sensitive credential path
- Breaking a high-impact authority connection
- Quarantining an unsafe release

The original evidence graph is never modified. Analysts can compare before-and-after exposure safely and choose the most direct response path.

> HydraGuard is designed to help teams stop further spread quickly while preserving the evidence needed for investigation.

---

# Fail-Closed by Design

Supply-chain security is dangerous when unknown information is treated as safe.

HydraGuard follows fail-closed principles:

- Missing evidence does not become trusted evidence
- Unknown trust boundaries do not become safe boundaries
- Corrupt graph data is rejected
- Incomplete release paths are quarantined
- Traversal limits are reported explicitly
- Candidate authority paths are not presented as confirmed compromise
- Derived graph relationships cannot fabricate evidence
- Containment simulations never rewrite original evidence

This makes HydraGuard useful for security decisions where uncertainty must be visible, not hidden.

---

# HydraDB-Powered Security Lifecycle

```text
1. Collect
   Package metadata, lockfiles, incidents, evidence, and release signals

2. Persist
   Store stable nodes and evidence-backed relationships in HydraDB

3. Analyse
   Trace dependency blast radius and verify path evidence

4. Propagate
   Discover possible credential and authority reachability

5. Prevent
   Evaluate release influence before publication

6. Contain
   Compare response actions against the immutable evidence graph
```

---

# Dashboard and Demonstration

The HydraGuard Evidence Console presents the security graph in a simple, visual format.

## Planned / Demonstrated Dashboard Views

| View | Purpose |
|---|---|
| Incident Overview | Show affected package versions and incident details |
| Blast Radius | Show services and dependency proof paths |
| Evidence Funnel | Separate structural candidates from verified evidence |
| Typosquat Radar | Show suspicious package candidates and evidence status |
| Wave 2 Authority | Show possible credential and authority reachability |
| Release Firewall | Show `ALLOW`, `QUARANTINE`, and `BLOCK` verdicts |
| Containment | Compare response actions and remaining exposure |
| Proof & Validation | Show deterministic checks and security guarantees |

> **Dashboard link:** [Add dashboard URL here](YOUR_DASHBOARD_LINK)
> **YouTube demo:** [Add demo video here](YOUR_YOUTUBE_DEMO_LINK)

---

# Technical Architecture

```text
┌───────────────────────────────────────────────┐
│          HydraGuard Dashboard (React)          │
│  Incidents · Evidence · Paths · Firewall       │
└──────────────────────┬────────────────────────┘
                       │ REST API
┌──────────────────────▼────────────────────────┐
│           HydraGuard API (Fastify)             │
│ Ingest · Analyse · Propagate · Prevent · Contain│
└───────────┬─────────────────────┬──────────────┘
            │                     │
            │ Graph Driver        │ Package Metadata
┌───────────▼─────────────┐  ┌────▼─────────────┐
│         HydraDB         │  │   npm Registry    │
│  Evidence Security Graph│  │  Package Metadata │
└─────────────────────────┘  └──────────────────┘
```

## Graph Entities

```text
Package
PackageVersion
Service
Maintainer
Incident
Evidence
LockfileSnapshot
WorkflowRun
CacheEntry
Build
Credential
Artifact
Release
```

## Important Graph Relationships

```text
DEPENDS_ON
USED_BY
AFFECTS
MAINTAINS
SUPPORTS
RESOLVED_IN
RELEASE_INFLUENCE
```

---

# Tech Stack

```text
HydraDB Graph Database
Cypher Graph Query Language
TypeScript
JavaScript
Node.js
Fastify
React
Vite
Neo4j JavaScript Driver
REST APIs
JSON Schema
npm Registry API
npm Lockfile Parsing
Semantic Versioning (SemVer)
Graph Data Modeling
Deterministic Bounded Graph Traversal
HTML5
CSS3
TSX
Git and GitHub
```

---

# Validation

HydraGuard includes dedicated validation for key security behaviors.

```powershell
npm run typecheck --prefix "apps/api"
npm run validate:release-firewall --prefix "apps/api"
npm run validate:release-persistence --prefix "apps/api"
npm run validate:server --prefix "apps/api"
npm run validate:wave2 --prefix "apps/api"
npm run validate:containment --prefix "apps/api"
```

The Release Influence Firewall validation verifies that:

- npm, PyPI, and Maven releases can be evaluated together
- Fully trusted releases can be allowed
- Cross-boundary cache poisoning is blocked
- Valid OIDC does not override unsafe causal paths
- Missing or unknown influence is quarantined
- Malformed graphs are rejected
- Traversal limits are surfaced
- Source graphs remain immutable

---

# Running HydraGuard

## Quick Dashboard Demo

```bash
npm run demo
```

Then open:

```text
http://localhost:5173
```

## Full Local Stack

1. Install dependencies:

```bash
npm run setup
```

2. Create environment configuration:

```bash
cp .env.example .env
```

3. Add HydraDB connection settings to `.env`.

4. Start the API:

```bash
npm run api
```

5. Start the dashboard:

```bash
npm run demo
```

6. Verify API health:

```text
http://localhost:3000/health
http://localhost:3000/ready
```

---

# Team Contributions

## Akshita

- Developed the core dependency blast-radius analysis
- Implemented typosquatting detection
- Built the dashboard and visual security experience
- Contributed to incident analysis, graph integration, and user-facing explanation

## Pratik Raj

- Designed and implemented Wave 2 Authority Propagation
- Designed and implemented the Universal Release Influence Firewall
- Added immutable release-influence snapshots in HydraDB
- Implemented persisted firewall API contracts, strict validation, error handling, and smoke tests
- Contributed to containment and graph-security validation

---

# HydraGuard

> **Detection tells you that a package may be dangerous.**
> **HydraGuard shows what it reached, what evidence proves it, what authority may be exposed, and whether the next unsafe release should be blocked before it ships.**

**Evidence-first · Graph-native · Fail-closed**
