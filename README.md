<div align="center">

# HydraGuard

### The Graph-Native Supply Chain Firewall & Defense Platform

**Built on HydraDB · Evidence-First · Fail-Closed by Design**

> **Trace the blast. Verify the evidence. Expose authority. Block poisoned releases.**

</div>

---

# The Supply-Chain Problem We Are Solving

A modern software application is not built from one codebase. It is built from a large chain of external packages, exact resolved versions, lockfiles, maintainers, CI workflows, build caches, artifacts, credentials, and release pipelines.

When one package is compromised, typosquatted, or published through an unsafe build process, security teams need immediate answers:

1. Which **exact package versions** are affected?
2. Which applications and services depend on those versions?
3. Through which dependency path did the risk spread?
4. Which paths are supported by real evidence?
5. Which credentials, permissions, or sensitive capabilities may become reachable next?
6. What direct containment action can reduce the exposure fastest?
7. Can an unsafe release be blocked **before it is published**?

Most tools solve only one small part of this problem. They scan a manifest, match a package name against a known advisory, and produce an alert. They often cannot prove the full path from a compromised package to an internal service, cannot distinguish a suspicious possibility from evidence-backed exposure, and do not inspect the causal history of a release before publication.

HydraGuard solves this as one connected **HydraDB security graph**.

```text
Package → Exact Version → Dependency → Application → Service
                                         ↓
                         Workflow → Credential → Authority
                                         ↓
Source Change → Cache → Build → Artifact → Published Release
```

Instead of an unexplained risk score, HydraGuard returns the path, evidence, impact, uncertainty, and response options.

---

# What We Built

HydraGuard is a graph-native software supply-chain defense platform built on HydraDB.

It combines:

- Exact package and lockfile ingestion
- Dependency blast-radius analysis
- Evidence-backed path verification
- Typosquatting detection
- Wave 2 authority propagation
- Immutable containment simulation
- Universal Release Influence Firewall
- Fastify APIs and a React evidence dashboard

Our solution is not a collection of unrelated features. Every capability is part of a single security lifecycle:

```text
Detect suspicious package
→ Trace affected services
→ Verify evidence
→ Investigate reachable authority
→ Compare containment actions
→ Prevent unsafe release publication
```

This allows HydraGuard to support security teams before, during, and after a supply-chain incident.

---

# Why HydraDB Is Central to HydraGuard

HydraDB is not used as a simple storage layer. It is the **security memory and graph reasoning foundation** of the entire platform.

HydraGuard stores and connects:

```text
Packages, package versions, lockfiles, dependencies, services,
incidents, maintainers, evidence, workflows, caches, builds,
artifacts, credentials, authority paths, and releases.
```

HydraDB enables HydraGuard to answer graph-native questions:

```text
What was affected?
How did the dependency path reach a service?
What evidence supports that path?
What authority may become reachable after compromise?
Which release input influenced the final artifact?
Which containment action breaks the most relevant path?
```

A supply-chain incident is a connected chain of cause and impact, not an isolated database record. HydraDB lets us preserve that chain and explain it clearly.

---

# Core Innovation 1 — Evidence-First Blast Radius Analysis

## The Challenge

A vulnerable package can affect a service through multiple transitive dependencies. A normal package scanner may say that a package exists, but it cannot always show:

```text
Which exact version is involved?
Which service is exposed?
Which dependency path proves it?
What evidence supports the finding?
```

## Our Approach

HydraGuard performs deterministic reverse traversal over the HydraDB dependency graph:

```text
Incident
→ Affected PackageVersion
→ Reverse Dependency Paths
→ Applications and Services
```

Each impacted service is returned with an explainable path:

```text
Compromised Package Version
← Dependency
← Application
← Internal Service
```

## Technical Depth

- Exact package-version identities
- npm and lockfile-aware dependency ingestion
- Reverse dependency traversal
- Deterministic path ordering
- Bounded traversal depth, fan-out, paths, and states
- Canonical dependency relationships
- Explicit truncation and warning reporting
- Evidence Funnel for path confidence analysis

## Why It Matters

HydraGuard gives responders a defensible answer:

> “This service is affected because it resolved this exact version through this dependency path, supported by this evidence.”

This is stronger than an alert that only says a package name was found.

---

# Core Innovation 2 — Evidence-Backed Typosquat Radar

## The Challenge

Name similarity alone does not prove malicious intent. Traditional typosquat detectors frequently produce noisy alerts, leading analysts to ignore them.

For example:

```text
A package may look similar to a trusted package,
but it may not be used by the organisation at all.
```

## Our Approach

HydraGuard detects suspicious naming patterns such as:

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

However, similarity is only the beginning. HydraGuard applies an evidence gate:

```text
Suspicious Name
→ Candidate Finding
→ Evidence Verification
→ Lockfile / Resolution Proof
→ Confirmed or Dismissed
```

A similar-looking package is not treated as confirmed exposure unless the environment has actually resolved or used it.

## Why It Matters

HydraGuard separates:

```text
“This name looks suspicious.”
```

from:

```text
“This suspicious package was actually resolved in our environment.”
```

This reduces false alarms and gives analysts a more trustworthy signal.

---

# Core Innovation 3 — Wave 2 Authority Propagation

## The Challenge

The damage from a compromised package may not stop at the package or immediate service.

A compromise can potentially move through workflows or services to reach:

```text
Credentials
Sensitive permissions
Publishing access
Operational capabilities
Cloud-connected authority
```

Most dependency tools stop after identifying affected packages or services. They do not investigate what sensitive authority may become reachable next.

## Our Approach

HydraGuard adds a second graph-analysis layer called **Wave 2 Authority Propagation**:

```text
Compromised Package
→ Affected Service or Workflow
→ Credential
→ Authority or Capability Target
```

This creates a broader view of supply-chain risk.

## Technical Depth

Wave 2 Authority Propagation was designed carefully to avoid false claims:

- Authority paths are treated as candidates, not automatic proof of exploitation
- Evidence validation is required
- Traversal is deterministic and bounded
- Cycles and excessive fan-out are controlled
- Missing evidence is visible
- Truncation is reported explicitly
- Source graph inputs remain immutable

## Why It Matters

HydraGuard answers not only:

> “Which services are affected?”

but also:

> “What credentials, permissions, or authority may become reachable through the affected path?”

This is a major extension beyond normal dependency scanning.

---

# Core Innovation 4 — Universal Release Influence Firewall

## The Challenge

A release can be published using valid OIDC and a trusted workflow, while still being unsafe.

For example:

```text
Untrusted Pull Request
→ Untrusted Workflow
→ Shared Cache
→ Trusted Release Workflow Restores Cache
→ Compromised Artifact
→ Valid OIDC Publishes Release
```

The publisher identity is valid, but the artifact was influenced by an unsafe path.

Many tools inspect the final package only after publication. By then, downstream users may already have installed it.

## Our Approach

HydraGuard introduces a **Universal Release Influence Firewall**.

Before a release is trusted, HydraGuard traces its full causal history:

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

The firewall returns an explainable decision:

| Verdict | Meaning | Action |
|:---:|---|---|
| `ALLOW` | Trusted and evidence-backed causal path | Release may proceed |
| `QUARANTINE` | Unknown, missing, or incomplete evidence | Hold for review |
| `BLOCK` | Untrusted influence reached the release | Prevent publication |

## What the Firewall Detects

- Untrusted source-change influence
- Untrusted workflow influence
- Shared-cache poisoning across trust boundaries
- Missing artifact-publication paths
- Unknown trust boundaries
- Missing evidence
- Malformed release graphs
- Unsafe causal paths even when final OIDC is valid

## Key Security Principle

```text
Trusted publisher identity ≠ trusted artifact
```

A valid OIDC token cannot make an unsafe build path safe.

## Why It Matters

The Release Influence Firewall shifts the security model from:

```text
Detect compromised packages after publication
```

to:

```text
Prevent unsafe releases before publication
```

It supports arbitrary ecosystems, including npm, PyPI, Maven, internal registries, and future ecosystems.

---

# Direct Containment Path Analysis

Detection is valuable, but responders also need to know where to act first.

HydraGuard uses the dependency path, evidence context, and authority relationship to help teams identify direct places where containment can reduce further spread.

Examples include:

```text
Isolate an affected service
Block a dependency path
Quarantine an unsafe release
Remove a risky authority connection
Disable access linked to a suspicious workflow
```

The containment engine uses immutable overlays:

```text
Original Evidence Graph
+ Proposed Containment Directive
= Simulated Remaining Exposure
```

This means teams can compare containment choices without changing the original evidence graph.

HydraGuard does not claim that every result is a guaranteed optimal answer. Instead, it provides an explainable and safe way to compare response paths and identify high-value actions quickly.

---

# Fail-Closed Security Principles

HydraGuard is designed so that missing information is never silently treated as safety.

- Missing evidence does not become trusted evidence
- Unknown trust boundaries do not become safe boundaries
- Corrupt graph data is rejected
- Incomplete release paths are quarantined
- Traversal limits are reported
- Candidate authority paths are not presented as confirmed exploitation
- Derived relationships cannot fabricate evidence
- Containment simulations never modify original evidence

This makes uncertainty visible to responders instead of hiding it behind a simple risk score.

---

# Research Positioning and Broader Scope

During our research and implementation period, we studied dependency-exposure and supply-chain security approaches that focus primarily on package detection, manifest scanning, or dependency reachability.

HydraGuard intentionally broadens this scope.

Instead of focusing on only one company, one application, or one package ecosystem, our graph model is designed around reusable entities and relationships:

```text
Any package ecosystem
Any number of packages
Any number of services
Any number of dependency paths
Any release pipeline
Any evidence source
```

Our contribution is not a claim that existing research is incorrect. Instead, HydraGuard extends the security conversation by combining several layers that are often handled separately:

| Security Need | HydraGuard Approach |
|---|---|
| Dependency exposure | Exact version-level graph traversal |
| False-positive reduction | Evidence Funnel and lockfile-aware verification |
| Shared-risk investigation | Authority and infrastructure relationships |
| Operational impact | Wave 2 authority propagation |
| Response planning | Immutable containment simulation |
| Release prevention | Pre-publication Release Influence Firewall |
| Explainability | Evidence-backed graph paths, not opaque scores |

Within a short hackathon build period, our goal was to demonstrate a broader, practical, and technically defensible graph-security architecture—not to make unsupported benchmark claims.

---

# Security Lifecycle in HydraGuard

```text
1. Collect
   Package metadata, lockfiles, incidents, evidence, and release signals

2. Persist
   Store stable graph entities and relationships in HydraDB

3. Analyse
   Trace dependency blast radius and verify supporting evidence

4. Investigate
   Discover possible authority and credential reachability

5. Prevent
   Evaluate release influence before publication

6. Contain
   Compare response actions against an immutable evidence graph
```

---

# Architecture

```text
┌───────────────────────────────────────────────┐
│       HydraGuard Evidence Console (React)      │
│ Incidents · Evidence · Paths · Firewall        │
└──────────────────────┬────────────────────────┘
                       │ REST API
┌──────────────────────▼────────────────────────┐
│            HydraGuard API (Fastify)            │
│ Ingest · Analyse · Propagate · Prevent · Contain│
└───────────┬─────────────────────┬──────────────┘
            │                     │
            │ Graph Driver        │ Package Metadata
┌───────────▼─────────────┐  ┌────▼─────────────┐
│         HydraDB         │  │   npm Registry    │
│ Evidence Security Graph │  │  Package Metadata │
└─────────────────────────┘  └──────────────────┘
```

---

# Graph Model

## Main Nodes

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

## Main Relationships

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

HydraGuard includes focused validation for core security behavior:

```powershell
npm run typecheck --prefix "apps/api"
npm run validate:release-firewall --prefix "apps/api"
npm run validate:release-persistence --prefix "apps/api"
npm run validate:server --prefix "apps/api"
npm run validate:wave2 --prefix "apps/api"
npm run validate:containment --prefix "apps/api"
```

The Release Influence Firewall validation confirms:

- npm, PyPI, and Maven releases can be evaluated together
- Fully trusted evidence-backed release paths can be allowed
- Cross-boundary cache poisoning is blocked
- Valid OIDC does not override unsafe causal paths
- Unknown influence is quarantined
- Missing publication paths fail closed
- Malformed graphs are rejected
- Traversal limits are surfaced
- Source graphs remain immutable

---

# Team Contributions

## Akshita

- Developed core dependency blast-radius analysis
- Implemented typosquatting detection
- Built the dashboard and visual security experience
- Contributed to graph integration and user-facing explanation

## Pratik Raj

- Designed and implemented Wave 2 Authority Propagation
- Designed and implemented the Universal Release Influence Firewall
- Added immutable release-influence snapshots in HydraDB
- Implemented firewall API contracts, strict validation, error handling, and smoke tests
- Contributed to containment and graph-security validation

---

# Run HydraGuard

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

6. Verify the stack:

```text
http://localhost:3000/health
http://localhost:3000/ready
```

---

# Demo Video and Dashboard

🎥 **YouTube Demo Video:**
[Add your YouTube demo link here](YOUR_YOUTUBE_DEMO_LINK)

🖥️ **Live Dashboard / Evidence Console:**
[Add your dashboard link here](YOUR_DASHBOARD_LINK)

---

<div align="center">

## HydraGuard

**Detection tells you that a package may be dangerous.**
**HydraGuard shows what it reached, what evidence proves it, what authority may be exposed, and whether the next unsafe release should be blocked before it ships.**

**Evidence-first · Graph-native · Fail-closed**

</div>
