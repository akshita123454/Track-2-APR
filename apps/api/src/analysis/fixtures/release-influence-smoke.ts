import assert from "node:assert/strict";

import {
  evaluateReleaseFirewall,
} from "../release-trust/release-influence-firewall.js";
import {
  ReleaseFirewallInputError,
} from "../release-trust/release-influence-types.js";
import type {
  ReleaseFirewallInput,
  ReleaseInfluenceEdge,
  ReleaseInfluenceNode,
  ReleaseInfluenceNodeKind,
  ReleaseNode,
  ReleaseTrustLevel,
} from "../release-trust/release-influence-types.js";

const OBSERVED_AT = 1_778_502_000_000;
const EVIDENCE_ID = 90_001;

function pipelineNode(
  id: number,
  kind: Exclude<ReleaseInfluenceNodeKind, "release">,
  label: string,
  trust: ReleaseTrustLevel,
): ReleaseInfluenceNode {
  return {
    id,
    kind,
    label,
    trust,
    evidenceIds: [EVIDENCE_ID],
    observedAt: OBSERVED_AT,
  };
}

function releaseNode(
  id: number,
  ecosystem: string,
  packageName: string,
  version: string,
): ReleaseNode {
  return {
    id,
    kind: "release",
    label: `${packageName}@${version}`,
    trust: "trusted",
    evidenceIds: [EVIDENCE_ID],
    observedAt: OBSERVED_AT,
    subject: {
      ecosystem,
      packageName,
      version,
      artifactDigest: `sha256:fixture-${String(id)}`,
    },
  };
}

function influenceEdge(
  id: number,
  kind: ReleaseInfluenceEdge["kind"],
  sourceId: number,
  targetId: number,
  trust: ReleaseTrustLevel = "trusted",
  boundary: ReleaseInfluenceEdge["boundary"] =
    "same-trust-zone",
): ReleaseInfluenceEdge {
  return {
    id,
    kind,
    sourceId,
    targetId,
    trust,
    boundary,
    evidenceIds: [EVIDENCE_ID],
    observedAt: OBSERVED_AT,
  };
}

function createFixture(): ReleaseFirewallInput {
  const nodes: ReleaseInfluenceNode[] = [
    // Safe PyPI release: demonstrates that the firewall is not npm-specific.
    pipelineNode(1, "source-change", "reviewed source commit", "trusted"),
    pipelineNode(2, "workflow-run", "isolated release workflow", "trusted"),
    pipelineNode(3, "build", "clean-room build", "trusted"),
    pipelineNode(4, "artifact", "verified wheel", "trusted"),
    releaseNode(5, "pypi", "hydra-client", "2.4.0"),

    // TanStack-style npm release: trusted OIDC exists, but an untrusted fork
    // can influence the artifact through a cross-boundary shared cache.
    pipelineNode(10, "source-change", "external fork pull request", "untrusted"),
    pipelineNode(11, "workflow-run", "pull request workflow", "untrusted"),
    pipelineNode(12, "cache-entry", "shared pnpm cache", "unknown"),
    pipelineNode(13, "workflow-run", "trusted release workflow", "trusted"),
    pipelineNode(14, "credential", "short-lived OIDC publisher", "trusted"),
    pipelineNode(15, "artifact", "npm release tarball", "trusted"),
    releaseNode(16, "npm", "@example/router", "1.2.3"),

    // Unknown Maven input: incomplete trust must quarantine, not allow.
    pipelineNode(20, "source-change", "unclassified source mirror", "unknown"),
    pipelineNode(21, "workflow-run", "Maven Central publisher", "trusted"),
    pipelineNode(22, "artifact", "JAR artifact", "trusted"),
    releaseNode(23, "maven", "org.example:core", "7.1.0"),

    // A release with no artifact-publication path must never be allowed.
    releaseNode(30, "cargo", "hydra-orphan", "0.1.0"),
  ];

  const edges: ReleaseInfluenceEdge[] = [
    influenceEdge(101, "checks-out", 1, 2),
    influenceEdge(102, "starts-build", 2, 3),
    influenceEdge(103, "produces", 3, 4),
    influenceEdge(104, "publishes", 4, 5),

    influenceEdge(110, "checks-out", 10, 11, "untrusted"),
    influenceEdge(
      111,
      "writes-cache",
      11,
      12,
      "untrusted",
      "cross-trust-boundary",
    ),
    influenceEdge(
      112,
      "restores-cache",
      12,
      13,
      "unknown",
      "cross-trust-boundary",
    ),
    influenceEdge(113, "mints-credential", 13, 14),
    influenceEdge(114, "produces", 13, 15),
    influenceEdge(115, "publishes", 15, 16),
    influenceEdge(116, "authorizes-publish", 14, 16),

    influenceEdge(120, "checks-out", 20, 21, "unknown", "unknown"),
    influenceEdge(121, "produces", 21, 22),
    influenceEdge(122, "publishes", 22, 23),
  ];

  return {
    graph: { nodes, edges },
    releaseNodeIds: [5, 16, 23],
  };
}

function run(): void {
  const fixture = createFixture();
  const before = JSON.stringify(fixture);
  const result = evaluateReleaseFirewall(fixture);

  assert.deepEqual(result.summary, {
    evaluated: 3,
    allowed: 1,
    quarantined: 1,
    blocked: 1,
    truncated: 0,
  });

  const safe = result.decisions.find(
    (decision) => decision.releaseNodeId === 5,
  );
  const poisoned = result.decisions.find(
    (decision) => decision.releaseNodeId === 16,
  );
  const unknown = result.decisions.find(
    (decision) => decision.releaseNodeId === 23,
  );

  assert.equal(safe?.subject.ecosystem, "pypi");
  assert.equal(safe?.verdict, "allow");
  assert.equal(poisoned?.subject.ecosystem, "npm");
  assert.equal(poisoned?.verdict, "block");
  assert.ok(
    poisoned?.findings.some(
      (finding) => finding.code === "cross-boundary-cache",
    ),
  );
  assert.ok(
    poisoned?.findings.some(
      (finding) =>
        finding.code === "untrusted-node" &&
        finding.nodeId === 10,
    ),
  );
  assert.ok(
    poisoned?.riskPaths.some(
      (path) =>
        path.nodeIds[0] === 10 &&
        path.nodeIds.at(-1) === 16,
    ),
  );
  assert.ok(
    poisoned?.inspectedNodeCount !== undefined &&
      poisoned.inspectedNodeCount >= 7,
  );
  assert.equal(unknown?.subject.ecosystem, "maven");
  assert.equal(unknown?.verdict, "quarantine");
  assert.ok(
    unknown?.findings.some(
      (finding) => finding.code === "unknown-node",
    ),
  );

  const orphan = evaluateReleaseFirewall({
    graph: fixture.graph,
    releaseNodeIds: [30],
  });

  assert.equal(orphan.decisions[0]?.verdict, "quarantine");
  assert.ok(
    orphan.decisions[0]?.findings.some(
      (finding) => finding.code === "missing-artifact-publication",
    ),
  );

  const limited = evaluateReleaseFirewall(
    {
      graph: fixture.graph,
      releaseNodeIds: [5],
    },
    { maxDepth: 1 },
  );

  assert.equal(limited.decisions[0]?.verdict, "quarantine");
  assert.equal(limited.decisions[0]?.truncated, true);
  assert.ok(
    limited.decisions[0]?.findings.some(
      (finding) => finding.code === "depth-limit-reached",
    ),
  );

  assert.throws(
    () =>
      evaluateReleaseFirewall({
        graph: {
          nodes: fixture.graph.nodes,
          edges: [
            influenceEdge(999, "publishes", 4, 999_999),
          ],
        },
        releaseNodeIds: [5],
      }),
    (error: unknown) =>
      error instanceof ReleaseFirewallInputError &&
      error.code === "missing-edge-endpoint",
  );

  assert.equal(JSON.stringify(fixture), before);

  console.log("Release influence firewall smoke passed");
  console.log("- arbitrary npm, PyPI, and Maven releases evaluated together");
  console.log("- fully trusted evidence-backed release allowed");
  console.log("- cross-boundary cache poisoning blocked despite trusted OIDC");
  console.log("- unknown influence and missing publication paths quarantined fail closed");
  console.log("- malformed graphs rejected and traversal limits surfaced");
  console.log("- immutable input graph remained unchanged");
}

run();
