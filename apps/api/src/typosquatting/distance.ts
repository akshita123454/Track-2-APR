import type {
  DistanceOperation,
  DistanceOperationKind,
  DistanceResult,
} from "./types.js";

const COST = Object.freeze({
  match: 0,
  "adjacent-transposition": 75,
  substitution: 100,
  deletion: 100,
  insertion: 100,
} satisfies Record<DistanceOperationKind, number>);

const PRIORITY: Readonly<Record<DistanceOperationKind, number>> = Object.freeze({
  match: 0,
  "adjacent-transposition": 1,
  substitution: 2,
  deletion: 3,
  insertion: 4,
});

interface Cell {
  readonly cost: number;
  readonly previousI: number;
  readonly previousJ: number;
  readonly operation: DistanceOperationKind;
}

function choose(cells: readonly Cell[]): Cell {
  return [...cells].sort((left, right) =>
    left.cost - right.cost || PRIORITY[left.operation] - PRIORITY[right.operation]
  )[0]!;
}

export function weightedDamerauLevenshtein(
  sourceValue: string,
  targetValue: string,
): DistanceResult {
  const source = Array.from(sourceValue);
  const target = Array.from(targetValue);
  const matrix: Cell[][] = Array.from({ length: source.length + 1 }, () => []);
  matrix[0]![0] = { cost: 0, previousI: 0, previousJ: 0, operation: "match" };

  for (let i = 1; i <= source.length; i += 1) {
    matrix[i]![0] = {
      cost: i * COST.deletion,
      previousI: i - 1,
      previousJ: 0,
      operation: "deletion",
    };
  }
  for (let j = 1; j <= target.length; j += 1) {
    matrix[0]![j] = {
      cost: j * COST.insertion,
      previousI: 0,
      previousJ: j - 1,
      operation: "insertion",
    };
  }

  for (let i = 1; i <= source.length; i += 1) {
    for (let j = 1; j <= target.length; j += 1) {
      const same = source[i - 1] === target[j - 1];
      const choices: Cell[] = [
        {
          cost: matrix[i - 1]![j - 1]!.cost + (same ? COST.match : COST.substitution),
          previousI: i - 1,
          previousJ: j - 1,
          operation: same ? "match" : "substitution",
        },
        {
          cost: matrix[i - 1]![j]!.cost + COST.deletion,
          previousI: i - 1,
          previousJ: j,
          operation: "deletion",
        },
        {
          cost: matrix[i]![j - 1]!.cost + COST.insertion,
          previousI: i,
          previousJ: j - 1,
          operation: "insertion",
        },
      ];
      if (
        i > 1 && j > 1 &&
        source[i - 1] === target[j - 2] &&
        source[i - 2] === target[j - 1]
      ) {
        choices.push({
          cost: matrix[i - 2]![j - 2]!.cost + COST["adjacent-transposition"],
          previousI: i - 2,
          previousJ: j - 2,
          operation: "adjacent-transposition",
        });
      }
      matrix[i]![j] = choose(choices);
    }
  }

  const operations: DistanceOperation[] = [];
  let i = source.length;
  let j = target.length;
  while (i > 0 || j > 0) {
    const cell = matrix[i]![j]!;
    const sourceText = source.slice(cell.previousI, i).join("");
    const targetText = target.slice(cell.previousJ, j).join("");
    operations.push({
      kind: cell.operation,
      sourceIndex: cell.previousI,
      targetIndex: cell.previousJ,
      source: sourceText,
      target: targetText,
      cost: COST[cell.operation],
    });
    i = cell.previousI;
    j = cell.previousJ;
  }
  operations.reverse();

  const cost = matrix[source.length]![target.length]!.cost;
  return {
    cost,
    normalizedCost: cost / (Math.max(source.length, target.length, 1) * 100),
    operations,
  };
}
