import neo4j from "neo4j-driver";

function convertHydraValue(value: unknown): unknown {
  if (neo4j.isInt(value)) {
    return value;
  }

  if (typeof value === "number") {
    if (
      Number.isInteger(value) &&
      !Number.isSafeInteger(value)
    ) {
      throw new RangeError(
        "HydraDB integer parameters must be safe JavaScript integers",
      );
    }

    return Number.isSafeInteger(value)
      ? neo4j.int(value)
      : value;
  }

  if (Array.isArray(value)) {
    return value.map(convertHydraValue);
  }

  if (
    typeof value === "object" &&
    value !== null
  ) {
    const prototype =
      Object.getPrototypeOf(value);

    if (
      prototype === Object.prototype ||
      prototype === null
    ) {
      return Object.fromEntries(
        Object.entries(value).map(
          ([key, entry]) => [
            key,
            convertHydraValue(entry),
          ],
        ),
      );
    }
  }

  return value;
}

export function toHydraParameters(
  parameters: Readonly<Record<string, unknown>>,
): Record<string, unknown> {
  return convertHydraValue(
    parameters,
  ) as Record<string, unknown>;
}
