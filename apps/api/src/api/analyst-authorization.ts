import {
  timingSafeEqual,
} from "node:crypto";

import {
  ApiError,
} from "./errors.js";

export interface AnalystPrincipal {
  readonly reviewer: string;
}

export interface AnalystAuthorizer {
  authorize(
    authorization: string | undefined,
  ): AnalystPrincipal | Promise<AnalystPrincipal>;
}

function matchesToken(
  supplied: string,
  expected: string,
): boolean {
  const suppliedBytes =
    Buffer.from(supplied, "utf8");
  const expectedBytes =
    Buffer.from(expected, "utf8");

  return (
    suppliedBytes.length ===
      expectedBytes.length &&
    timingSafeEqual(
      suppliedBytes,
      expectedBytes,
    )
  );
}

export function createStaticAnalystAuthorizer(
  token: string,
  reviewer: string,
): AnalystAuthorizer {
  if (
    token.length < 16 ||
    token.length > 512 ||
    /\s/.test(token)
  ) {
    throw new Error(
      "Analyst bearer token must contain 16 to 512 non-whitespace characters",
    );
  }

  if (
    reviewer.trim() !== reviewer ||
    reviewer.length === 0 ||
    reviewer.length > 200
  ) {
    throw new Error(
      "Analyst reviewer identity must contain 1 to 200 trimmed characters",
    );
  }

  const principal =
    Object.freeze({ reviewer });

  return Object.freeze({
    authorize(
      authorization: string | undefined,
    ): AnalystPrincipal {
      const match =
        authorization?.match(
          /^Bearer ([^\s]+)$/i,
        );

      if (
        match === null ||
        match === undefined ||
        !matchesToken(
          match[1]!,
          token,
        )
      ) {
        throw new ApiError(
          "ANALYST_AUTHENTICATION_REQUIRED",
          401,
          "A valid analyst bearer token is required.",
        );
      }

      return principal;
    },
  });
}
