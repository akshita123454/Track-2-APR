import type {
  FastifyError,
  FastifyInstance,
} from "fastify";

import {
  JobManagerError,
} from "./jobs/job-manager.js";

import {
  WorkerDispatcherError,
} from "./jobs/worker-dispatcher.js";

import {
  IncidentServiceError,
} from "../incidents/incident-service.js";

export class ApiError
  extends Error {
  constructor(
    readonly code: string,
    readonly httpStatusCode: number,
    message: string,
    readonly details?: readonly string[],
  ) {
    super(message);
    this.name = "ApiError";
  }
}

interface ValidationIssue {
  readonly instancePath?: string;
  readonly message?: string;
}

function validationDetails(
  error: FastifyError,
): readonly string[] | undefined {
  const validation =
    error.validation as
      | readonly ValidationIssue[]
      | undefined;

  if (
    validation === undefined ||
    validation.length === 0
  ) {
    return undefined;
  }

  return validation
    .slice(0, 50)
    .map((issue) => {
      const path =
        issue.instancePath?.length
          ? issue.instancePath
          : "request";

      return `${path} ${issue.message ?? "is invalid"}`;
    });
}

export function registerErrorHandling(
  app: FastifyInstance,
): void {
  app.setNotFoundHandler(
    async (_request, reply) => {
      return reply
        .code(404)
        .send({
          code: "ROUTE_NOT_FOUND",
          message:
            "The requested API route was not found.",
        });
    },
  );

  app.setErrorHandler(
    async (
      error,
      request,
      reply,
    ) => {
      if (
        error instanceof
        ApiError
      ) {
        return reply
          .code(
            error.httpStatusCode,
          )
          .send({
            code: error.code,
            message: error.message,
            ...(error.details ===
            undefined
              ? {}
              : {
                  details:
                    error.details,
                }),
          });
      }

      if (
        error instanceof
        JobManagerError ||
        error instanceof
          WorkerDispatcherError ||
        error instanceof
          IncidentServiceError
      ) {
        return reply
          .code(
            error.httpStatusCode,
          )
          .send({
            code: error.code,
            message: error.message,
          });
      }

      const fastifyError =
        error as FastifyError;

      if (
        fastifyError.validation !==
        undefined
      ) {
        return reply
          .code(400)
          .send({
            code:
              "REQUEST_VALIDATION_FAILED",
            message:
              "The request did not match the API contract.",
            details:
              validationDetails(
                fastifyError,
              ),
          });
      }

      if (
        fastifyError.code ===
        "FST_ERR_CTP_BODY_TOO_LARGE"
      ) {
        return reply
          .code(413)
          .send({
            code:
              "REQUEST_BODY_TOO_LARGE",
            message:
              "The request body exceeds the configured limit.",
          });
      }

      request.log.error(
        {
          err: error,
        },
        "Unhandled API request error",
      );

      return reply
        .code(500)
        .send({
          code:
            "INTERNAL_SERVER_ERROR",
          message:
            "The request could not be completed because of an internal error.",
        });
    },
  );
}
