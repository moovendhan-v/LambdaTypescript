import { Data } from "effect";

export class DatabaseError extends Data.TaggedError("DatabaseError")<{
  message: string;
  cause?: unknown;
}> {}

export class ValidationError extends Data.TaggedError("ValidationError")<{
  message: string;
  field?: string;
}> {}

export class AuthenticationError extends Data.TaggedError("AuthenticationError")<{
  message: string;
}> {}

export class AuthorizationError extends Data.TaggedError("AuthorizationError")<{
  message: string;
}> {}

export class NotFoundError extends Data.TaggedError("NotFoundError")<{
  message: string;
  resource?: string;
}> {}

export class ConflictError extends Data.TaggedError("ConflictError")<{
  message: string;
}> {}

export class InternalServerError extends Data.TaggedError("InternalServerError")<{
  message: string;
  cause?: unknown;
}> {}