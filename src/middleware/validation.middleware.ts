// src/middleware/validation.middleware.ts
import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import Joi from 'joi';
import { logger } from '@/utils/logger';
import { errorResponse } from '@/utils/response-helper';

export type ValidatedEvent<T = any> = Omit<APIGatewayProxyEvent, 'body'> & {
  body: T;
};

export function validateBody<T>(
  schema: Joi.ObjectSchema,
  handler: (event: ValidatedEvent<T>, context: Context) => Promise<APIGatewayProxyResult>
) {
  return async (event: any, context: Context): Promise<APIGatewayProxyResult> => {
    try {
      // Parse request body
      let body: any;
      try {
        body = event.body ? JSON.parse(event.body) : {};
      } catch (parseError) {
        logger.error('Failed to parse request body', parseError as Error);
        return errorResponse('Invalid JSON in request body', 400);
      }

      // Validate body against schema
      const { error, value } = schema.validate(body, { abortEarly: false });
      if (error) {
        const errorMessages = error.details.map(detail => detail.message);
        logger.warn('Validation failed', { errors: errorMessages, body });
        return errorResponse(`Validation failed: ${errorMessages.join(', ')}`, 400);
      }

      // Create validated event with typed body
      const validatedEvent: ValidatedEvent<T> = {
        ...event,
        body: value,
      };

      return await handler(validatedEvent, context);
    } catch (error) {
      logger.error('Validation middleware error', error as Error);
      return errorResponse('Internal server error during validation', 500);
    }
  };
}

export function validateQueryParams<T>(
  schema: Joi.ObjectSchema,
  handler: (event: APIGatewayProxyEvent & { queryParams: T }, context: Context) => Promise<APIGatewayProxyResult>
) {
  return async (event: any, context: Context): Promise<APIGatewayProxyResult> => {
    try {
      // Validate query parameters
      const { error, value } = schema.validate(event.queryStringParameters || {}, { abortEarly: false });
      if (error) {
        const errorMessages = error.details.map(detail => detail.message);
        logger.warn('Query validation failed', { errors: errorMessages, query: event.queryStringParameters });
        return errorResponse(`Query validation failed: ${errorMessages.join(', ')}`, 400);
      }

      // Create event with validated query params
      const validatedEvent = {
        ...event,
        queryParams: value,
      };

      return await handler(validatedEvent, context);
    } catch (error) {
      logger.error('Query validation middleware error', error as Error);
      return errorResponse('Internal server error during query validation', 500);
    }
  };
}