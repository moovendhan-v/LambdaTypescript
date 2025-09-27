import { APIGatewayProxyResult, Context } from 'aws-lambda';
import { logger } from '@/utils/logger';
import { errorResponse } from '@/utils/response-helper';
import { AuthenticatedEvent } from '@/types/lambda.types';

export function withErrorHandling<T extends AuthenticatedEvent | any>(
  handler: (event: T, context: Context) => Promise<APIGatewayProxyResult>
) {
  return async (event: T, context: Context): Promise<APIGatewayProxyResult> => {
    try {
      return await handler(event, context);
    } catch (error) {
      logger.error('Handler error', error as Error);

      // Handle different types of errors
      if (error instanceof Error) {
        // Check for specific error types
        if (error.message.includes('Validation failed')) {
          return errorResponse(error.message, 400);
        }
        if (error.message.includes('not found')) {
          return errorResponse(error.message, 404);
        }
        if (error.message.includes('Unauthorized') || error.message.includes('Invalid token')) {
          return errorResponse(error.message, 401);
        }
        if (error.message.includes('Forbidden') || error.message.includes('not allowed')) {
          return errorResponse(error.message, 403);
        }
      }

      return errorResponse('Internal server error', 500);
    }
  };
}