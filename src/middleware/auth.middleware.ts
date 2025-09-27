import { APIGatewayProxyResult, Context } from 'aws-lambda';
import { verifyToken } from '@/utils/jwt-helper';
import { logger } from '@/utils/logger';
import { errorResponse } from '@/utils/response-helper';
import { AuthenticatedEvent, AuthenticatedHandler } from '@/types/lambda.types';
import { IJwtPayload } from '@/types/jwt.types';

export function requireAuth(handler: AuthenticatedHandler) {
  return async (event: any, context: Context): Promise<APIGatewayProxyResult> => {
    try {
      // Extract token from Authorization header
      const authHeader = event.headers?.Authorization || event.headers?.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return errorResponse('Authorization header missing or invalid', 401);
      }

      const token = authHeader.substring(7); // Remove 'Bearer ' prefix

      // Verify token
      const decoded = verifyToken(token) as IJwtPayload;

      // Attach user info to event
      const authenticatedEvent: AuthenticatedEvent = {
        ...event,
        user: {
          userId: decoded.userId,
          email: decoded.email,
          roles: decoded.roles || [],
        },
      };

      return await handler(authenticatedEvent, context);
    } catch (error) {
      logger.error('Authentication failed', error as Error);
      return errorResponse('Invalid or expired token', 401);
    }
  };
}