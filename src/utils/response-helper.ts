import { APIGatewayProxyResult } from 'aws-lambda';
import { SuccessResponse, ErrorResponse } from '@/types/response.types';

export function createSuccessResponse<T>(
  data: T,
  statusCode: number = 200,
  message?: string
): APIGatewayProxyResult {
  const response: SuccessResponse<T> = {
    success: true,
    data,
    ...(message && { message }),
  };

  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    },
    body: JSON.stringify(response),
  };
}

export function createErrorResponse(
  message: string,
  statusCode: number = 500,
  details?: any
): APIGatewayProxyResult {
  const response: ErrorResponse = {
    success: false,
    error: {
      message,
      ...(details && { details }),
    },
  };

  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    },
    body: JSON.stringify(response),
  };
}

export function createApiResponse<T>(
  statusCode: number,
  headers: Record<string, string>,
  body: string
): APIGatewayProxyResult {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
    body,
  };
}

// Aliases for convenience
export const successResponse = createSuccessResponse;
export const errorResponse = createErrorResponse;