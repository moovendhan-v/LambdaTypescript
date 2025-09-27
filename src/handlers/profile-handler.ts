// src/handlers/profile-handler.ts
import { APIGatewayProxyResult } from 'aws-lambda';
import { profileService } from '@/services/profile.service';
import { validateUpdateProfile } from '@/utils/validation';
import { successResponse, errorResponse } from '@/utils/response-helper';
import { withErrorHandling } from '@/middleware/error-handler.middleware';
import { requireAuth } from '@/middleware/auth.middleware';
import { logger } from '@/utils/logger';
import { AuthenticatedEvent } from '@/types/lambda.types';

const getProfileHandler = async (event: AuthenticatedEvent): Promise<APIGatewayProxyResult> => {
  logger.info('Get profile request', { path: event.path });

  const userId = event.user?.userId;

  if (!userId) {
    return errorResponse('Unauthorized', 401);
  }

  const profile = await profileService.getProfileByUserId(userId);

  return successResponse({ profile }, 200);
};

const updateProfileHandler = async (event: AuthenticatedEvent): Promise<APIGatewayProxyResult> => {
  logger.info('Update profile request', { path: event.path });

  const userId = event.user?.userId;

  if (!userId) {
    return errorResponse('Unauthorized', 401);
  }

  const updateData = JSON.parse(event.body || '{}');

  // Validate input
  const validation = validateUpdateProfile(updateData);
  if (!validation.isValid) {
    return errorResponse('Validation failed', 400, validation.errors);
  }

  const profile = await profileService.updateProfile(userId, validation.data);

  return successResponse({
    message: 'Profile updated successfully',
    profile,
  }, 200);
};

export const getProfile = requireAuth(withErrorHandling(getProfileHandler));
export const updateProfile = requireAuth(withErrorHandling(updateProfileHandler));