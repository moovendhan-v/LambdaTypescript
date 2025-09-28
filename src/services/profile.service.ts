// src/services/profile.service.ts
import { Effect } from 'effect';
import { profileRepository } from '@/repositories/profile.repository';
import { userRepository } from '@/repositories/user.repository';
import { logger } from '@/utils/logger';
import { IProfile } from '@/interfaces/user.interface';
import { DatabaseError, NotFoundError } from '@/types/effect.types';

export class ProfileService {
  getProfileByUserId(userId: string): Effect.Effect<IProfile, DatabaseError | NotFoundError> {
    return Effect.gen(function* () {
      logger.info('Getting profile for user', { userId });

      const profile = yield* profileRepository.findByUserId(userId);
      if (!profile) {
        return yield* Effect.fail(new NotFoundError({ message: 'Profile not found' }));
      }

      return profile.toJSON();
    });
  }

  updateProfile(userId: string, updateData: Partial<IProfile>): Effect.Effect<IProfile, DatabaseError | NotFoundError> {
    return Effect.gen(function* () {
      logger.info('Updating profile for user', { userId });

      // Verify user exists
      const user = yield* userRepository.findById(userId);
      if (!user) {
        return yield* Effect.fail(new NotFoundError({ message: 'User not found' }));
      }

      // Get existing profile
      const existingProfile = yield* profileRepository.findByUserId(userId);
      if (!existingProfile) {
        return yield* Effect.fail(new NotFoundError({ message: 'Profile not found' }));
      }

      // Update profile
      const updatedProfile = yield* profileRepository.update(existingProfile.id, updateData);
      return updatedProfile.toJSON();
    });
  }
}

export const profileService = new ProfileService();