// src/services/profile.service.ts
import { profileRepository } from '@/repositories/profile.repository';
import { userRepository } from '@/repositories/user.repository';
import { logger } from '@/utils/logger';
import { IProfile } from '@/interfaces/user.interface';

export class ProfileService {
  async getProfileByUserId(userId: string): Promise<IProfile> {
    logger.info('Getting profile for user', { userId });

    const profile = await profileRepository.findByUserId(userId);
    if (!profile) {
      throw new Error('Profile not found');
    }

    return profile.toJSON();
  }

  async updateProfile(userId: string, updateData: Partial<IProfile>): Promise<IProfile> {
    logger.info('Updating profile for user', { userId });

    // Verify user exists
    const user = await userRepository.findById(userId);
    if (!user) {
      throw new Error('User not found');
    }

    // Get existing profile
    const existingProfile = await profileRepository.findByUserId(userId);
    if (!existingProfile) {
      throw new Error('Profile not found');
    }

    // Update profile
    const updatedProfile = await profileRepository.update(existingProfile.id, updateData);
    return updatedProfile.toJSON();
  }
}

export const profileService = new ProfileService();