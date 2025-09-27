// src/repositories/profile.repository.ts
import { BaseRepository } from './base.repository';
import { Profile } from '@/models';

export class ProfileRepository extends BaseRepository<Profile> {
  constructor() {
    super(Profile);
  }

  async findByUserId(userId: string): Promise<Profile | null> {
    return await this.findOne({
      where: { userId }
    });
  }
}

export const profileRepository = new ProfileRepository();