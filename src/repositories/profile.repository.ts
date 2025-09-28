// src/repositories/profile.repository.ts
import { Effect } from 'effect';
import { BaseRepository } from './base.repository';
import { Profile } from '@/models';
import { DatabaseError } from '@/types/effect.types';

export class ProfileRepository extends BaseRepository<Profile> {
  constructor() {
    super(Profile);
  }

  findByUserId(userId: string): Effect.Effect<Profile | null, DatabaseError> {
    return this.findOne({
      where: { userId }
    });
  }
}

export const profileRepository = new ProfileRepository();