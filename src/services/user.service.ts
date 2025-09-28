// src/services/user.service.ts
import { Effect } from 'effect';
import { userRepository } from '@/repositories/user.repository';
import { logger } from '@/utils/logger';
import {
  IUserResponse,
  IUpdateUserRequest,
} from '@/interfaces/user.interface';
import { PaginationResponse } from '@/types/response.types';
import { DatabaseError, NotFoundError } from '@/types/effect.types';

export class UserService {
  getUserById(id: string): Effect.Effect<IUserResponse, DatabaseError | NotFoundError> {
    return Effect.gen(function* () {
      logger.info('Getting user by ID', { userId: id });

      const user = yield* userRepository.findByIdWithProfile(id);
      if (!user) {
        return yield* Effect.fail(new NotFoundError({ message: 'User not found' }));
      }

      return user.toSafeObject();
    });
  }

  getUsers(
    page: number = 1,
    limit: number = 10,
    search: string = ''
  ): Effect.Effect<PaginationResponse<IUserResponse>, DatabaseError> {
    logger.info('Getting users with pagination', { page, limit, search });

    return userRepository.findUsersWithPagination(page, limit, search);
  }

  updateUser(id: string, updateData: IUpdateUserRequest): Effect.Effect<IUserResponse, DatabaseError | NotFoundError> {
    return Effect.gen(function* () {
      logger.info('Updating user', { userId: id });

      // Verify user exists
      const existingUser = yield* userRepository.findById(id);
      if (!existingUser) {
        return yield* Effect.fail(new NotFoundError({ message: 'User not found' }));
      }

      // Update user
      const updatedUser = yield* userRepository.update(id, updateData);
      return updatedUser.toSafeObject();
    });
  }

  deactivateUser(id: string): Effect.Effect<void, DatabaseError | NotFoundError> {
    return Effect.gen(function* () {
      logger.info('Deactivating user', { userId: id });

      // Verify user exists
      const user = yield* userRepository.findById(id);
      if (!user) {
        return yield* Effect.fail(new NotFoundError({ message: 'User not found' }));
      }

      // Deactivate user
      yield* userRepository.update(id, { isActive: false });
    });
  }

  activateUser(id: string): Effect.Effect<void, DatabaseError | NotFoundError> {
    return Effect.gen(function* () {
      logger.info('Activating user', { userId: id });

      // Verify user exists
      const user = yield* userRepository.findById(id);
      if (!user) {
        return yield* Effect.fail(new NotFoundError({ message: 'User not found' }));
      }

      // Activate user
      yield* userRepository.update(id, { isActive: true });
    });
  }
}

export const userService = new UserService();