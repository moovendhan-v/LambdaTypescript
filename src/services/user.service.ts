// src/services/user.service.ts
import { userRepository } from '@/repositories/user.repository';
import { logger } from '@/utils/logger';
import {
  IUserResponse,
  IUpdateUserRequest,
} from '@/interfaces/user.interface';
import { PaginationResponse } from '@/types/response.types';

export class UserService {
  async getUserById(id: string): Promise<IUserResponse> {
    logger.info('Getting user by ID', { userId: id });

    const user = await userRepository.findByIdWithProfile(id);
    if (!user) {
      throw new Error('User not found');
    }

    return user.toSafeObject();
  }

  async getUsers(
    page: number = 1,
    limit: number = 10,
    search: string = ''
  ): Promise<PaginationResponse<IUserResponse>> {
    logger.info('Getting users with pagination', { page, limit, search });

    return await userRepository.findUsersWithPagination(page, limit, search);
  }

  async updateUser(id: string, updateData: IUpdateUserRequest): Promise<IUserResponse> {
    logger.info('Updating user', { userId: id });

    // Verify user exists
    const existingUser = await userRepository.findById(id);
    if (!existingUser) {
      throw new Error('User not found');
    }

    // Update user
    const updatedUser = await userRepository.update(id, updateData);
    return updatedUser.toSafeObject();
  }

  async deactivateUser(id: string): Promise<void> {
    logger.info('Deactivating user', { userId: id });

    // Verify user exists
    const user = await userRepository.findById(id);
    if (!user) {
      throw new Error('User not found');
    }

    // Deactivate user
    await userRepository.update(id, { isActive: false });
  }

  async activateUser(id: string): Promise<void> {
    logger.info('Activating user', { userId: id });

    // Verify user exists
    const user = await userRepository.findById(id);
    if (!user) {
      throw new Error('User not found');
    }

    // Activate user
    await userRepository.update(id, { isActive: true });
  }
}

export const userService = new UserService();