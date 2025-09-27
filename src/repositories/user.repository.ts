// src/repositories/user.repository.ts
import { Op } from 'sequelize';
import { BaseRepository } from './base.repository';
import { User, Profile, Role } from '@/models';
import { IUserResponse } from '@/interfaces/user.interface';
import { PaginationResponse } from '@/types/response.types';

export class UserRepository extends BaseRepository<User> {
  constructor() {
    super(User);
  }

  async findByEmail(email: string, includePassword: boolean = false): Promise<User | null> {
    const attributes = includePassword 
      ? undefined 
      : { exclude: ['password', 'emailVerificationToken', 'passwordResetToken'] };

    return await this.findOne({
      where: { email },
      attributes,
    });
  }

  async findByEmailWithRoles(email: string): Promise<User | null> {
    return await this.findOne({
      where: { email },
      include: [
        {
          model: Role,
          as: 'roles',
          attributes: ['id', 'name', 'permissions'],
        },
      ],
    });
  }

  async findByIdWithProfile(id: string): Promise<User | null> {
    return await this.findById(id, {
      include: [
        {
          model: Profile,
          as: 'profile',
        },
      ],
      attributes: { exclude: ['password', 'emailVerificationToken', 'passwordResetToken'] },
    });
  }

  async findUsersWithPagination(
    page: number = 1,
    limit: number = 10,
    search: string = ''
  ): Promise<PaginationResponse<IUserResponse>> {
    const offset = (page - 1) * limit;
    const whereClause = search
      ? {
          [Op.or]: [
            { firstName: { [Op.iLike]: `%${search}%` } },
            { lastName: { [Op.iLike]: `%${search}%` } },
            { email: { [Op.iLike]: `%${search}%` } },
          ],
        }
      : {};

    const result = await this.findAndCountAll({
      where: whereClause,
      limit,
      offset,
      order: [['createdAt', 'DESC']],
      include: [
        {
          model: Profile,
          as: 'profile',
          attributes: ['avatar', 'phoneNumber'],
        },
        {
          model: Role,
          as: 'roles',
          attributes: ['name'],
        },
      ],
      attributes: { exclude: ['password', 'emailVerificationToken', 'passwordResetToken'] },
    });

    return {
      items: result.rows.map(user => user.toSafeObject()),
      pagination: {
        total: result.count,
        page,
        limit,
        totalPages: Math.ceil(result.count / limit),
      },
    };
  }

  async updateLastLogin(id: string): Promise<User> {
    return await this.update(id, { lastLoginAt: new Date() });
  }

  async setEmailVerified(id: string): Promise<User> {
    return await this.update(id, {
      emailVerified: true,
      emailVerificationToken: undefined,
    });
  }

  async findByVerificationToken(token: string): Promise<User | null> {
    return await this.findOne({
      where: { emailVerificationToken: token },
    });
  }

  async findByPasswordResetToken(token: string): Promise<User | null> {
    return await this.findOne({
      where: {
        passwordResetToken: token,
        passwordResetExpires: { [Op.gt]: new Date() },
      },
    });
  }
}

export const userRepository = new UserRepository();