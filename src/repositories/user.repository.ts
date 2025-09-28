// src/repositories/user.repository.ts
import { Op } from 'sequelize';
import { Effect } from 'effect';
import { BaseRepository } from './base.repository';
import { User, Profile, Role } from '@/models';
import { IUserResponse } from '@/interfaces/user.interface';
import { PaginationResponse } from '@/types/response.types';
import { DatabaseError, NotFoundError } from '@/types/effect.types';

export class UserRepository extends BaseRepository<User> {
  constructor() {
    super(User);
  }

  findByEmail(email: string, includePassword: boolean = false): Effect.Effect<User | null, DatabaseError> {
    const attributes = includePassword
      ? undefined
      : { exclude: ['password', 'emailVerificationToken', 'passwordResetToken'] };

    return this.findOne({
      where: { email },
      attributes,
    });
  }

  findByEmailWithRoles(email: string): Effect.Effect<User | null, DatabaseError> {
    return this.findOne({
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

  findByIdWithProfile(id: string): Effect.Effect<User | null, DatabaseError> {
    return this.findById(id, {
      include: [
        {
          model: Profile,
          as: 'profile',
        },
      ],
      attributes: { exclude: ['password', 'emailVerificationToken', 'passwordResetToken'] },
    });
  }

  findUsersWithPagination(
    page: number = 1,
    limit: number = 10,
    search: string = ''
  ): Effect.Effect<PaginationResponse<IUserResponse>, DatabaseError> {
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

    return Effect.gen(function* (this: UserRepository) {
      const result = yield* this.findAndCountAll({
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
    }.bind(this)) as Effect.Effect<PaginationResponse<IUserResponse>, DatabaseError>;
  }

  updateLastLogin(id: string): Effect.Effect<User, DatabaseError | NotFoundError> {
    return this.update(id, { lastLoginAt: new Date() });
  }

  setEmailVerified(id: string): Effect.Effect<User, DatabaseError | NotFoundError> {
    return this.update(id, {
      emailVerified: true,
      emailVerificationToken: undefined,
    });
  }

  findByVerificationToken(token: string): Effect.Effect<User | null, DatabaseError> {
    return this.findOne({
      where: { emailVerificationToken: token },
    });
  }

  findByPasswordResetToken(token: string): Effect.Effect<User | null, DatabaseError> {
    return this.findOne({
      where: {
        passwordResetToken: token,
        passwordResetExpires: { [Op.gt]: new Date() },
      },
    });
  }
}

export const userRepository = new UserRepository();