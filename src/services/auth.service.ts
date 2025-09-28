// src/services/auth.service.ts
import { Effect } from 'effect';
import { userRepository } from '@/repositories/user.repository';
import { generateToken, verifyToken } from '@/utils/jwt-helper';
import { generateRandomToken } from '@/utils/password-helper';
import { emailService } from './email.service';
import { logger } from '@/utils/logger';
import {
  IRegisterRequest,
  IAuthResponse,
  IRefreshTokenRequest
} from '@/interfaces/auth.interface';
import { IJwtPayload } from '@/types/jwt.types';
import { Profile } from '@/models/profile.model';
import { DatabaseError, ValidationError, ConflictError, AuthenticationError, NotFoundError } from '@/types/effect.types';

export class AuthService {
  register(userData: IRegisterRequest): Effect.Effect<IAuthResponse, DatabaseError | ValidationError | ConflictError> {
    return Effect.gen(function* () {
      logger.info('Registering new user', { email: userData.email });

      // Check if user exists
      const existingUser = yield* userRepository.findByEmail(userData.email);
      if (existingUser) {
        return yield* Effect.fail(new ConflictError({ message: 'User already exists with this email' }));
      }

      // Generate email verification token
      const emailVerificationToken = generateRandomToken();

      // Create user
      const user = yield* userRepository.create({
        ...userData,
        emailVerificationToken,
      });

      // Create default profile
      yield* Effect.tryPromise({
        try: () => Profile.create({ userId: user.id }),
        catch: (error) => new DatabaseError({ message: 'Failed to create profile', cause: error }),
      });

      // Send verification email (fire and forget)
      Effect.tryPromise({
        try: () => emailService.sendVerificationEmail(user.email, emailVerificationToken),
        catch: (error) => {
          logger.error('Failed to send verification email', error as Error);
          return new DatabaseError({ message: 'Failed to send verification email', cause: error });
        },
      });

      // Generate JWT token
      const token = generateToken({ userId: user.id, email: user.email });

      return {
        user: user.toSafeObject(),
        token,
      };
    });
  }

  login(email: string, password: string): Effect.Effect<IAuthResponse, DatabaseError | AuthenticationError> {
    return Effect.gen(function* () {
      logger.info('User login attempt', { email });

      // Find user with roles
      const user = yield* userRepository.findByEmailWithRoles(email);
      if (!user) {
        return yield* Effect.fail(new AuthenticationError({ message: 'Invalid email or password' }));
      }

      // Validate password
      const isValidPassword = yield* Effect.tryPromise({
        try: () => user.validatePassword(password),
        catch: (error) => new DatabaseError({ message: 'Password validation failed', cause: error }),
      });
      if (!isValidPassword) {
        return yield* Effect.fail(new AuthenticationError({ message: 'Invalid email or password' }));
      }

      // Check if user is active
      if (!user.isActive) {
        return yield* Effect.fail(new AuthenticationError({ message: 'Account is deactivated' }));
      }

      // Update last login (fire and forget)
      Effect.fork(userRepository.updateLastLogin(user.id));

      // Generate JWT token
      const token = generateToken({
        userId: user.id,
        email: user.email,
        roles: user.roles?.map((role: { name: any; }) => role.name) || [],
      });

      return {
        user: user.toSafeObject(),
        token,
      };
    });
  }

  refreshToken(tokenData: IRefreshTokenRequest): Effect.Effect<{ token: string }, DatabaseError | AuthenticationError> {
    return Effect.gen(function* () {
      let decoded: IJwtPayload;
      try {
        decoded = verifyToken(tokenData.token) as IJwtPayload;
      } catch (error) {
        return yield* Effect.fail(new AuthenticationError({ message: 'Invalid or expired token' }));
      }

      const user = yield* userRepository.findById(decoded.userId);

      if (!user || !user.isActive) {
        return yield* Effect.fail(new AuthenticationError({ message: 'Invalid token' }));
      }

      const newToken = generateToken({
        userId: user.id,
        email: user.email,
      });

      return { token: newToken };
    });
  }

  verifyEmail(token: string): Effect.Effect<{ message: string }, DatabaseError | NotFoundError> {
    return Effect.gen(function* () {
      const user = yield* userRepository.findByVerificationToken(token);
      if (!user) {
        return yield* Effect.fail(new NotFoundError({ message: 'Invalid verification token' }));
      }

      yield* userRepository.setEmailVerified(user.id);

      return { message: 'Email verified successfully' };
    });
  }

  requestPasswordReset(email: string): Effect.Effect<{ message: string }, DatabaseError | NotFoundError> {
    return Effect.gen(function* () {
      const user = yield* userRepository.findByEmail(email);
      if (!user) {
        return yield* Effect.fail(new NotFoundError({ message: 'User not found' }));
      }

      const resetToken = generateRandomToken();
      const resetExpires = new Date(Date.now() + 3600000); // 1 hour

      yield* userRepository.update(user.id, {
        passwordResetToken: resetToken,
        passwordResetExpires: resetExpires,
      });

      // Send email (fire and forget)
      Effect.fork(Effect.tryPromise({
        try: () => emailService.sendPasswordResetEmail(email, resetToken),
        catch: (error) => {
          logger.error('Failed to send password reset email', error as Error);
          return new DatabaseError({ message: 'Failed to send password reset email', cause: error });
        },
      }));

      return { message: 'Password reset email sent' };
    });
  }
}

export const authService = new AuthService();