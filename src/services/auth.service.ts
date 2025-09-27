// src/services/auth.service.ts
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

export class AuthService {
  async register(userData: IRegisterRequest): Promise<IAuthResponse> {
    logger.info('Registering new user', { email: userData.email });

    // Check if user exists
    const existingUser = await userRepository.findByEmail(userData.email);
    if (existingUser) {
      throw new Error('User already exists with this email');
    }

    // Generate email verification token
    const emailVerificationToken = generateRandomToken();

    // Create user
    const user = await userRepository.create({
      ...userData,
      emailVerificationToken,
    });

    // Create default profile
    await Profile.create({ userId: user.id });

    // Send verification email
    emailService
      .sendVerificationEmail(user.email, emailVerificationToken)
      .catch((error) => logger.error('Failed to send verification email', error));

    // Generate JWT token
    const token = generateToken({ userId: user.id, email: user.email });

    return {
      user: user.toSafeObject(),
      token,
    };
  }

  async login(email: string, password: string): Promise<IAuthResponse> {
    logger.info('User login attempt', { email });

    // Find user with roles
    const user = await userRepository.findByEmailWithRoles(email);
    if (!user) {
      throw new Error('Invalid email or password');
    }

    // Validate password
    const isValidPassword = await user.validatePassword(password);
    if (!isValidPassword) {
      throw new Error('Invalid email or password');
    }

    // Check if user is active
    if (!user.isActive) {
      throw new Error('Account is deactivated');
    }

    // Update last login
    userRepository
      .updateLastLogin(user.id)
      .catch((error) => logger.error('Failed to update last login', error));

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
  }

  async refreshToken(tokenData: IRefreshTokenRequest): Promise<{ token: string }> {
    try {
      const decoded = verifyToken(tokenData.token) as IJwtPayload;
      const user = await userRepository.findById(decoded.userId);

      if (!user || !user.isActive) {
        throw new Error('Invalid token');
      }

      const newToken = generateToken({
        userId: user.id,
        email: user.email,
      });

      return { token: newToken };
    } catch (error) {
      throw new Error('Invalid or expired token');
    }
  }

  async verifyEmail(token: string): Promise<{ message: string }> {
    const user = await userRepository.findByVerificationToken(token);
    if (!user) {
      throw new Error('Invalid verification token');
    }

    await userRepository.setEmailVerified(user.id);

    return { message: 'Email verified successfully' };
  }

  async requestPasswordReset(email: string): Promise<{ message: string }> {
    const user = await userRepository.findByEmail(email);
    if (!user) {
      throw new Error('User not found');
    }

    const resetToken = generateRandomToken();
    const resetExpires = new Date(Date.now() + 3600000); // 1 hour

    await userRepository.update(user.id, {
      passwordResetToken: resetToken,
      passwordResetExpires: resetExpires,
    });

    emailService
      .sendPasswordResetEmail(email, resetToken)
      .catch((error) => logger.error('Failed to send password reset email', error));

    return { message: 'Password reset email sent' };
  }
}

export const authService = new AuthService();