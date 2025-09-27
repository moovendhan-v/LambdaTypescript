import { logger } from '@/utils/logger';

export class EmailService {
  async sendVerificationEmail(email: string, token: string): Promise<void> {
    logger.info('Sending verification email', { email, token });
    // TODO: Implement actual email sending (e.g., AWS SES)
    console.log(`Verification email sent to ${email} with token ${token}`);
  }

  async sendPasswordResetEmail(email: string, token: string): Promise<void> {
    logger.info('Sending password reset email', { email, token });
    // TODO: Implement actual email sending (e.g., AWS SES)
    console.log(`Password reset email sent to ${email} with token ${token}`);
  }
}

export const emailService = new EmailService();