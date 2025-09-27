// src/config/environment.config.ts
import { logger } from '@/utils/logger';

export interface EnvironmentConfig {
  NODE_ENV: string;
  JWT_SECRET: string;
  JWT_EXPIRES_IN: string;
  DB_HOST?: string;
  DB_PORT?: string;
  DB_NAME?: string;
  DB_USER?: string;
  DB_PASSWORD?: string;
  LOG_LEVEL?: string;
  AWS_REGION?: string;
  AWS_LAMBDA_FUNCTION_NAME?: string;
}

export function validateEnvironment(): EnvironmentConfig {
  const requiredEnvVars = ['JWT_SECRET'];

  const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);

  if (missingVars.length > 0) {
    const error = `Missing required environment variables: ${missingVars.join(', ')}`;
    logger.error(error);
    throw new Error(error);
  }

  return {
    NODE_ENV: process.env.NODE_ENV || 'development',
    JWT_SECRET: process.env.JWT_SECRET!,
    JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '1h',
    DB_HOST: process.env.DB_HOST,
    DB_PORT: process.env.DB_PORT,
    DB_NAME: process.env.DB_NAME,
    DB_USER: process.env.DB_USER,
    DB_PASSWORD: process.env.DB_PASSWORD,
    LOG_LEVEL: process.env.LOG_LEVEL,
    AWS_REGION: process.env.AWS_REGION,
    AWS_LAMBDA_FUNCTION_NAME: process.env.AWS_LAMBDA_FUNCTION_NAME,
  };
}

// Validate environment on module load
export const env = validateEnvironment();