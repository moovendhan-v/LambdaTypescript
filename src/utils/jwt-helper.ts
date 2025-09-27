import jwt from 'jsonwebtoken';
import { IJwtPayload } from '@/types/jwt.types';

const JWT_SECRET: string = process.env.JWT_SECRET || 'your-secret-key';
const JWT_EXPIRES_IN: string = process.env.JWT_EXPIRES_IN || '1h';

export function generateToken(payload: Omit<IJwtPayload, 'iat' | 'exp'>): string {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN } as any);
}

export function verifyToken(token: string): IJwtPayload {
  return jwt.verify(token, JWT_SECRET as jwt.Secret) as IJwtPayload;
}