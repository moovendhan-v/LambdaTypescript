// src/types/jwt.types.ts

export interface IJwtPayload {
  userId: string;
  email: string;
  roles?: string[];
  iat?: number;
  exp?: number;
}

export interface IJwtOptions {
  expiresIn?: string | number;
  issuer?: string;
  audience?: string;
}

export interface IJwtConfig {
  secret: string;
  expiresIn: string;
  issuer?: string;
  audience?: string;
}