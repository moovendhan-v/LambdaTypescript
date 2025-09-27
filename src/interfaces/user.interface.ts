// src/interfaces/user.interface.ts
export interface IUser {
    id: string;
    email: string;
    firstName: string;
    lastName: string;
    isActive: boolean;
    emailVerified: boolean;
    lastLoginAt?: Date;
    createdAt: Date;
    updatedAt: Date;
  }
  
  export interface IUserWithPassword extends IUser {
    password: string;
    emailVerificationToken?: string;
    passwordResetToken?: string;
    passwordResetExpires?: Date;
  }
  
  export interface ICreateUserRequest {
    email: string;
    password: string;
    firstName: string;
    lastName: string;
  }
  
  export interface IUpdateUserRequest {
    firstName?: string;
    lastName?: string;
    isActive?: boolean;
  }
  
  export interface IUserResponse {
    id: string;
    email: string;
    firstName: string;
    lastName: string;
    isActive: boolean;
    emailVerified: boolean;
    lastLoginAt?: Date;
    profile?: IProfile;
    roles?: IRole[];
  }
  
  export interface IProfile {
    id: string;
    userId: string;
    avatar?: string;
    bio?: string;
    phoneNumber?: string;
    dateOfBirth?: Date;
    address?: Record<string, any>;
    preferences: Record<string, any>;
    createdAt: Date;
    updatedAt: Date;
  }
  
  export interface IRole {
    id: string;
    name: string;
    description?: string;
    permissions: string[];
    createdAt: Date;
    updatedAt: Date;
  }