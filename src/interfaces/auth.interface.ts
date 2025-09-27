import { IUserResponse } from "./user.interface";

// src/interfaces/auth.interface.ts
export interface ILoginRequest {
    email: string;
    password: string;
  }
  
  export interface IRegisterRequest {
    email: string;
    password: string;
    firstName: string;
    lastName: string;
  }
  
  export interface IAuthResponse {
    user: IUserResponse;
    token: string;
  }
  
  
  export interface IRefreshTokenRequest {
    token: string;
  }