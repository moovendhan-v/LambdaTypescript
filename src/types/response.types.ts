// src/types/response.types.ts
export interface ApiResponse<T = any> {
    statusCode: number;
    headers: Record<string, string>;
    body: string;
  }
  
  export interface SuccessResponse<T = any> {
    success: true;
    data: T;
    message?: string;
  }
  
  export interface ErrorResponse {
    success: false;
    error: {
      message: string;
      details?: any;
    };
  }
  
  export interface PaginationResponse<T = any> {
    items: T[];
    pagination: {
      total: number;
      page: number;
      limit: number;
      totalPages: number;
    };
  }