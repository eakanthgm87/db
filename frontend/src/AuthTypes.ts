export interface AuthError {
  message: string;
  code?: number;
}

export interface AuthResponse {
  success: boolean;
  user?: {
    userId: string;
    username: string;
    createdAt: number;
  };
  error?: AuthError;
}

export interface LoginCredentials {
  username: string;
  password: string;
}

export interface RegisterCredentials {
  username: string;
  password: string;
}