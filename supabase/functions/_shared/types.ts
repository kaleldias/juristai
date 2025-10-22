export type Environment = "PROD" | "DEV";

export interface AuthResult {
  authenticated: boolean;
  user: any | null;
  accessToken?: string;
  refreshToken?: string;
  error?: string;
  code?: string;
}

export interface UserProfile {
  id: string;
  email: string;
  role: string;
  plan: string;
  full_name: string;
}

export interface TokenPair {
  accessToken: string;
  refreshToken?: string;
}

export interface CookieOptions {
  httpOnly: boolean;
  secure: boolean;
  sameSite: string;
  path: string;
  maxAge: number;
}

export interface SuccessResponse {
  success: true;
  user: UserProfile;
  access_token?: string;
  refresh_token?: string;
  expires_at?: string;
}

export interface ErrorResponse {
  success?: false;
  error: string;
  code?: string;
  message?: string;
  details?: string;
}

export interface ResetPasswordPayload {
  access_token?: string;
  refresh_token?: string;
  accessToken?: string;
  refreshToken?: string;
  new_password?: string;
  newPassword?: string;
  password?: string;
}
