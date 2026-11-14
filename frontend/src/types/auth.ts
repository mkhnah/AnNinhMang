export type UserRole = 'USER' | 'ADMIN';
export type UserStatus = 'ACTIVE' | 'LOCKED' | 'DISABLED';

export interface User {
  id: string;
  email: string;
  full_name: string;
  role: UserRole;
  status: UserStatus;
  created_at: string;
  last_login_at?: string | null;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  user: User;
}

export interface AdminOverview {
  total_users: number;
  active_users: number;
  locked_users: number;
  admin_users: number;
  users: User[];
}
