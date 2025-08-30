// Group types
export interface Group {
  id: string;
  name: string;
  description?: string;
  tenant: string;
  ad_guid?: string;
  members_count: number;
  created_at: string;
}

export interface CreateGroupRequest {
  name: string;
  description?: string;
}

// User types
export interface User {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  is_active: boolean;
  is_staff: boolean;
  date_joined: string;
  last_login?: string;
  tenant: string;
  ad_username?: string;
  ad_guid?: string;
  groups: Group[];
}

export interface CreateUserRequest {
  email: string;
  first_name: string;
  last_name: string;
  password?: string;
  is_active?: boolean;
  ad_username?: string;
  groups?: string[];
}

export interface UpdateUserRequest {
  email?: string;
  first_name?: string;
  last_name?: string;
  is_active?: boolean;
  groups?: string[];
}

// Tenant types
export interface Tenant {
  id: string;
  name: string;
  domain: string;
  is_active: boolean;
  created_at: string;
  settings: TenantSettings;
}

export interface TenantSettings {
  microsoft_integration_enabled: boolean;
  ad_sync_enabled: boolean;
  audit_retention_days: number;
}

// Auth types
export interface LoginRequest {
  email: string;
  password: string;
}

export interface LoginResponse {
  access: string;
  refresh: string;
  user: User;
}

export interface AuthUser {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  is_staff: boolean;
  tenant: Tenant;
}

// API types
export interface ApiResponse<T> {
  data: T;
  message?: string;
}

export interface PaginatedResponse<T> {
  count: number;
  next?: string;
  previous?: string;
  results: T[];
}

export interface ApiError {
  message: string;
  errors?: Record<string, string[]>;
}

// Audit types
export interface AuditLog {
  id: string;
  user: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  details: Record<string, any>;
  ip_address: string;
  user_agent: string;
  timestamp: string;
  tenant: string;
}

// Agent types
export interface Agent {
  id: string;
  name: string;
  version: string;
  status: 'online' | 'offline' | 'error';
  last_heartbeat: string;
  tenant: string;
  system_info: Record<string, any>;
}

export interface AgentCommand {
  id: string;
  command_type: string;
  parameters: Record<string, any>;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  result?: Record<string, any>;
  created_at: string;
  executed_at?: string;
  agent: string;
}

// Microsoft Graph types
export interface MSGraphUser {
  id: string;
  userPrincipalName: string;
  displayName: string;
  givenName: string;
  surname: string;
  mail: string;
  accountEnabled: boolean;
}

export interface SyncResult {
  id: string;
  sync_type: 'users' | 'groups';
  status: 'running' | 'completed' | 'failed';
  started_at: string;
  completed_at?: string;
  total_records: number;
  processed_records: number;
  errors: string[];
  tenant: string;
}

// UI types
export interface FormField {
  name: string;
  label: string;
  type: 'text' | 'email' | 'password' | 'select' | 'checkbox' | 'textarea';
  required?: boolean;
  placeholder?: string;
  options?: { value: string; label: string }[];
}

export interface TableColumn<T> {
  key: keyof T;
  label: string;
  sortable?: boolean;
  render?: (value: any, row: T) => React.ReactNode;
}

export interface TableProps<T> {
  data: T[];
  columns: TableColumn<T>[];
  loading?: boolean;
  pagination?: {
    current: number;
    total: number;
    pageSize: number;
    onChange: (page: number) => void;
  };
  onSort?: (key: keyof T, direction: 'asc' | 'desc') => void;
}

export interface FilterOption {
  label: string;
  value: string;
}

export interface Filter {
  key: string;
  label: string;
  type: 'text' | 'select' | 'date';
  options?: FilterOption[];
}

export interface FilterState {
  [key: string]: string | string[];
}