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
export interface UserTenant {
  id: number;
  name: string;
  slug: string;
  role: string;
  is_active: boolean;
}

export interface User {
  id: string;
  username: string;
  email: string;
  first_name: string;
  last_name: string;
  is_active?: boolean;
  is_staff?: boolean;
  date_joined: string;
  last_login?: string;
  tenants: UserTenant[];
  ad_username?: string;
  ad_guid?: string;
  groups?: Group[];
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
  id: string;
  tenant: string;
  // Configurações de Segurança
  password_min_length: number;
  password_require_uppercase: boolean;
  password_require_lowercase: boolean;
  password_require_numbers: boolean;
  password_require_symbols: boolean;
  password_expiry_days: number;
  // Configurações de Bloqueio
  account_lockout_attempts: number;
  account_lockout_duration: number;
  // Configurações de Sessão
  session_timeout_minutes: number;
  max_concurrent_sessions: number;
  // Configurações de Auditoria
  audit_log_retention_days: number;
  audit_events_enabled: boolean;
  // Configurações de Sincronização
  sync_user_attributes: string[];
  sync_group_attributes: string[];
  auto_create_users: boolean;
  auto_deactivate_users: boolean;
  // Configurações de Notificação
  email_notifications_enabled: boolean;
  // Configurações de Interface
  ui_theme: 'light' | 'dark' | 'auto';
  ui_language: string;
  ui_timezone: string;
  // Configurações de Limites
  max_users: number;
  max_groups: number;
  // Configurações Customizadas
  custom_settings: Record<string, any>;
  // Timestamps
  created_at: string;
  updated_at: string;
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
  tenants: UserTenant[];
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