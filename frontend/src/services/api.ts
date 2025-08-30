import axios from 'axios';
import type { AxiosInstance, AxiosResponse } from 'axios';
import * as Types from '../types';

type User = Types.User;
type CreateUserRequest = Types.CreateUserRequest;
type UpdateUserRequest = Types.UpdateUserRequest;
type Group = Types.Group;
type CreateGroupRequest = Types.CreateGroupRequest;
type LoginRequest = Types.LoginRequest;
type LoginResponse = Types.LoginResponse;
type PaginatedResponse<T> = Types.PaginatedResponse<T>;
type AuditLog = Types.AuditLog;
type Agent = Types.Agent;
type AgentCommand = Types.AgentCommand;
type SyncResult = Types.SyncResult;
type Tenant = Types.Tenant;
type ApiError = Types.ApiError;

class ApiService {
  private api: AxiosInstance;
  private baseURL: string;

  constructor() {
    this.baseURL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api';
    
    this.api = axios.create({
      baseURL: this.baseURL,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Request interceptor to add auth token
    this.api.interceptors.request.use(
      (config) => {
        const token = localStorage.getItem('access_token');
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor to handle token refresh
    this.api.interceptors.response.use(
      (response) => response,
      async (error) => {
        const originalRequest = error.config;

        if (error.response?.status === 401 && !originalRequest._retry) {
          originalRequest._retry = true;

          try {
            const refreshToken = localStorage.getItem('refresh_token');
            if (refreshToken) {
              const response = await axios.post(`${this.baseURL}/auth/token/refresh/`, {
                refresh: refreshToken,
              });

              const { access } = response.data;
              localStorage.setItem('access_token', access);
              originalRequest.headers.Authorization = `Bearer ${access}`;

              return this.api(originalRequest);
            }
          } catch (refreshError) {
            // Refresh failed, redirect to login
            localStorage.removeItem('access_token');
            localStorage.removeItem('refresh_token');
            window.location.href = '/login';
          }
        }

        return Promise.reject(error);
      }
    );
  }

  // Helper method to handle API errors
  private handleError(error: any): never {
    if (error.response?.data) {
      throw error.response.data as ApiError;
    }
    throw { message: 'Network error occurred' } as ApiError;
  }

  // Auth endpoints
  async login(credentials: LoginRequest): Promise<LoginResponse> {
    try {
      const response: AxiosResponse<LoginResponse> = await this.api.post('/auth/login/', credentials);
      return response.data;
    } catch (error) {
      this.handleError(error);
    }
  }

  async logout(): Promise<void> {
    try {
      const refreshToken = localStorage.getItem('refresh_token');
      if (refreshToken) {
        await this.api.post('/auth/logout/', { refresh: refreshToken });
      }
    } catch (error) {
      // Ignore logout errors
    } finally {
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
    }
  }

  async getCurrentUser(): Promise<User> {
    try {
      const response: AxiosResponse<User> = await this.api.get('/auth/user/');
      return response.data;
    } catch (error) {
      this.handleError(error);
    }
  }

  // User endpoints
  async getUsers(params?: {
    page?: number;
    page_size?: number;
    search?: string;
    is_active?: boolean;
    ordering?: string;
  }): Promise<PaginatedResponse<User>> {
    try {
      const response: AxiosResponse<PaginatedResponse<User>> = await this.api.get('/users/', { params });
      return response.data;
    } catch (error) {
      this.handleError(error);
    }
  }

  async getUser(id: string): Promise<User> {
    try {
      const response: AxiosResponse<User> = await this.api.get(`/users/${id}/`);
      return response.data;
    } catch (error) {
      this.handleError(error);
    }
  }

  async createUser(userData: CreateUserRequest): Promise<User> {
    try {
      const response: AxiosResponse<User> = await this.api.post('/users/', userData);
      return response.data;
    } catch (error) {
      this.handleError(error);
    }
  }

  async updateUser(id: string, userData: UpdateUserRequest): Promise<User> {
    try {
      const response: AxiosResponse<User> = await this.api.patch(`/users/${id}/`, userData);
      return response.data;
    } catch (error) {
      this.handleError(error);
    }
  }

  async deleteUser(id: string): Promise<void> {
    try {
      await this.api.delete(`/users/${id}/`);
    } catch (error) {
      this.handleError(error);
    }
  }

  async activateUser(id: string): Promise<User> {
    try {
      const response: AxiosResponse<User> = await this.api.post(`/users/${id}/activate/`);
      return response.data;
    } catch (error) {
      this.handleError(error);
    }
  }

  async deactivateUser(id: string): Promise<User> {
    try {
      const response: AxiosResponse<User> = await this.api.post(`/users/${id}/deactivate/`);
      return response.data;
    } catch (error) {
      this.handleError(error);
    }
  }

  // Group endpoints
  async getGroups(params?: {
    page?: number;
    page_size?: number;
    search?: string;
    ordering?: string;
  }): Promise<PaginatedResponse<Group>> {
    try {
      const response: AxiosResponse<PaginatedResponse<Group>> = await this.api.get('/groups/', { params });
      return response.data;
    } catch (error) {
      this.handleError(error);
    }
  }

  async getGroup(id: string): Promise<Group> {
    try {
      const response: AxiosResponse<Group> = await this.api.get(`/groups/${id}/`);
      return response.data;
    } catch (error) {
      this.handleError(error);
    }
  }

  async createGroup(groupData: CreateGroupRequest): Promise<Group> {
    try {
      const response: AxiosResponse<Group> = await this.api.post('/groups/', groupData);
      return response.data;
    } catch (error) {
      this.handleError(error);
    }
  }

  async updateGroup(id: string, groupData: Partial<CreateGroupRequest>): Promise<Group> {
    try {
      const response: AxiosResponse<Group> = await this.api.patch(`/groups/${id}/`, groupData);
      return response.data;
    } catch (error) {
      this.handleError(error);
    }
  }

  async deleteGroup(id: string): Promise<void> {
    try {
      await this.api.delete(`/groups/${id}/`);
    } catch (error) {
      this.handleError(error);
    }
  }

  async addUserToGroup(groupId: string, userId: string): Promise<void> {
    try {
      await this.api.post(`/groups/${groupId}/add_user/`, { user_id: userId });
    } catch (error) {
      this.handleError(error);
    }
  }

  async removeUserFromGroup(groupId: string, userId: string): Promise<void> {
    try {
      await this.api.post(`/groups/${groupId}/remove_user/`, { user_id: userId });
    } catch (error) {
      this.handleError(error);
    }
  }

  // Audit endpoints
  async getAuditLogs(params?: {
    page?: number;
    page_size?: number;
    user?: string;
    action?: string;
    resource_type?: string;
    start_date?: string;
    end_date?: string;
  }): Promise<PaginatedResponse<AuditLog>> {
    try {
      const response: AxiosResponse<PaginatedResponse<AuditLog>> = await this.api.get('/audit/', { params });
      return response.data;
    } catch (error) {
      this.handleError(error);
    }
  }

  // Agent endpoints
  async getAgents(): Promise<Agent[]> {
    try {
      const response: AxiosResponse<Agent[]> = await this.api.get('/agents/');
      return response.data;
    } catch (error) {
      this.handleError(error);
    }
  }

  async getAgentCommands(agentId?: string): Promise<AgentCommand[]> {
    try {
      const params = agentId ? { agent: agentId } : {};
      const response: AxiosResponse<AgentCommand[]> = await this.api.get('/agent-commands/', { params });
      return response.data;
    } catch (error) {
      this.handleError(error);
    }
  }

  async sendAgentCommand(command: {
    agent_id: string;
    command_type: string;
    parameters: Record<string, any>;
  }): Promise<AgentCommand> {
    try {
      const response: AxiosResponse<AgentCommand> = await this.api.post('/agent-commands/', command);
      return response.data;
    } catch (error) {
      this.handleError(error);
    }
  }

  // Sync endpoints
  async getSyncResults(params?: {
    page?: number;
    page_size?: number;
    sync_type?: string;
    status?: string;
  }): Promise<PaginatedResponse<SyncResult>> {
    try {
      const response: AxiosResponse<PaginatedResponse<SyncResult>> = await this.api.get('/sync-results/', { params });
      return response.data;
    } catch (error) {
      this.handleError(error);
    }
  }

  async startSync(syncType: 'users' | 'groups'): Promise<SyncResult> {
    try {
      const response: AxiosResponse<SyncResult> = await this.api.post('/sync/', { sync_type: syncType });
      return response.data;
    } catch (error) {
      this.handleError(error);
    }
  }

  // Tenant endpoints
  async getTenant(): Promise<Tenant> {
    try {
      const response: AxiosResponse<Tenant> = await this.api.get('/tenant/');
      return response.data;
    } catch (error) {
      this.handleError(error);
    }
  }

  async updateTenant(tenantData: Partial<Tenant>): Promise<Tenant> {
    try {
      const response: AxiosResponse<Tenant> = await this.api.patch('/tenant/', tenantData);
      return response.data;
    } catch (error) {
      this.handleError(error);
    }
  }

  // Health check
  async healthCheck(): Promise<{ status: string }> {
    try {
      const response: AxiosResponse<{ status: string }> = await this.api.get('/health/');
      return response.data;
    } catch (error) {
      this.handleError(error);
    }
  }
}

export const apiService = new ApiService();
export default apiService;