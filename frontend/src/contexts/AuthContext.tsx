import React, { createContext, useContext, useState, useEffect, type ReactNode } from 'react';
import * as Types from '../types';

type AuthUser = Types.AuthUser;
type LoginRequest = Types.LoginRequest;
import apiService from '../services/api';

interface AuthContextType {
  user: AuthUser | null;
  loading: boolean;
  login: (credentials: LoginRequest) => Promise<void>;
  logout: () => Promise<void>;
  isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    checkAuthStatus();
  }, []);

  const checkAuthStatus = async () => {
    try {
      const token = localStorage.getItem('access_token');
      if (token) {
        const currentUser = await apiService.getCurrentUser();
        setUser({
          id: currentUser.id,
          email: currentUser.email,
          first_name: currentUser.first_name,
          last_name: currentUser.last_name,
          is_staff: currentUser.is_staff,
          tenant: currentUser.tenants && currentUser.tenants.length > 0 ? {
            id: currentUser.tenants[0].id.toString(),
            name: currentUser.tenants[0].name,
            domain: currentUser.tenants[0].slug,
            is_active: currentUser.tenants[0].is_active ?? true,
            created_at: '',
            settings: {} as any
          } : null as any,
        });
      }
    } catch (error) {
      // Token is invalid, remove it
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
    } finally {
      setLoading(false);
    }
  };

  const login = async (credentials: LoginRequest) => {
    try {
      const response = await apiService.login(credentials);
      
      // Store tokens
      localStorage.setItem('access_token', response.access);
      localStorage.setItem('refresh_token', response.refresh);
      
      // Set user state
      setUser({
        id: response.user.id,
        email: response.user.email,
        first_name: response.user.first_name,
        last_name: response.user.last_name,
        is_staff: response.user.is_staff,
        tenant: response.user.tenants && response.user.tenants.length > 0 ? {
           id: response.user.tenants[0].id.toString(),
           name: response.user.tenants[0].name,
           domain: response.user.tenants[0].slug,
           is_active: response.user.tenants[0].is_active ?? true,
           created_at: '',
           settings: {} as any
         } : null as any,
      });
    } catch (error) {
      throw error;
    }
  };

  const logout = async () => {
    try {
      await apiService.logout();
    } catch (error) {
      // Ignore logout errors
    } finally {
      setUser(null);
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
    }
  };

  const value: AuthContextType = {
    user,
    loading,
    login,
    logout,
    isAuthenticated: !!user,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};