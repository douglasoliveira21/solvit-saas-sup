import React, { useState, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';
import type { TenantSettings as TenantSettingsType } from '../types';
import {
  Save,
  RotateCcw,
  Download,
  Shield,
  Clock,
  FileText,
  RefreshCw,
  Mail,
  Palette,
  Users,
  Settings,
  AlertTriangle,
} from 'lucide-react';

// Componentes UI simples
const Card = ({ children, className = '' }: { children: React.ReactNode; className?: string }) => (
  <div className={`rounded-lg border border-gray-200 bg-white shadow-sm ${className}`}>{children}</div>
);

const CardHeader = ({ children, className = '' }: { children: React.ReactNode; className?: string }) => (
  <div className={`flex flex-col space-y-1.5 p-6 ${className}`}>{children}</div>
);

const CardTitle = ({ children, className = '' }: { children: React.ReactNode; className?: string }) => (
  <h3 className={`text-2xl font-semibold leading-none tracking-tight ${className}`}>{children}</h3>
);

const CardDescription = ({ children, className = '' }: { children: React.ReactNode; className?: string }) => (
  <p className={`text-sm text-gray-600 ${className}`}>{children}</p>
);

const CardContent = ({ children, className = '' }: { children: React.ReactNode; className?: string }) => (
  <div className={`p-6 pt-0 ${className}`}>{children}</div>
);

const Button = ({ children, onClick, variant = 'default', className = '', disabled = false }: {
  children: React.ReactNode;
  onClick?: () => void;
  variant?: 'default' | 'destructive' | 'outline';
  className?: string;
  disabled?: boolean;
}) => {
  const baseClasses = 'inline-flex items-center justify-center rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-gray-400 focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 h-10 px-4 py-2';
  const variantClasses = {
    default: 'bg-gray-900 text-gray-50 hover:bg-gray-900/90',
    destructive: 'bg-red-500 text-gray-50 hover:bg-red-500/90',
    outline: 'border border-gray-200 bg-white hover:bg-gray-100 hover:text-gray-900',
  };
  
  return (
    <button
      className={`${baseClasses} ${variantClasses[variant]} ${className}`}
      onClick={onClick}
      disabled={disabled}
    >
      {children}
    </button>
  );
};

const Input = ({ className = '', type = 'text', value, onChange, placeholder, ...props }: {
  className?: string;
  type?: string;
  value?: string | number;
  onChange?: (e: React.ChangeEvent<HTMLInputElement>) => void;
  placeholder?: string;
  [key: string]: any;
}) => (
  <input
    type={type}
    className={`flex h-10 w-full rounded-md border border-gray-200 bg-white px-3 py-2 text-sm ring-offset-white file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-gray-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-gray-400 focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 ${className}`}
    value={value}
    onChange={onChange}
    placeholder={placeholder}
    {...props}
  />
);

const Label = ({ children, htmlFor, className = '' }: {
  children: React.ReactNode;
  htmlFor?: string;
  className?: string;
}) => (
  <label htmlFor={htmlFor} className={`text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70 ${className}`}>
    {children}
  </label>
);

const Switch = ({ checked, onCheckedChange, className = '' }: {
  checked?: boolean;
  onCheckedChange?: (checked: boolean) => void;
  className?: string;
}) => (
  <button
    type="button"
    role="switch"
    aria-checked={checked}
    className={`peer inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-gray-400 focus-visible:ring-offset-2 focus-visible:ring-offset-white disabled:cursor-not-allowed disabled:opacity-50 ${
      checked ? 'bg-gray-900' : 'bg-gray-200'
    } ${className}`}
    onClick={() => onCheckedChange?.(!checked)}
  >
    <span className={`pointer-events-none block h-5 w-5 rounded-full bg-white shadow-lg ring-0 transition-transform ${
      checked ? 'translate-x-5' : 'translate-x-0'
    }`} />
  </button>
);

const Textarea = ({ className = '', value, onChange, placeholder, rows = 3, ...props }: {
  className?: string;
  value?: string;
  onChange?: (e: React.ChangeEvent<HTMLTextAreaElement>) => void;
  placeholder?: string;
  rows?: number;
  [key: string]: any;
}) => (
  <textarea
    className={`flex min-h-[80px] w-full rounded-md border border-gray-200 bg-white px-3 py-2 text-sm ring-offset-white placeholder:text-gray-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-gray-400 focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 ${className}`}
    value={value}
    onChange={onChange}
    placeholder={placeholder}
    rows={rows}
    {...props}
  />
);

const Alert = ({ children, className = '' }: { children: React.ReactNode; className?: string }) => (
  <div className={`relative w-full rounded-lg border border-gray-200 p-4 ${className}`}>
    {children}
  </div>
);

const AlertDescription = ({ children, className = '' }: { children: React.ReactNode; className?: string }) => (
  <div className={`text-sm ${className}`}>{children}</div>
);

// Hook para toast
const useToast = () => {
  return {
    toast: ({ title, description, variant }: { title: string; description: string; variant?: string }) => {
      console.log(`${title}: ${description}`);
      // Implementação simples de toast
      alert(`${title}: ${description}`);
    }
  };
};

// Cliente API simples
const apiClient = {
  get: async (url: string) => {
    const response = await fetch(url, {
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('token')}`,
        'Content-Type': 'application/json',
      },
    });
    return response.json();
  },
  post: async (url: string, data: any) => {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('token')}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(data),
    });
    return response.json();
  },
  put: async (url: string, data: any) => {
    const response = await fetch(url, {
      method: 'PUT',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('token')}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(data),
    });
    return response.json();
  },
};

export const TenantSettings: React.FC = () => {
  const { user } = useAuth();
  const { toast } = useToast();
  const [settings, setSettings] = useState<TenantSettingsType | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState('security');
  const [showResetDialog, setShowResetDialog] = useState(false);

  // Carregar configurações do tenant
  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    try {
      setLoading(true);
      setError(null);
      const primaryTenant = user?.tenants?.[0];
      const response = await apiClient.get(`/api/tenants/tenant-settings/?tenant=${primaryTenant?.id?.toString()}`);
      setSettings(response.results?.[0] || getDefaultSettings());
    } catch (err) {
      setError('Erro ao carregar configurações');
      setSettings(getDefaultSettings());
    } finally {
      setLoading(false);
    }
  };

  const getDefaultSettings = (): TenantSettingsType => ({
    id: '',
    tenant: user?.tenants?.[0]?.id?.toString() || '',
    password_min_length: 8,
    password_require_uppercase: true,
    password_require_lowercase: true,
    password_require_numbers: true,
    password_require_symbols: false,
    password_expiry_days: 90,
    account_lockout_attempts: 5,
    account_lockout_duration: 30,
    session_timeout_minutes: 60,
    max_concurrent_sessions: 3,
    audit_log_retention_days: 365,
    audit_events_enabled: true,
    sync_user_attributes: ['email', 'first_name', 'last_name'],
    sync_group_attributes: ['name', 'description'],
    auto_create_users: true,
    auto_deactivate_users: false,
    email_notifications_enabled: true,
    ui_theme: 'light',
    ui_language: 'pt-BR',
    ui_timezone: 'America/Sao_Paulo',
    max_users: 1000,
    max_groups: 100,
    custom_settings: {},
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  });

  const saveSettings = async () => {
    if (!settings) return;

    try {
      setSaving(true);
      setError(null);

      if (settings.id) {
        await apiClient.put(`/api/tenants/tenant-settings/${settings.id}/`, settings);
      } else {
        const response = await apiClient.post('/api/tenants/tenant-settings/', settings);
        setSettings(response);
      }

      toast({
        title: 'Sucesso',
        description: 'Configurações salvas com sucesso!',
        variant: 'default',
      });
    } catch (err) {
      setError('Erro ao salvar configurações');
      toast({
        title: 'Erro',
        description: 'Erro ao salvar configurações',
        variant: 'destructive',
      });
    } finally {
      setSaving(false);
    }
  };

  const resetSettings = async () => {
    try {
      setSaving(true);
      setError(null);

      if (settings?.id) {
        await apiClient.post(`/api/tenants/tenant-settings/${settings.id}/reset/`, {});
      }

      await loadSettings();
      setShowResetDialog(false);

      toast({
        title: 'Sucesso',
        description: 'Configurações resetadas para os valores padrão!',
        variant: 'default',
      });
    } catch (err) {
      setError('Erro ao resetar configurações');
      toast({
        title: 'Erro',
        description: 'Erro ao resetar configurações',
        variant: 'destructive',
      });
    } finally {
      setSaving(false);
    }
  };

  const exportSettings = () => {
    if (!settings) return;

    const dataStr = JSON.stringify(settings, null, 2);
    const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
    
    const exportFileDefaultName = `tenant-settings-${user?.tenant?.name || 'export'}-${new Date().toISOString().split('T')[0]}.json`;
    
    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportFileDefaultName);
    linkElement.click();
  };

  const updateSetting = (key: keyof TenantSettingsType, value: any) => {
    if (!settings) return;
    setSettings({ ...settings, [key]: value });
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-gray-900"></div>
      </div>
    );
  }

  if (!settings) {
    return (
      <Alert className="border-red-200 bg-red-50">
        <AlertTriangle className="h-4 w-4" />
        <AlertDescription>
          Erro ao carregar configurações do tenant.
        </AlertDescription>
      </Alert>
    );
  }

  const tabs = [
    { id: 'security', label: 'Segurança', icon: Shield },
    { id: 'session', label: 'Sessão', icon: Clock },
    { id: 'audit', label: 'Auditoria', icon: FileText },
    { id: 'sync', label: 'Sincronização', icon: RefreshCw },
    { id: 'notifications', label: 'Notificações', icon: Mail },
    { id: 'interface', label: 'Interface', icon: Palette },
    { id: 'limits', label: 'Limites', icon: Users },
    { id: 'custom', label: 'Customizadas', icon: Settings },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Configurações do Tenant</h1>
          <p className="text-gray-600">Gerencie as configurações específicas do seu tenant</p>
        </div>
        <div className="flex space-x-2">
          <Button onClick={exportSettings} variant="outline">
            <Download className="h-4 w-4 mr-2" />
            Exportar
          </Button>
          <Button onClick={() => setShowResetDialog(true)} variant="outline">
            <RotateCcw className="h-4 w-4 mr-2" />
            Resetar
          </Button>
          <Button onClick={saveSettings} disabled={saving}>
            <Save className="h-4 w-4 mr-2" />
            {saving ? 'Salvando...' : 'Salvar'}
          </Button>
        </div>
      </div>

      {/* Error Alert */}
      {error && (
        <Alert className="border-red-200 bg-red-50">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center py-2 px-1 border-b-2 font-medium text-sm ${
                  activeTab === tab.id
                    ? 'border-gray-900 text-gray-900'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <Icon className="h-4 w-4 mr-2" />
                {tab.label}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Tab Content */}
      <div className="space-y-6">
        {/* Segurança */}
        {activeTab === 'security' && (
          <Card>
            <CardHeader>
              <CardTitle>Políticas de Segurança</CardTitle>
              <CardDescription>
                Configure as políticas de senha e bloqueio de conta
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-2">
                  <Label htmlFor="password_min_length">Comprimento mínimo da senha</Label>
                  <Input
                    id="password_min_length"
                    type="number"
                    value={settings.password_min_length}
                    onChange={(e) => updateSetting('password_min_length', parseInt(e.target.value))}
                    min={4}
                    max={128}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="password_expiry_days">Expiração da senha (dias)</Label>
                  <Input
                    id="password_expiry_days"
                    type="number"
                    value={settings.password_expiry_days}
                    onChange={(e) => updateSetting('password_expiry_days', parseInt(e.target.value))}
                    min={0}
                  />
                </div>
              </div>
              
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <Label htmlFor="password_require_uppercase">Exigir letras maiúsculas</Label>
                  <Switch
                    checked={settings.password_require_uppercase}
                    onCheckedChange={(checked) => updateSetting('password_require_uppercase', checked)}
                  />
                </div>
                <div className="flex items-center justify-between">
                  <Label htmlFor="password_require_lowercase">Exigir letras minúsculas</Label>
                  <Switch
                    checked={settings.password_require_lowercase}
                    onCheckedChange={(checked) => updateSetting('password_require_lowercase', checked)}
                  />
                </div>
                <div className="flex items-center justify-between">
                  <Label htmlFor="password_require_numbers">Exigir números</Label>
                  <Switch
                    checked={settings.password_require_numbers}
                    onCheckedChange={(checked) => updateSetting('password_require_numbers', checked)}
                  />
                </div>
                <div className="flex items-center justify-between">
                  <Label htmlFor="password_require_symbols">Exigir símbolos</Label>
                  <Switch
                    checked={settings.password_require_symbols}
                    onCheckedChange={(checked) => updateSetting('password_require_symbols', checked)}
                  />
                </div>
              </div>

              <div className="border-t pt-6">
                <h4 className="text-lg font-medium mb-4">Bloqueio de Conta</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-2">
                    <Label htmlFor="account_lockout_attempts">Tentativas antes do bloqueio</Label>
                    <Input
                      id="account_lockout_attempts"
                      type="number"
                      value={settings.account_lockout_attempts}
                      onChange={(e) => updateSetting('account_lockout_attempts', parseInt(e.target.value))}
                      min={1}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="account_lockout_duration">Duração do bloqueio (minutos)</Label>
                    <Input
                      id="account_lockout_duration"
                      type="number"
                      value={settings.account_lockout_duration}
                      onChange={(e) => updateSetting('account_lockout_duration', parseInt(e.target.value))}
                      min={1}
                    />
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Sessão */}
        {activeTab === 'session' && (
          <Card>
            <CardHeader>
              <CardTitle>Configurações de Sessão</CardTitle>
              <CardDescription>
                Configure o comportamento das sessões de usuário
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-2">
                  <Label htmlFor="session_timeout_minutes">Timeout da sessão (minutos)</Label>
                  <Input
                    id="session_timeout_minutes"
                    type="number"
                    value={settings.session_timeout_minutes}
                    onChange={(e) => updateSetting('session_timeout_minutes', parseInt(e.target.value))}
                    min={5}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="max_concurrent_sessions">Máximo de sessões simultâneas</Label>
                  <Input
                    id="max_concurrent_sessions"
                    type="number"
                    value={settings.max_concurrent_sessions}
                    onChange={(e) => updateSetting('max_concurrent_sessions', parseInt(e.target.value))}
                    min={1}
                  />
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Configurações Customizadas */}
        {activeTab === 'custom' && (
          <Card>
            <CardHeader>
              <CardTitle>Configurações Customizadas</CardTitle>
              <CardDescription>
                Adicione configurações específicas em formato JSON
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                <Label htmlFor="custom_settings">Configurações JSON</Label>
                <Textarea
                  id="custom_settings"
                  value={JSON.stringify(settings.custom_settings, null, 2)}
                  onChange={(e) => {
                    try {
                      const parsed = JSON.parse(e.target.value);
                      updateSetting('custom_settings', parsed);
                    } catch (err) {
                      // Ignore invalid JSON while typing
                    }
                  }}
                  placeholder="{}"
                  rows={10}
                  className="font-mono"
                />
              </div>
            </CardContent>
          </Card>
        )}
      </div>

      {/* Reset Dialog */}
      {showResetDialog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
          <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4">
            <div className="mb-4">
              <h2 className="text-lg font-semibold">Resetar Configurações</h2>
              <p className="text-sm text-gray-600 mt-2">
                Tem certeza que deseja resetar todas as configurações para os valores padrão? Esta ação não pode ser desfeita.
              </p>
            </div>
            <div className="flex justify-end space-x-2 mt-4">
              <Button variant="outline" onClick={() => setShowResetDialog(false)}>
                Cancelar
              </Button>
              <Button variant="destructive" onClick={resetSettings}>
                Resetar
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default TenantSettings;