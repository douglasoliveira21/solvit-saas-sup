import React from 'react';
import { useAuth } from '../contexts/AuthContext';
import { TenantSettings } from '../components/TenantSettings';
import { AlertTriangle } from 'lucide-react';

// Componente Alert simples
const Alert = ({ children, className = '' }: { children: React.ReactNode; className?: string }) => (
  <div className={`rounded-lg border border-red-200 bg-red-50 p-4 ${className}`}>
    <div className="flex">
      <div className="flex-shrink-0">
        <AlertTriangle className="h-5 w-5 text-red-400" />
      </div>
      <div className="ml-3">
        <div className="text-sm text-red-700">{children}</div>
      </div>
    </div>
  </div>
);

export default function TenantSettingsPage() {
  const { user } = useAuth();

  if (!user?.tenant) {
    return (
      <div className="container mx-auto py-6">
        <Alert>
          Você precisa estar associado a um tenant para acessar as configurações.
        </Alert>
      </div>
    );
  }

  // Verificar se o usuário tem permissão de administrador do tenant
  const isAdmin = user.is_staff;
  
  if (!isAdmin) {
    return (
      <div className="container mx-auto py-6">
        <Alert>
          Você não tem permissão para acessar as configurações do tenant.
          Apenas administradores podem modificar essas configurações.
        </Alert>
      </div>
    );
  }

  return (
    <div className="container mx-auto py-6">
      <TenantSettings 
        tenantId={user.tenant.id} 
        tenantName={user.tenant.name}
      />
    </div>
  );
}