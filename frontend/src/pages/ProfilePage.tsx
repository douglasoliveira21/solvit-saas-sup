import React from 'react';
import { useAuth } from '../contexts/AuthContext';
import { User, Building2, Mail, Calendar, Shield } from 'lucide-react';

const ProfilePage: React.FC = () => {
  const { user } = useAuth();

  if (!user) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-gray-500">Carregando informações do usuário...</div>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Meu Perfil</h1>
        <p className="text-gray-600">Visualize e gerencie suas informações pessoais</p>
      </div>

      {/* Profile Card */}
      <div className="bg-white shadow rounded-lg">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-medium text-gray-900">Informações Pessoais</h2>
        </div>
        <div className="px-6 py-4 space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="flex items-center space-x-3">
              <User className="h-5 w-5 text-gray-400" />
              <div>
                <label className="block text-sm font-medium text-gray-700">Nome Completo</label>
                <p className="text-sm text-gray-900">{user.first_name} {user.last_name}</p>
              </div>
            </div>
            
            <div className="flex items-center space-x-3">
              <Mail className="h-5 w-5 text-gray-400" />
              <div>
                <label className="block text-sm font-medium text-gray-700">Email</label>
                <p className="text-sm text-gray-900">{user.email}</p>
              </div>
            </div>
            
            <div className="flex items-center space-x-3">
              <Shield className="h-5 w-5 text-gray-400" />
              <div>
                <label className="block text-sm font-medium text-gray-700">ID do Usuário</label>
                <p className="text-sm text-gray-900 font-mono">{user.id}</p>
              </div>
            </div>
            
            <div className="flex items-center space-x-3">
              <Shield className="h-5 w-5 text-gray-400" />
              <div>
                <label className="block text-sm font-medium text-gray-700">Tipo de Usuário</label>
                <p className="text-sm text-gray-900">{user.is_staff ? 'Administrador do Sistema' : 'Usuário'}</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Tenant Information */}
      {user.tenant && (
        <div className="bg-white shadow rounded-lg">
          <div className="px-6 py-4 border-b border-gray-200">
            <h2 className="text-lg font-medium text-gray-900">Informações do Tenant</h2>
          </div>
          <div className="px-6 py-4 space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="flex items-center space-x-3">
                <Building2 className="h-5 w-5 text-gray-400" />
                <div>
                  <label className="block text-sm font-medium text-gray-700">Nome do Tenant</label>
                  <p className="text-sm text-gray-900">{user.tenant.name}</p>
                </div>
              </div>
              
              {user.tenant && (
                <>
                  <div className="flex items-center space-x-3">
                    <Shield className="h-5 w-5 text-gray-400" />
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Tenant ID</label>
                      <p className="text-sm text-gray-900 font-mono bg-gray-50 px-2 py-1 rounded border">
                        {user.tenant.id}
                      </p>
                    </div>
                  </div>
                  
                  <div className="flex items-center space-x-3">
                    <Building2 className="h-5 w-5 text-gray-400" />
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Nome do Tenant</label>
                      <p className="text-sm text-gray-900">{user.tenant.name}</p>
                    </div>
                  </div>
                  
                  <div className="flex items-center space-x-3">
                    <Building2 className="h-5 w-5 text-gray-400" />
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Domínio</label>
                      <p className="text-sm text-gray-900">{user.tenant.domain}</p>
                    </div>
                  </div>
                  
                  <div className="flex items-center space-x-3">
                    <Shield className="h-5 w-5 text-gray-400" />
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Status</label>
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                        user.tenant.is_active 
                          ? 'bg-green-100 text-green-800' 
                          : 'bg-red-100 text-red-800'
                      }`}>
                        {user.tenant.is_active ? 'Ativo' : 'Inativo'}
                      </span>
                    </div>
                  </div>
                </>              )}            </div>          </div>        </div>      )}

      {/* Instructions */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
        <div className="flex">
          <div className="flex-shrink-0">
            <Shield className="h-5 w-5 text-blue-400" />
          </div>
          <div className="ml-3">
            <h3 className="text-sm font-medium text-blue-800">Como encontrar seu Tenant ID</h3>
            <div className="mt-2 text-sm text-blue-700">
              <p>O Tenant ID é um identificador único da sua organização no sistema. Você pode encontrá-lo:</p>
              <ul className="mt-2 list-disc list-inside space-y-1">
                <li>Nesta página, na seção "Informações do Tenant"</li>
                <li>Na URL quando navegar pelas páginas do sistema</li>
                <li>Nas configurações do tenant (se você for administrador)</li>
                <li>Nos logs de auditoria do sistema</li>
              </ul>
              <p className="mt-2 font-medium">Seu Tenant ID atual: <span className="font-mono bg-white px-2 py-1 rounded border">{user.tenant?.id}</span></p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ProfilePage;