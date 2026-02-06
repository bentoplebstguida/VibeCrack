"use client";

import AuthGuard from "@/components/ui/AuthGuard";
import { useAuth } from "@/hooks/useAuth";
import { Settings, User, Bell, Shield } from "lucide-react";

export default function SettingsPage() {
  return (
    <AuthGuard>
      <SettingsContent />
    </AuthGuard>
  );
}

function SettingsContent() {
  const { user } = useAuth();

  return (
    <div className="max-w-3xl mx-auto">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white">Configuracoes</h1>
        <p className="text-gray-400 mt-1">Gerencie sua conta e preferencias</p>
      </div>

      {/* Account */}
      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 mb-6">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <User className="w-5 h-5 text-gray-400" />
          Conta
        </h2>
        <div className="space-y-4">
          <div>
            <label className="text-sm text-gray-500">Email</label>
            <p className="text-white">{user?.email || "--"}</p>
          </div>
          <div>
            <label className="text-sm text-gray-500">Nome</label>
            <p className="text-white">{user?.displayName || "Nao definido"}</p>
          </div>
          <div>
            <label className="text-sm text-gray-500">UID</label>
            <p className="text-gray-500 font-mono text-xs">{user?.uid}</p>
          </div>
        </div>
      </div>

      {/* Scan Settings */}
      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 mb-6">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Shield className="w-5 h-5 text-gray-400" />
          Scan
        </h2>
        <p className="text-gray-500 text-sm">
          Configuracoes de agendamento e notificacoes serao adicionadas em breve
          (Fase 5).
        </p>
      </div>

      {/* Notifications */}
      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Bell className="w-5 h-5 text-gray-400" />
          Notificacoes
        </h2>
        <p className="text-gray-500 text-sm">
          Notificacoes por email e Slack serao adicionadas em breve (Fase 5).
        </p>
      </div>
    </div>
  );
}
