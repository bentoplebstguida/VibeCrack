"use client";

import type { Scan } from "@/lib/firestore";
import { Loader2, CheckCircle, XCircle, Clock } from "lucide-react";

const phaseLabels: Record<string, string> = {
  recon_scanner: "Reconhecimento",
  subdomain_scanner: "Subdominios",
  ssl_scanner: "SSL/TLS",
  headers_scanner: "Security Headers",
  secrets_scanner: "Secrets Expostos",
  directory_scanner: "Diretorios Sensiveis",
  xss_scanner: "Cross-Site Scripting",
  sqli_scanner: "SQL Injection",
  csrf_scanner: "CSRF",
  ssrf_scanner: "SSRF / RCE",
  endpoint_scanner: "Endpoints de API",
  zap_scanner: "OWASP ZAP Scan",
  initializing: "Inicializando",
  scoring: "Calculando Score",
  done: "Finalizado",
};

export default function ScanProgress({ scan }: { scan: Scan }) {
  const statusConfig = {
    pending: {
      icon: <Clock className="w-5 h-5 text-yellow-500" />,
      label: "Aguardando",
      color: "yellow",
    },
    running: {
      icon: <Loader2 className="w-5 h-5 text-blue-500 animate-spin" />,
      label: "Em execucao",
      color: "blue",
    },
    completed: {
      icon: <CheckCircle className="w-5 h-5 text-emerald-500" />,
      label: "Concluido",
      color: "emerald",
    },
    failed: {
      icon: <XCircle className="w-5 h-5 text-red-500" />,
      label: "Falhou",
      color: "red",
    },
  };

  const config = statusConfig[scan.status];

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
      {/* Status Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          {config.icon}
          <span className="text-white font-medium">{config.label}</span>
        </div>
        <span className="text-gray-400 text-sm">
          {scan.progress}% completo
        </span>
      </div>

      {/* Progress Bar */}
      <div className="w-full bg-gray-800 rounded-full h-3 mb-4">
        <div
          className={`h-3 rounded-full transition-all duration-500 ${
            scan.status === "completed"
              ? "bg-emerald-500"
              : scan.status === "failed"
              ? "bg-red-500"
              : "bg-blue-500"
          }`}
          style={{ width: `${scan.progress}%` }}
        />
      </div>

      {/* Current Phase */}
      {scan.currentPhase && scan.status === "running" && (
        <p className="text-sm text-gray-400">
          Executando:{" "}
          <span className="text-white">
            {phaseLabels[scan.currentPhase] || scan.currentPhase}
          </span>
        </p>
      )}

      {/* Module Progress */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-2 mt-4">
        {scan.modules.map((mod) => {
          const isActive = scan.currentPhase === `${mod}_scanner`;
          const isPast =
            scan.status === "completed" ||
            (scan.currentPhase &&
              scan.modules.indexOf(mod) <
                scan.modules.indexOf(
                  scan.currentPhase.replace("_scanner", "") as typeof mod
                ));

          return (
            <div
              key={mod}
              className={`text-xs px-3 py-2 rounded-lg text-center ${
                isActive
                  ? "bg-blue-500/10 text-blue-400 border border-blue-500/20"
                  : isPast
                  ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                  : "bg-gray-800 text-gray-500 border border-gray-700"
              }`}
            >
              {phaseLabels[`${mod}_scanner`] || mod}
            </div>
          );
        })}
      </div>
    </div>
  );
}
