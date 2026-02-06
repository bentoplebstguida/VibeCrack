"use client";

import { useParams } from "next/navigation";
import AuthGuard from "@/components/ui/AuthGuard";
import ScanProgress from "@/components/scans/ScanProgress";
import ScanSummary from "@/components/scans/ScanSummary";
import VulnerabilityCard from "@/components/scans/VulnerabilityCard";
import { useScan } from "@/hooks/useScan";
import { ArrowLeft, Globe, Clock, ScrollText } from "lucide-react";
import Link from "next/link";

export default function ScanDetailPage() {
  return (
    <AuthGuard>
      <ScanDetailContent />
    </AuthGuard>
  );
}

function ScanDetailContent() {
  const params = useParams();
  const scanId = params?.scanId as string;
  const { scan, vulnerabilities, logs, loading } = useScan(scanId);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="w-10 h-10 border-4 border-emerald-500/30 border-t-emerald-500 rounded-full animate-spin" />
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="text-center py-20">
        <p className="text-gray-400">Scan nao encontrado</p>
        <Link
          href="/dashboard"
          className="text-emerald-500 hover:text-emerald-400 mt-4 inline-block"
        >
          Voltar ao Dashboard
        </Link>
      </div>
    );
  }

  return (
    <div className="max-w-5xl mx-auto">
      {/* Header */}
      <div className="mb-6">
        <Link
          href="/dashboard"
          className="text-gray-500 hover:text-white text-sm flex items-center gap-2 mb-4"
        >
          <ArrowLeft className="w-4 h-4" />
          Voltar
        </Link>
        <h1 className="text-2xl font-bold text-white">Detalhe do Scan</h1>
        <div className="flex items-center gap-4 mt-2">
          <div className="flex items-center gap-2 text-gray-400 text-sm">
            <Globe className="w-4 h-4" />
            {scan.domain}
          </div>
          <div className="flex items-center gap-2 text-gray-500 text-sm">
            <Clock className="w-4 h-4" />
            {scan.scanType === "full"
              ? "Scan Completo"
              : scan.scanType === "quick"
              ? "Scan Rapido"
              : "Scan Custom"}
          </div>
        </div>
      </div>

      {/* Progress */}
      <div className="mb-6">
        <ScanProgress scan={scan} />
      </div>

      {/* Summary */}
      <div className="mb-6">
        <ScanSummary scan={scan} />
      </div>

      {/* Vulnerabilities */}
      {vulnerabilities.length > 0 && (
        <div className="mb-6">
          <h2 className="text-lg font-semibold text-white mb-4">
            Vulnerabilidades ({vulnerabilities.length})
          </h2>
          <div className="space-y-3">
            {vulnerabilities.map((vuln) => (
              <VulnerabilityCard key={vuln.id} vuln={vuln} />
            ))}
          </div>
        </div>
      )}

      {/* Logs */}
      {logs.length > 0 && (
        <div>
          <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <ScrollText className="w-5 h-5 text-gray-400" />
            Logs ({logs.length})
          </h2>
          <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <div className="max-h-96 overflow-y-auto p-4 font-mono text-xs space-y-1">
              {logs.map((log) => (
                <div key={log.id} className="flex gap-3">
                  <span className="text-gray-600 shrink-0">
                    {log.timestamp?.toDate?.()
                      ? log.timestamp.toDate().toLocaleTimeString()
                      : "--:--:--"}
                  </span>
                  <span
                    className={`shrink-0 uppercase font-bold ${
                      log.level === "error"
                        ? "text-red-400"
                        : log.level === "warning"
                        ? "text-yellow-400"
                        : log.level === "info"
                        ? "text-blue-400"
                        : "text-gray-500"
                    }`}
                  >
                    [{log.level}]
                  </span>
                  <span className="text-gray-400">{log.message}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
