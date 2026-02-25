"use client";

import { useAuth } from "@/hooks/useAuth";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import {
  collection,
  query,
  where,
  orderBy,
  onSnapshot,
} from "firebase/firestore";
import { db } from "@/lib/firebase";
import type { Scan } from "@/lib/firestore";
import { gradeToColor, scoreToGrade } from "@/lib/scoring";
import {
  Loader2,
  CheckCircle,
  XCircle,
  Clock,
  Globe,
  ArrowRight,
} from "lucide-react";

export default function ScansListClient() {
  const { uid } = useAuth();
  const router = useRouter();
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!uid) {
      return;
    }

    const q = query(
      collection(db, "scans"),
      where("userId", "==", uid),
      orderBy("createdAt", "desc")
    );

    const unsub = onSnapshot(
      q,
      (snap) => {
        const data = snap.docs.map((d) => ({ id: d.id, ...d.data() })) as Scan[];
        setScans(data);
        setLoading(false);
      },
      (error) => {
        console.error("Firestore scans listener error:", error);
        setScans([]);
        setLoading(false);
      }
    );

    return unsub;
  }, [uid]);

  const statusIcon = (status: string) => {
    switch (status) {
      case "pending":
        return <Clock className="w-4 h-4 text-yellow-500" />;
      case "running":
        return <Loader2 className="w-4 h-4 text-blue-500 animate-spin" />;
      case "completed":
        return <CheckCircle className="w-4 h-4 text-emerald-500" />;
      case "failed":
        return <XCircle className="w-4 h-4 text-red-500" />;
      default:
        return null;
    }
  };

  const statusLabel = (status: string) => {
    const labels: Record<string, string> = {
      pending: "Aguardando",
      running: "Em execucao",
      completed: "Concluido",
      failed: "Falhou",
    };
    return labels[status] || status;
  };

  return (
    <div className="max-w-5xl mx-auto">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white">Scans</h1>
        <p className="text-gray-400 mt-1">Historico de todas as analises</p>
      </div>

      {loading ? (
        <div className="text-center py-12 text-gray-500">Carregando...</div>
      ) : scans.length === 0 ? (
        <div className="bg-gray-900 border border-gray-800 rounded-2xl p-12 text-center">
          <p className="text-gray-400">
            Nenhum scan realizado ainda. Va para Projetos e inicie um scan.
          </p>
        </div>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded-2xl divide-y divide-gray-800">
          {scans.map((scan) => {
            const grade =
              scan.score !== null ? scoreToGrade(scan.score) : null;
            return (
              <div
                key={scan.id}
                onClick={() => router.push(`/scans/detail?scanId=${scan.id}`)}
                className="p-5 flex items-center gap-4 hover:bg-gray-800/30 transition-colors cursor-pointer"
              >
                {/* Grade */}
                <div
                  className="w-12 h-12 rounded-xl flex items-center justify-center font-bold"
                  style={{
                    backgroundColor: grade
                      ? `${gradeToColor(grade)}15`
                      : "#1f2937",
                    color: grade ? gradeToColor(grade) : "#4b5563",
                  }}
                >
                  {grade || "--"}
                </div>

                {/* Info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <Globe className="w-4 h-4 text-gray-500" />
                    <span className="text-white text-sm truncate">
                      {scan.domain}
                    </span>
                  </div>
                  <div className="flex items-center gap-3 mt-1">
                    <div className="flex items-center gap-1.5">
                      {statusIcon(scan.status)}
                      <span className="text-xs text-gray-400">
                        {statusLabel(scan.status)}
                      </span>
                    </div>
                    <span className="text-xs text-gray-600">
                      {scan.progress}%
                    </span>
                    {scan.summary.critical > 0 && (
                      <span className="text-xs text-red-400">
                        {scan.summary.critical} critico
                        {scan.summary.critical > 1 ? "s" : ""}
                      </span>
                    )}
                  </div>
                </div>

                {/* Score */}
                <div className="text-right shrink-0">
                  {scan.score !== null ? (
                    <span className="text-white font-semibold">
                      {scan.score}/100
                    </span>
                  ) : (
                    <span className="text-gray-600 text-sm">--</span>
                  )}
                </div>

                <ArrowRight className="w-4 h-4 text-gray-600 shrink-0" />
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
