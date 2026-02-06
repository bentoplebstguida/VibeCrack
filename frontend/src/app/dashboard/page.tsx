"use client";

import AuthGuard from "@/components/ui/AuthGuard";
import { useProjects } from "@/hooks/useProjects";
import { useRouter } from "next/navigation";
import {
  Shield,
  Plus,
  ArrowRight,
  AlertTriangle,
  CheckCircle,
  Clock,
} from "lucide-react";
import { gradeToColor } from "@/lib/scoring";

export default function DashboardPage() {
  return (
    <AuthGuard>
      <DashboardContent />
    </AuthGuard>
  );
}

function DashboardContent() {
  const { projects, loading } = useProjects();
  const router = useRouter();

  const stats = {
    totalProjects: projects.length,
    scannedProjects: projects.filter((p) => p.currentScore !== null).length,
    avgScore:
      projects.filter((p) => p.currentScore !== null).length > 0
        ? Math.round(
            projects
              .filter((p) => p.currentScore !== null)
              .reduce((sum, p) => sum + (p.currentScore || 0), 0) /
              projects.filter((p) => p.currentScore !== null).length
          )
        : null,
    criticalProjects: projects.filter(
      (p) => p.currentScore !== null && p.currentScore < 30
    ).length,
  };

  return (
    <div className="max-w-7xl mx-auto">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white">Dashboard</h1>
        <p className="text-gray-400 mt-1">
          Visao geral da seguranca dos seus projetos
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <StatCard
          label="Total Projetos"
          value={stats.totalProjects}
          icon={<Shield className="w-5 h-5" />}
          color="emerald"
        />
        <StatCard
          label="Ja Escaneados"
          value={stats.scannedProjects}
          icon={<CheckCircle className="w-5 h-5" />}
          color="blue"
        />
        <StatCard
          label="Score Medio"
          value={stats.avgScore !== null ? `${stats.avgScore}/100` : "--"}
          icon={<Clock className="w-5 h-5" />}
          color="yellow"
        />
        <StatCard
          label="Estado Critico"
          value={stats.criticalProjects}
          icon={<AlertTriangle className="w-5 h-5" />}
          color="red"
        />
      </div>

      {/* Projects List */}
      <div className="bg-gray-900 border border-gray-800 rounded-2xl">
        <div className="p-6 border-b border-gray-800 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">Seus Projetos</h2>
          <button
            onClick={() => router.push("/projects")}
            className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-700 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors"
          >
            <Plus className="w-4 h-4" />
            Novo Projeto
          </button>
        </div>

        {loading ? (
          <div className="p-12 text-center text-gray-500">Carregando...</div>
        ) : projects.length === 0 ? (
          <div className="p-12 text-center">
            <Shield className="w-12 h-12 text-gray-700 mx-auto mb-4" />
            <p className="text-gray-400 mb-2">Nenhum projeto ainda</p>
            <p className="text-gray-600 text-sm">
              Adicione seu primeiro dominio para comecar a escanear
            </p>
          </div>
        ) : (
          <div className="divide-y divide-gray-800">
            {projects.map((project) => (
              <div
                key={project.id}
                className="p-6 flex items-center gap-4 hover:bg-gray-800/50 transition-colors cursor-pointer"
                onClick={() => router.push(`/projects?id=${project.id}`)}
              >
                {/* Score Badge */}
                <div
                  className="w-14 h-14 rounded-xl flex items-center justify-center font-bold text-lg"
                  style={{
                    backgroundColor: project.currentGrade
                      ? `${gradeToColor(project.currentGrade)}15`
                      : "#374151",
                    color: project.currentGrade
                      ? gradeToColor(project.currentGrade)
                      : "#6b7280",
                  }}
                >
                  {project.currentGrade || "--"}
                </div>

                {/* Info */}
                <div className="flex-1 min-w-0">
                  <h3 className="text-white font-medium">{project.name}</h3>
                  <p className="text-gray-500 text-sm truncate">
                    {project.domain}
                  </p>
                </div>

                {/* Score */}
                <div className="text-right">
                  {project.currentScore !== null ? (
                    <>
                      <p className="text-white font-semibold">
                        {project.currentScore}/100
                      </p>
                      <p className="text-gray-500 text-xs">
                        {project.totalScans} scan
                        {project.totalScans !== 1 ? "s" : ""}
                      </p>
                    </>
                  ) : (
                    <p className="text-gray-600 text-sm">Nao escaneado</p>
                  )}
                </div>

                <ArrowRight className="w-5 h-5 text-gray-600" />
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function StatCard({
  label,
  value,
  icon,
  color,
}: {
  label: string;
  value: string | number;
  icon: React.ReactNode;
  color: string;
}) {
  const colorMap: Record<string, string> = {
    emerald: "bg-emerald-500/10 text-emerald-500 border-emerald-500/20",
    blue: "bg-blue-500/10 text-blue-500 border-blue-500/20",
    yellow: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
    red: "bg-red-500/10 text-red-500 border-red-500/20",
  };

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
      <div className="flex items-center gap-3 mb-3">
        <div
          className={`w-10 h-10 rounded-lg flex items-center justify-center border ${colorMap[color]}`}
        >
          {icon}
        </div>
      </div>
      <p className="text-2xl font-bold text-white">{value}</p>
      <p className="text-sm text-gray-500 mt-1">{label}</p>
    </div>
  );
}
