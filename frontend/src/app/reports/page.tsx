"use client";

import AuthGuard from "@/components/ui/AuthGuard";
import { useProjects } from "@/hooks/useProjects";
import { useState, useEffect } from "react";
import { subscribeToScoreHistory, type ScoreHistory } from "@/lib/firestore";
import { gradeToColor } from "@/lib/scoring";
import { BarChart3, TrendingUp } from "lucide-react";

export default function ReportsPage() {
  return (
    <AuthGuard>
      <ReportsContent />
    </AuthGuard>
  );
}

function ReportsContent() {
  const { projects, loading: projectsLoading } = useProjects();
  const [selectedProject, setSelectedProject] = useState<string | null>(null);
  const [scores, setScores] = useState<ScoreHistory[]>([]);
  const [scoresLoading, setScoresLoading] = useState(false);

  useEffect(() => {
    if (projects.length > 0 && !selectedProject) {
      setSelectedProject(projects[0].id);
    }
  }, [projects, selectedProject]);

  useEffect(() => {
    if (!selectedProject) return;
    setScoresLoading(true);
    const unsub = subscribeToScoreHistory(selectedProject, (data) => {
      setScores(data);
      setScoresLoading(false);
    });
    return unsub;
  }, [selectedProject]);

  const selectedProjectData = projects.find((p) => p.id === selectedProject);

  return (
    <div className="max-w-5xl mx-auto">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white">Relatorios</h1>
        <p className="text-gray-400 mt-1">
          Benchmark de seguranca e evolucao dos scores
        </p>
      </div>

      {/* Project Selector */}
      <div className="mb-6">
        <select
          value={selectedProject || ""}
          onChange={(e) => setSelectedProject(e.target.value)}
          className="bg-gray-900 border border-gray-800 text-white rounded-lg px-4 py-3 focus:outline-none focus:border-emerald-500"
        >
          {projects.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name} - {p.domain}
            </option>
          ))}
        </select>
      </div>

      {/* Benchmark - All Projects Comparison */}
      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 mb-6">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <BarChart3 className="w-5 h-5 text-gray-400" />
          Benchmark - Todos os Projetos
        </h2>

        {projectsLoading ? (
          <p className="text-gray-500">Carregando...</p>
        ) : (
          <div className="space-y-3">
            {projects
              .filter((p) => p.currentScore !== null)
              .sort((a, b) => (b.currentScore || 0) - (a.currentScore || 0))
              .map((project) => (
                <div key={project.id} className="flex items-center gap-4">
                  <div className="w-32 truncate text-sm text-gray-400">
                    {project.name}
                  </div>
                  <div className="flex-1">
                    <div className="w-full bg-gray-800 rounded-full h-4">
                      <div
                        className="h-4 rounded-full transition-all"
                        style={{
                          width: `${project.currentScore}%`,
                          backgroundColor: project.currentGrade
                            ? gradeToColor(project.currentGrade)
                            : "#4b5563",
                        }}
                      />
                    </div>
                  </div>
                  <div
                    className="w-16 text-right font-bold text-sm"
                    style={{
                      color: project.currentGrade
                        ? gradeToColor(project.currentGrade)
                        : "#4b5563",
                    }}
                  >
                    {project.currentScore}/100
                  </div>
                  <div
                    className="w-8 text-center font-bold text-sm"
                    style={{
                      color: project.currentGrade
                        ? gradeToColor(project.currentGrade)
                        : "#4b5563",
                    }}
                  >
                    {project.currentGrade}
                  </div>
                </div>
              ))}
            {projects.filter((p) => p.currentScore !== null).length === 0 && (
              <p className="text-gray-500 text-sm">
                Nenhum projeto escaneado ainda
              </p>
            )}
          </div>
        )}
      </div>

      {/* Score History */}
      {selectedProject && (
        <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 mb-6">
          <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <TrendingUp className="w-5 h-5 text-gray-400" />
            Historico - {selectedProjectData?.name}
          </h2>

          {scoresLoading ? (
            <p className="text-gray-500">Carregando...</p>
          ) : scores.length === 0 ? (
            <p className="text-gray-500 text-sm">
              Nenhum historico de score para este projeto
            </p>
          ) : (
            <div className="space-y-4">
              {/* Category Breakdown of latest scan */}
              {scores[0]?.categories && (
                <div>
                  <h3 className="text-sm font-medium text-gray-400 mb-3">
                    Ultimo Scan - Score por Categoria
                  </h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {Object.entries(scores[0].categories).map(
                      ([category, data]) => (
                        <div
                          key={category}
                          className="flex items-center gap-3 bg-gray-800/50 rounded-lg p-3"
                        >
                          <div
                            className="w-10 h-10 rounded-lg flex items-center justify-center font-bold text-sm"
                            style={{
                              backgroundColor: `${gradeToColor(data.grade)}15`,
                              color: gradeToColor(data.grade),
                            }}
                          >
                            {data.grade}
                          </div>
                          <div className="flex-1 min-w-0">
                            <p className="text-sm text-white capitalize">
                              {category.replace(/_/g, " ")}
                            </p>
                            <div className="w-full bg-gray-700 rounded-full h-1.5 mt-1">
                              <div
                                className="h-1.5 rounded-full"
                                style={{
                                  width: `${data.score}%`,
                                  backgroundColor: gradeToColor(data.grade),
                                }}
                              />
                            </div>
                          </div>
                          <span className="text-sm text-gray-400 shrink-0">
                            {data.score}
                          </span>
                        </div>
                      )
                    )}
                  </div>
                </div>
              )}

              {/* Timeline */}
              <div>
                <h3 className="text-sm font-medium text-gray-400 mb-3">
                  Timeline de Scores
                </h3>
                <div className="space-y-2">
                  {scores.map((score) => (
                    <div
                      key={score.id}
                      className="flex items-center gap-4 p-3 bg-gray-800/30 rounded-lg"
                    >
                      <div
                        className="w-10 h-10 rounded-lg flex items-center justify-center font-bold text-sm"
                        style={{
                          backgroundColor: `${gradeToColor(score.grade)}15`,
                          color: gradeToColor(score.grade),
                        }}
                      >
                        {score.grade}
                      </div>
                      <div className="flex-1">
                        <span className="text-white font-medium">
                          {score.overallScore}/100
                        </span>
                      </div>
                      <span className="text-gray-500 text-xs">
                        {score.createdAt?.toDate?.()
                          ? score.createdAt.toDate().toLocaleDateString("pt-BR")
                          : "--"}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
