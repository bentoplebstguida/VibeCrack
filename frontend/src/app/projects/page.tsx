"use client";

import { useState } from "react";
import AuthGuard from "@/components/ui/AuthGuard";
import { useProjects } from "@/hooks/useProjects";
import { useStartScan } from "@/hooks/useScan";
import { useRouter } from "next/navigation";
import {
  Plus,
  Globe,
  Trash2,
  Play,
  X,
  ExternalLink,
} from "lucide-react";
import { gradeToColor } from "@/lib/scoring";

export default function ProjectsPage() {
  return (
    <AuthGuard>
      <ProjectsContent />
    </AuthGuard>
  );
}

function ProjectsContent() {
  const { projects, loading, addProject, removeProject } = useProjects();
  const { startScan, starting } = useStartScan();
  const router = useRouter();
  const [showForm, setShowForm] = useState(false);
  const [formData, setFormData] = useState({
    name: "",
    domain: "",
    description: "",
  });
  const [formError, setFormError] = useState("");
  const [scanError, setScanError] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError("");

    // Validate domain
    let domain = formData.domain.trim();
    if (!domain.startsWith("http://") && !domain.startsWith("https://")) {
      domain = "https://" + domain;
    }

    try {
      new URL(domain);
    } catch {
      setFormError("URL invalida. Exemplo: https://meusite.com.br");
      return;
    }

    try {
      await addProject({
        name: formData.name.trim(),
        domain,
        description: formData.description.trim(),
      });
      setFormData({ name: "", domain: "", description: "" });
      setShowForm(false);
    } catch (err: unknown) {
      setFormError(
        err instanceof Error ? err.message : "Erro ao criar projeto"
      );
    }
  };

  const handleStartScan = async (projectId: string, domain: string) => {
    setScanError("");
    try {
      const scanId = await startScan(projectId, domain);
      router.push(`/scans/detail?scanId=${scanId}`);
    } catch (err: unknown) {
      console.error("Erro ao iniciar scan:", err);
      setScanError(
        err instanceof Error
          ? err.message
          : "Falha ao iniciar scan. Tente novamente."
      );
    }
  };

  const handleDelete = async (projectId: string, name: string) => {
    if (confirm(`Tem certeza que quer deletar "${name}"?`)) {
      await removeProject(projectId);
    }
  };

  return (
    <div className="max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-white">Projetos</h1>
          <p className="text-gray-400 mt-1">
            Gerencie seus dominios e aplicacoes
          </p>
        </div>
        <button
          onClick={() => setShowForm(true)}
          className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-700 text-white font-medium px-5 py-2.5 rounded-lg transition-colors"
        >
          <Plus className="w-4 h-4" />
          Novo Projeto
        </button>
      </div>

      {/* New Project Form */}
      {scanError && (
        <div className="bg-red-500/10 border border-red-500/20 text-red-400 px-4 py-3 rounded-lg mb-6 text-sm">
          {scanError}
        </div>
      )}

      {showForm && (
        <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 mb-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-white">Novo Projeto</h2>
            <button
              onClick={() => setShowForm(false)}
              className="text-gray-500 hover:text-white"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {formError && (
            <div className="bg-red-500/10 border border-red-500/20 text-red-400 px-4 py-3 rounded-lg mb-4 text-sm">
              {formError}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm text-gray-400 mb-2">
                  Nome do Projeto
                </label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) =>
                    setFormData({ ...formData, name: e.target.value })
                  }
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-emerald-500"
                  placeholder="Minha App de Vendas"
                  required
                />
              </div>
              <div>
                <label className="block text-sm text-gray-400 mb-2">
                  Dominio / URL
                </label>
                <input
                  type="text"
                  value={formData.domain}
                  onChange={(e) =>
                    setFormData({ ...formData, domain: e.target.value })
                  }
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-emerald-500"
                  placeholder="https://minhaapp.com.br"
                  required
                />
              </div>
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-2">
                Descricao (opcional)
              </label>
              <input
                type="text"
                value={formData.description}
                onChange={(e) =>
                  setFormData({ ...formData, description: e.target.value })
                }
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-emerald-500"
                placeholder="App principal de vendas online"
              />
            </div>
            <div className="flex gap-3">
              <button
                type="submit"
                className="bg-emerald-600 hover:bg-emerald-700 text-white font-medium px-6 py-2.5 rounded-lg transition-colors"
              >
                Criar Projeto
              </button>
              <button
                type="button"
                onClick={() => setShowForm(false)}
                className="bg-gray-800 hover:bg-gray-700 text-gray-300 font-medium px-6 py-2.5 rounded-lg transition-colors"
              >
                Cancelar
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Projects List */}
      {loading ? (
        <div className="text-center py-12 text-gray-500">Carregando...</div>
      ) : projects.length === 0 && !showForm ? (
        <div className="bg-gray-900 border border-gray-800 rounded-2xl p-12 text-center">
          <Globe className="w-16 h-16 text-gray-700 mx-auto mb-4" />
          <h3 className="text-xl font-semibold text-white mb-2">
            Nenhum projeto
          </h3>
          <p className="text-gray-500 mb-6">
            Cadastre seu primeiro dominio para comecar a analise de seguranca
          </p>
          <button
            onClick={() => setShowForm(true)}
            className="bg-emerald-600 hover:bg-emerald-700 text-white font-medium px-6 py-3 rounded-lg transition-colors"
          >
            Adicionar Primeiro Projeto
          </button>
        </div>
      ) : (
        <div className="grid gap-4">
          {projects.map((project) => (
            <div
              key={project.id}
              className="bg-gray-900 border border-gray-800 rounded-xl p-6"
            >
              <div className="flex items-start gap-4">
                {/* Score */}
                <div
                  className="w-16 h-16 rounded-xl flex items-center justify-center font-bold text-xl shrink-0"
                  style={{
                    backgroundColor: project.currentGrade
                      ? `${gradeToColor(project.currentGrade)}15`
                      : "#1f2937",
                    color: project.currentGrade
                      ? gradeToColor(project.currentGrade)
                      : "#4b5563",
                  }}
                >
                  {project.currentGrade || "--"}
                </div>

                {/* Info */}
                <div className="flex-1 min-w-0">
                  <h3 className="text-lg font-semibold text-white">
                    {project.name}
                  </h3>
                  <div className="flex items-center gap-2 mt-1">
                    <Globe className="w-4 h-4 text-gray-500" />
                    <a
                      href={project.domain}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-gray-400 hover:text-emerald-400 text-sm flex items-center gap-1"
                    >
                      {project.domain}
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  </div>
                  {project.description && (
                    <p className="text-gray-500 text-sm mt-1">
                      {project.description}
                    </p>
                  )}
                  <div className="flex items-center gap-4 mt-3">
                    {project.currentScore !== null && (
                      <span className="text-sm text-gray-400">
                        Score: {project.currentScore}/100
                      </span>
                    )}
                    <span className="text-sm text-gray-600">
                      {project.totalScans} scan
                      {project.totalScans !== 1 ? "s" : ""}
                    </span>
                  </div>
                </div>

                {/* Actions */}
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={() =>
                      handleStartScan(project.id, project.domain)
                    }
                    disabled={starting}
                    className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors"
                  >
                    <Play className="w-4 h-4" />
                    {starting ? "Iniciando..." : "Escanear"}
                  </button>
                  <button
                    onClick={() => handleDelete(project.id, project.name)}
                    className="text-gray-600 hover:text-red-400 p-2 rounded-lg hover:bg-gray-800 transition-colors"
                    title="Deletar projeto"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
