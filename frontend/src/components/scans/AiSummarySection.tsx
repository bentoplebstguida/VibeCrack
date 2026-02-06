"use client";

import { useState } from "react";
import type { Scan } from "@/lib/firestore";
import { Bot, Copy, Check, ChevronDown, ChevronUp, Download } from "lucide-react";

export default function AiSummarySection({ scan }: { scan: Scan }) {
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);

  if (!scan.aiSummary) return null;

  const handleCopy = async () => {
    await navigator.clipboard.writeText(scan.aiSummary!);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const domain = scan.domain.replace(/https?:\/\//, "").replace(/[/\\:*?"<>|]/g, "_");
    const blob = new Blob([scan.aiSummary!], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `analise-ia_${domain}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
      {/* Header - always visible */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full p-5 flex items-center justify-between hover:bg-gray-800/30 transition-colors"
      >
        <div className="flex items-center gap-3">
          <Bot className="w-5 h-5 text-purple-400" />
          <span className="text-white font-medium">Analise de IA</span>
          <span className="text-xs text-gray-500 bg-gray-800 px-2 py-1 rounded">
            Copie e cole no ChatGPT, Claude, etc.
          </span>
        </div>
        {expanded ? (
          <ChevronUp className="w-5 h-5 text-gray-500" />
        ) : (
          <ChevronDown className="w-5 h-5 text-gray-500" />
        )}
      </button>

      {/* Expanded content */}
      {expanded && (
        <div className="px-5 pb-5 border-t border-gray-800">
          {/* Action buttons */}
          <div className="flex justify-end gap-2 mt-3 mb-2">
            <button
              onClick={handleDownload}
              className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white text-sm font-medium rounded-lg transition-colors"
            >
              <Download className="w-4 h-4" />
              Baixar TXT
            </button>
            <button
              onClick={handleCopy}
              className="flex items-center gap-2 px-4 py-2 bg-purple-600 hover:bg-purple-500 text-white text-sm font-medium rounded-lg transition-colors"
            >
              {copied ? (
                <Check className="w-4 h-4" />
              ) : (
                <Copy className="w-4 h-4" />
              )}
              {copied ? "Copiado!" : "Copiar Tudo"}
            </button>
          </div>
          {/* Content */}
          <pre className="bg-gray-950 border border-gray-800 rounded-lg p-4 font-mono text-xs text-gray-300 overflow-x-auto whitespace-pre-wrap max-h-[600px] overflow-y-auto">
            {scan.aiSummary}
          </pre>
        </div>
      )}
    </div>
  );
}
