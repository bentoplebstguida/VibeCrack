"use client";

import type { Scan } from "@/lib/firestore";
import { severityToColor, severityToLabel } from "@/lib/scoring";
import { gradeToColor, scoreToGrade } from "@/lib/scoring";

export default function ScanSummary({ scan }: { scan: Scan }) {
  const severities = [
    { key: "critical" as const, count: scan.summary.critical },
    { key: "high" as const, count: scan.summary.high },
    { key: "medium" as const, count: scan.summary.medium },
    { key: "low" as const, count: scan.summary.low },
    { key: "info" as const, count: scan.summary.info },
  ];

  const totalFindings = severities.reduce((sum, s) => sum + s.count, 0);
  const grade = scan.score !== null ? scoreToGrade(scan.score) : null;

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      {/* Score Card */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 flex items-center gap-6">
        {scan.score !== null && grade ? (
          <>
            <div
              className="w-20 h-20 rounded-2xl flex items-center justify-center font-bold text-3xl"
              style={{
                backgroundColor: `${gradeToColor(grade)}15`,
                color: gradeToColor(grade),
              }}
            >
              {grade}
            </div>
            <div>
              <p className="text-3xl font-bold text-white">{scan.score}/100</p>
              <p className="text-gray-500 text-sm mt-1">Score de seguranca</p>
            </div>
          </>
        ) : (
          <div className="text-gray-500">
            Score sera calculado ao finalizar o scan
          </div>
        )}
      </div>

      {/* Findings Summary */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
        <div className="flex items-center justify-between mb-4">
          <span className="text-gray-400 text-sm">Vulnerabilidades</span>
          <span className="text-white font-bold">{totalFindings} total</span>
        </div>
        <div className="flex gap-2">
          {severities.map((s) => (
            <div
              key={s.key}
              className="flex-1 text-center py-2 rounded-lg"
              style={{
                backgroundColor: s.count > 0 ? `${severityToColor(s.key)}10` : "#1f2937",
              }}
            >
              <p
                className="text-lg font-bold"
                style={{
                  color: s.count > 0 ? severityToColor(s.key) : "#4b5563",
                }}
              >
                {s.count}
              </p>
              <p className="text-xs text-gray-500">
                {severityToLabel(s.key)}
              </p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
