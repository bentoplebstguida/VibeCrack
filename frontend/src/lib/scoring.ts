export type Grade = "A+" | "A" | "B" | "C" | "D" | "F";

export function scoreToGrade(score: number): Grade {
  if (score >= 95) return "A+";
  if (score >= 90) return "A";
  if (score >= 70) return "B";
  if (score >= 50) return "C";
  if (score >= 30) return "D";
  return "F";
}

export function gradeToColor(grade: Grade | string): string {
  switch (grade) {
    case "A+":
    case "A":
      return "#22c55e"; // green-500
    case "B":
      return "#84cc16"; // lime-500
    case "C":
      return "#eab308"; // yellow-500
    case "D":
      return "#f97316"; // orange-500
    case "F":
      return "#ef4444"; // red-500
    default:
      return "#6b7280"; // gray-500
  }
}

export function severityToColor(severity: string): string {
  switch (severity) {
    case "critical":
      return "#dc2626"; // red-600
    case "high":
      return "#ef4444"; // red-500
    case "medium":
      return "#f97316"; // orange-500
    case "low":
      return "#eab308"; // yellow-500
    case "info":
      return "#3b82f6"; // blue-500
    default:
      return "#6b7280"; // gray-500
  }
}

export function severityToLabel(severity: string): string {
  const labels: Record<string, string> = {
    critical: "Critico",
    high: "Alto",
    medium: "Medio",
    low: "Baixo",
    info: "Info",
  };
  return labels[severity] || severity;
}
