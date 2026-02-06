import {
  collection,
  doc,
  addDoc,
  updateDoc,
  deleteDoc,
  getDoc,
  getDocs,
  query,
  where,
  orderBy,
  onSnapshot,
  serverTimestamp,
  Timestamp,
  type DocumentData,
  type QueryConstraint,
} from "firebase/firestore";
import { db } from "./firebase";

// ==================== PROJECTS ====================

export interface Project {
  id: string;
  userId: string;
  name: string;
  domain: string;
  description: string;
  currentScore: number | null;
  currentGrade: string | null;
  lastScanAt: Timestamp | null;
  totalScans: number;
  createdAt: Timestamp;
}

export async function createProject(
  userId: string,
  data: { name: string; domain: string; description: string }
): Promise<string> {
  const docRef = await addDoc(collection(db, "projects"), {
    userId,
    name: data.name,
    domain: data.domain,
    description: data.description,
    currentScore: null,
    currentGrade: null,
    lastScanAt: null,
    totalScans: 0,
    createdAt: serverTimestamp(),
  });
  return docRef.id;
}

export async function updateProject(
  projectId: string,
  data: Partial<Pick<Project, "name" | "domain" | "description">>
): Promise<void> {
  await updateDoc(doc(db, "projects", projectId), data);
}

export async function deleteProject(projectId: string): Promise<void> {
  await deleteDoc(doc(db, "projects", projectId));
}

export function subscribeToProjects(
  userId: string,
  callback: (projects: Project[]) => void
) {
  const q = query(
    collection(db, "projects"),
    where("userId", "==", userId),
    orderBy("createdAt", "desc")
  );

  return onSnapshot(q, (snapshot) => {
    const projects = snapshot.docs.map((doc) => ({
      id: doc.id,
      ...doc.data(),
    })) as Project[];
    callback(projects);
  }, (error) => {
    console.error("Firestore projects listener error:", error);
    callback([]);
  });
}

// ==================== SCANS ====================

export type ScanStatus = "pending" | "running" | "completed" | "failed" | "cancelled";
export type ScanType = "full" | "quick" | "custom";
export type ScanModule =
  | "recon"
  | "subdomains"
  | "ssl"
  | "headers"
  | "xss"
  | "sqli"
  | "csrf"
  | "ssrf"
  | "secrets"
  | "directories"
  | "endpoints"
  | "zap";

export interface ScanSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface Scan {
  id: string;
  projectId: string;
  userId: string;
  domain: string;
  status: ScanStatus;
  scanType: ScanType;
  modules: ScanModule[];
  progress: number;
  currentPhase: string | null;
  score: number | null;
  grade: string | null;
  summary: ScanSummary;
  reportUrl: string | null;
  detectedTech: string[];
  startedAt: Timestamp | null;
  completedAt: Timestamp | null;
  createdAt: Timestamp;
}

const ALL_MODULES: ScanModule[] = [
  "recon",
  "subdomains",
  "ssl",
  "headers",
  "secrets",
  "directories",
  "xss",
  "sqli",
  "csrf",
  "ssrf",
  "endpoints",
];

export async function startScan(
  userId: string,
  projectId: string,
  domain: string,
  scanType: ScanType = "full",
  modules?: ScanModule[]
): Promise<string> {
  const docRef = await addDoc(collection(db, "scans"), {
    projectId,
    userId,
    domain,
    status: "pending" as ScanStatus,
    scanType,
    modules: modules || ALL_MODULES,
    progress: 0,
    currentPhase: null,
    score: null,
    grade: null,
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    startedAt: null,
    completedAt: null,
    createdAt: serverTimestamp(),
  });
  return docRef.id;
}

export async function cancelScan(scanId: string): Promise<void> {
  await updateDoc(doc(db, "scans", scanId), {
    status: "cancelled" as ScanStatus,
  });
}

export function subscribeToScan(
  scanId: string,
  callback: (scan: Scan | null) => void
) {
  return onSnapshot(doc(db, "scans", scanId), (snapshot) => {
    if (snapshot.exists()) {
      callback({ id: snapshot.id, ...snapshot.data() } as Scan);
    } else {
      callback(null);
    }
  });
}

export function subscribeToProjectScans(
  projectId: string,
  callback: (scans: Scan[]) => void
) {
  const q = query(
    collection(db, "scans"),
    where("projectId", "==", projectId),
    orderBy("createdAt", "desc")
  );

  return onSnapshot(q, (snapshot) => {
    const scans = snapshot.docs.map((doc) => ({
      id: doc.id,
      ...doc.data(),
    })) as Scan[];
    callback(scans);
  });
}

// ==================== VULNERABILITIES ====================

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface VulnerabilityEvidence {
  url: string;
  payload?: string;
  response_snippet?: string;
  screenshot_url?: string;
}

export interface Vulnerability {
  id: string;
  scanId: string;
  projectId: string;
  scanner: string;
  severity: Severity;
  title: string;
  description: string;
  evidence: VulnerabilityEvidence;
  remediation: string;
  owaspCategory: string;
  cvssScore: number;
  affectedUrl: string;
  createdAt: Timestamp;
}

export function subscribeToVulnerabilities(
  scanId: string,
  callback: (vulns: Vulnerability[]) => void
) {
  const q = query(
    collection(db, "vulnerabilities"),
    where("scanId", "==", scanId),
    orderBy("severity")
  );

  return onSnapshot(q, (snapshot) => {
    const vulns = snapshot.docs.map((doc) => ({
      id: doc.id,
      ...doc.data(),
    })) as Vulnerability[];
    callback(vulns);
  });
}

// ==================== SCAN LOGS ====================

export type LogLevel = "info" | "warning" | "error" | "debug";

export interface ScanLog {
  id: string;
  scanId: string;
  scanner: string;
  level: LogLevel;
  message: string;
  details: Record<string, unknown>;
  timestamp: Timestamp;
}

export function subscribeToScanLogs(
  scanId: string,
  callback: (logs: ScanLog[]) => void
) {
  const q = query(
    collection(db, "scan_logs"),
    where("scanId", "==", scanId),
    orderBy("timestamp", "asc")
  );

  return onSnapshot(q, (snapshot) => {
    const logs = snapshot.docs.map((doc) => ({
      id: doc.id,
      ...doc.data(),
    })) as ScanLog[];
    callback(logs);
  });
}

// ==================== SCORES HISTORY ====================

export interface CategoryScore {
  score: number;
  grade: string;
  weight: number;
}

export interface ScoreHistory {
  id: string;
  projectId: string;
  scanId: string;
  overallScore: number;
  grade: string;
  categories: Record<string, CategoryScore>;
  createdAt: Timestamp;
}

export function subscribeToScoreHistory(
  projectId: string,
  callback: (scores: ScoreHistory[]) => void
) {
  const q = query(
    collection(db, "scores_history"),
    where("projectId", "==", projectId),
    orderBy("createdAt", "desc")
  );

  return onSnapshot(q, (snapshot) => {
    const scores = snapshot.docs.map((doc) => ({
      id: doc.id,
      ...doc.data(),
    })) as ScoreHistory[];
    callback(scores);
  });
}
