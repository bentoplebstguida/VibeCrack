"use client";

import { useState, useEffect } from "react";
import {
  subscribeToScan,
  subscribeToProjectScans,
  subscribeToVulnerabilities,
  subscribeToScanLogs,
  startScan as firebaseStartScan,
  type Scan,
  type Vulnerability,
  type ScanLog,
  type ScanType,
  type ScanModule,
} from "@/lib/firestore";
import { useAuth } from "./useAuth";

export function useScan(scanId: string | null) {
  const [scan, setScan] = useState<Scan | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [logs, setLogs] = useState<ScanLog[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!scanId) {
      setScan(null);
      setLoading(false);
      return;
    }

    setLoading(true);
    const unsubScan = subscribeToScan(scanId, (data) => {
      setScan(data);
      setLoading(false);
    });

    const unsubVulns = subscribeToVulnerabilities(scanId, setVulnerabilities);
    const unsubLogs = subscribeToScanLogs(scanId, setLogs);

    return () => {
      unsubScan();
      unsubVulns();
      unsubLogs();
    };
  }, [scanId]);

  return { scan, vulnerabilities, logs, loading };
}

export function useProjectScans(projectId: string | null) {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!projectId) {
      setScans([]);
      setLoading(false);
      return;
    }

    setLoading(true);
    const unsubscribe = subscribeToProjectScans(projectId, (data) => {
      setScans(data);
      setLoading(false);
    });

    return unsubscribe;
  }, [projectId]);

  return { scans, loading };
}

export function useStartScan() {
  const { uid } = useAuth();
  const [starting, setStarting] = useState(false);

  const startScan = async (
    projectId: string,
    domain: string,
    scanType: ScanType = "full",
    modules?: ScanModule[]
  ) => {
    if (!uid) {
      throw new Error("Usuario nao autenticado. Faca login novamente.");
    }

    setStarting(true);
    try {
      const scanId = await firebaseStartScan(
        uid,
        projectId,
        domain,
        scanType,
        modules
      );
      return scanId;
    } finally {
      setStarting(false);
    }
  };

  return { startScan, starting };
}
