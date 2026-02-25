"use client";

import { useState, useEffect } from "react";
import { useAuth } from "./useAuth";
import {
  subscribeToProjects,
  createProject,
  updateProject,
  deleteProject,
  type Project,
} from "@/lib/firestore";

export function useProjects() {
  const { uid } = useAuth();
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!uid) {
      return;
    }

    setLoading(true);
    const unsubscribe = subscribeToProjects(uid, (data) => {
      setProjects(data);
      setLoading(false);
    });

    return unsubscribe;
  }, [uid]);

  const addProject = async (data: {
    name: string;
    domain: string;
    description: string;
  }) => {
    if (!uid) {
      throw new Error("Usuario nao autenticado. Faca login novamente.");
    }
    return createProject(uid, data);
  };

  const editProject = async (
    projectId: string,
    data: Partial<Pick<Project, "name" | "domain" | "description">>
  ) => {
    return updateProject(projectId, data);
  };

  const removeProject = async (projectId: string) => {
    return deleteProject(projectId);
  };

  return {
    projects,
    loading,
    addProject,
    editProject,
    removeProject,
  };
}
