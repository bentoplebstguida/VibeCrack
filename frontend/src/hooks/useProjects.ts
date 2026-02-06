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
  const { user } = useAuth();
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!user) {
      setProjects([]);
      setLoading(false);
      return;
    }

    setLoading(true);
    const unsubscribe = subscribeToProjects(user.uid, (data) => {
      setProjects(data);
      setLoading(false);
    });

    return unsubscribe;
  }, [user]);

  const addProject = async (data: {
    name: string;
    domain: string;
    description: string;
  }) => {
    if (!user) throw new Error("User not authenticated");
    return createProject(user.uid, data);
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
