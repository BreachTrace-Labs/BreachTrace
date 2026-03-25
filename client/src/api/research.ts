import apiClient from "./client";
import type { ExperimentRun } from "../types";

export async function getExperimentRuns(): Promise<ExperimentRun[]> {
  const { data } = await apiClient.get<ExperimentRun[]>("/research/export");
  return data;
}
