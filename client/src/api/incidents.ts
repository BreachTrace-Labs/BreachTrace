import apiClient from "./client";
import type {
  IncidentListItem,
  IncidentRecord,
  ForensicEvent,
  IncidentStats,
} from "../types";

export async function getIncidents(): Promise<IncidentListItem[]> {
  const { data } = await apiClient.get<IncidentListItem[]>("/incidents");
  return data;
}

export async function getIncident(id: string): Promise<IncidentRecord> {
  const { data } = await apiClient.get<IncidentRecord>(`/incidents/${id}`);
  return data;
}

export async function getIncidentTimeline(
  id: string
): Promise<ForensicEvent[]> {
  const { data } = await apiClient.get<ForensicEvent[]>(
    `/incidents/${id}/timeline`
  );
  return data;
}

export async function getIncidentStats(): Promise<IncidentStats> {
  const { data } = await apiClient.get<IncidentStats>("/incidents/stats");
  return data;
}
