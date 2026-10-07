import type { AnalyzeResponse, ModelInfo } from "./types";

const API_BASE = import.meta.env.VITE_API_URL ?? "";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...options?.headers
    },
    ...options
  });

  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || "Request failed");
  }

  return response.json() as Promise<T>;
}

export function analyzeUrl(url: string) {
  return request<AnalyzeResponse>("/api/analyze", {
    method: "POST",
    body: JSON.stringify({ url })
  });
}

export function analyzeBatch(urls: string[]) {
  return request<{ results: AnalyzeResponse[] }>("/api/batch", {
    method: "POST",
    body: JSON.stringify({ urls })
  });
}

export function getModelInfo() {
  return request<ModelInfo>("/api/model/info");
}
