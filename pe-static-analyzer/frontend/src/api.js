import axios from "axios";

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

export const api = axios.create({
  baseURL: API_URL,
});

export async function getStatus() {
  const { data } = await api.get("/status");
  return data;
}

export async function yaraSync(token) {
  const form = new FormData();
  if (token) form.append("token", token);
  const { data } = await api.post("/yara-sync", form);
  return data;
}

export async function analyzeFile(file) {
  const form = new FormData();
  form.append("file", file);
  const { data } = await api.post("/analyze", form);
  return data;
}

export async function analyzePath(path) {
  const form = new FormData();
  form.append("path", path);
  const { data } = await api.post("/analyze-path", form);
  return data;
}

export async function scanDir(path, recursive = true) {
  const form = new FormData();
  form.append("path", path);
  form.append("recursive", recursive);
  const { data } = await api.post("/scan-dir", form);
  return data;
}
