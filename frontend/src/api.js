async function request(path, options = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `Request failed (${res.status})`);
  }
  return res.json();
}

export const getStats = () => request("/api/stats");
export const getHistory = () => request("/api/history");
export const checkCommand = (command) =>
  request("/api/check", { method: "POST", body: JSON.stringify({ command }) });
export const clearHistory = () => request("/api/history", { method: "DELETE" });
