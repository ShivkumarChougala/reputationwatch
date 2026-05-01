const API_BASE = "https://api.thechougala.in/api/v1";

async function fetchJson(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
    ...options,
  });

  const data = await res.json().catch(() => null);

  if (!res.ok) {
    throw new Error(data?.detail || `API error ${res.status}`);
  }

  return data;
}

export async function lookupIp(ip) {
  return fetchJson(`/reputation/lookup/${ip}`);
}

export async function submitReport(payload) {
  return fetchJson("/reputation/report", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}
