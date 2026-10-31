/** Petit client fetch JSON avec jeton CSRF. */
export function csrf() {
  return document.querySelector('meta[name="csrf-token"]')?.content || "";
}

export async function api(url, { method = "GET", body } = {}) {
  const headers = { Accept: "application/json", "X-CSRF-Token": csrf() };
  let payload;
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }
  const res = await fetch(url, { method, headers, body: payload, credentials: "same-origin" });
  let data = null;
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("application/json")) data = await res.json();
  if (!res.ok) {
    const msg = (data && (data.detail || data.message)) || `Erreur ${res.status}`;
    throw new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
  }
  return data;
}
