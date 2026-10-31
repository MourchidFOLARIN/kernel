/**
 * Stockage local IndexedDB du navigateur (stores "identity", "keys", "convkeys").
 * Robustesse : si IndexedDB est indisponible (navigation privee, stockage bloque,
 * ouverture sans reponse), bascule sur un stockage en memoire pour la session :
 * l'interface ne reste jamais bloquee.
 */
const DB_NAME = "kernel-keys", VERSION = 1, STORES = ["identity", "keys", "convkeys"];
const OPEN_TIMEOUT_MS = 3000;
let dbp;
const mem = new Map(STORES.map((s) => [s, new Map()]));
export let persistent = true;

function open() {
  if (!dbp) {
    dbp = new Promise((res) => {
      const fallback = () => { persistent = false; res(null); };
      const timer = setTimeout(fallback, OPEN_TIMEOUT_MS);
      try {
        if (typeof indexedDB === "undefined") { clearTimeout(timer); return fallback(); }
        const r = indexedDB.open(DB_NAME, VERSION);
        r.onupgradeneeded = () => {
          for (const s of STORES) {
            if (!r.result.objectStoreNames.contains(s)) r.result.createObjectStore(s);
          }
        };
        r.onsuccess = () => { clearTimeout(timer); res(r.result); };
        r.onerror = () => { clearTimeout(timer); fallback(); };
        r.onblocked = () => { clearTimeout(timer); fallback(); };
      } catch { clearTimeout(timer); fallback(); }
    });
  }
  return dbp;
}

export async function idbGet(store, key) {
  const db = await open();
  if (!db) return mem.get(store).get(key);
  return new Promise((res) => {
    try {
      const r = db.transaction(store).objectStore(store).get(key);
      r.onsuccess = () => res(r.result); r.onerror = () => res(mem.get(store).get(key));
    } catch { res(mem.get(store).get(key)); }
  });
}

export async function idbSet(store, key, value) {
  mem.get(store).set(key, value);
  const db = await open();
  if (!db) return;
  return new Promise((res) => {
    try {
      const tx = db.transaction(store, "readwrite");
      tx.objectStore(store).put(value, key);
      tx.oncomplete = () => res(); tx.onerror = () => res();
    } catch { res(); }
  });
}

export async function idbAll(store) {
  const db = await open();
  if (!db) return new Map(mem.get(store));
  return new Promise((res) => {
    const out = new Map();
    try {
      const r = db.transaction(store).objectStore(store).openCursor();
      r.onsuccess = () => {
        const c = r.result;
        if (c) { out.set(c.key, c.value); c.continue(); } else res(out);
      };
      r.onerror = () => res(out);
    } catch { res(out); }
  });
}
