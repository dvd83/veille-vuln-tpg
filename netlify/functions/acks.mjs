// Acquittements partagés de la veille vulnérabilités tpg.
// GET  /api/acks  -> { "<clé>": { status, team, note, name, at, history:[...] }, ... }
// POST /api/acks  -> body { key, status, team, note, name }
import { getStore } from "@netlify/blobs";

const STATUSES = new Set(["todo", "taken", "na", "done"]);
const KEY_RE = /^[A-Za-z0-9._:-]{1,80}$/;
const clip = (v, n) => String(v ?? "").trim().slice(0, n);

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });

export default async (req) => {
  const store = getStore({ name: "acks", consistency: "strong" });

  if (req.method === "GET") {
    try {
      const { blobs } = await store.list();
      const out = {};
      await Promise.all(
        blobs.map(async ({ key }) => {
          const v = await store.get(key, { type: "json" });
          if (v) out[key] = v;
        })
      );
      return json(out);
    } catch (e) {
      console.error("acks GET failed", e);
      return json({ error: "lecture impossible" }, 500);
    }
  }

  if (req.method === "POST") {
    let body;
    try { body = await req.json(); } catch { return json({ error: "JSON invalide" }, 400); }
    const key = clip(body.key, 80);
    const status = clip(body.status, 10);
    if (!KEY_RE.test(key)) return json({ error: "clé invalide" }, 400);
    if (!STATUSES.has(status)) return json({ error: "statut invalide" }, 400);
    const entry = {
      status,
      team: clip(body.team, 40),
      note: clip(body.note, 300),
      name: clip(body.name, 60) || "Anonyme",
      at: new Date().toISOString(),
    };
    try {
      const prev = await store.get(key, { type: "json" });
      const history = Array.isArray(prev?.history) ? prev.history.slice(-19) : [];
      history.push({ status: entry.status, team: entry.team, name: entry.name, at: entry.at });
      await store.setJSON(key, { ...entry, history });
      return json({ ok: true, key, ...entry });
    } catch (e) {
      console.error("acks POST failed", e);
      return json({ error: "enregistrement impossible" }, 500);
    }
  }

  return json({ error: "méthode non autorisée" }, 405);
};

export const config = { path: "/api/acks" };
