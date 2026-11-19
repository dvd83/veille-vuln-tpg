# Veille vulnérabilités — Pôle Infrastructure IT tpg

Newsletter quotidienne des vulnérabilités (CVE) avec acquittement partagé.

- `public/index.html`, `public/app.js` : la page (charte tpg, tram en en-tête).
- `public/data/edition.json` : l'édition du jour, **seul fichier mis à jour chaque matin** par la tâche planifiée.
- `public/data/editions/AAAA-MM-JJ.json` : archive des éditions.
- `netlify/functions/acks.mjs` : API `/api/acks` (GET = tous les acquittements, POST = acquitter), stockage Netlify Blobs.

Déploiement : Netlify (projet `veille-vuln-tpg`), à chaque push sur `main`.

## Format de `edition.json`
`date`, `dateLabel`, `stats{kevYesterday,kevWeek,kevDue7d}`, `essentiel[]` (texte, `**gras**`),
`une` / `kev[]` / `correctifs[]` = `{key, title, cves[], tags[{label,level:red|amber|grey}], body, pourNous, sources[{label,url}]}`,
`chaud[]` = `{key, title, cves[], tag{label,level}, sub, team, priority, kevDue}`, `checklist[]` = `{team, text}`.
Champs optionnels sur chaque sujet : `priority` (`P1` | `P2`), `kevDue` (AAAA-MM-JJ, échéance CISA KEV), `epss` (« 1,13 % » ou « NV »), `fix` (version corrective / remédiation ou « NV »).
Blocs optionnels : `horsPerimetre[]` = `{cve, product, cvss, note}` (CVE critiques vues mais a priori absentes des tpg), `volume` = `{published, critical, source}`, `limites` (texte).
P1 = exploitation confirmée ou risque de compromission majeur ; P2 = exploitation sous conditions ou avec privilèges ; NV = non vérifié.
`key` = identifiant CVE exact (ou clé stable pour un lot) : l'acquittement suit la clé d'un jour à l'autre.
