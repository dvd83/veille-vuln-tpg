# Veille vulnérabilités — Pôle Infrastructure IT tpg

Newsletter quotidienne des vulnérabilités (CVE), site statique sur Netlify, mis à jour chaque matin par une tâche planifiée.

## Règle de contenu (impératif)
La page est publique : **elle ne contient que des informations publiques** (avis éditeurs, CISA, NVD, presse).
Jamais : nom de serveur, adresse IP, version installée chez nous, résultat d'inventaire, statut de correction interne, nom de collaborateur, n° de ticket.
Les lignes `pourNous` sont des vérifications conditionnelles (« si X est utilisé, vérifier Y »), jamais une affirmation sur ce que nous avons.
Le suivi des actions se fait dans Jira (bouton « Préparer le changement Jira » qui copie un texte de ticket).

## Fichiers
- `public/index.html`, `public/app.js` : la page (charte tpg, tram en en-tête). Config Jira en tête de `app.js` (`CONFIG.jiraCreateUrl`).
- `public/data/edition.json` : l'édition du jour.
- `public/data/editions/AAAA-MM-JJ.json` : archive ; `public/data/editions/index.json` = `{editions:[{date, dateLabel, une}]}`.
- Une édition archivée s'ouvre avec `#ed-AAAA-MM-JJ`.

## Format de `edition.json`
- `date` (AAAA-MM-JJ), `dateLabel`, `publishedAt` (ISO 8601 avec fuseau), `stats{kevYesterday,kevWeek,kevDue7d}` (nombre ou « NV »)
- `essentiel[]` : 2-3 phrases (`**gras**` autorisé, pas de HTML)
- `semaine[]` (le lundi seulement) : 3-6 puces résumant la semaine écoulée
- `serviceDesk[]` : `{title, text, phrase}` — ce qui touche les utilisateurs + phrase prête à dire au téléphone
- `une` / `kev[]` / `correctifs[]` : `{key, title, cves[], tags[{label,level:red|amber|grey}], body, priority, kevDue, epss, fix, pourNous, teams[], sources[{label,url}]}`
- `chaud[]` : `{key, title, cves[], tag{label,level}, sub, team, priority, kevDue, teams[]}`
- `kevCalendar[]` (optionnel) : `{key, title, cves[], kevDue, teams[]}` pour des échéances KEV à afficher sans sujet développé
- `horsPerimetre[]` : `{cve, product, cvss, note}`
- `checklist[]` : `{team, text, teams[]}`
- `volume{published, critical, source}`, `limites` (texte)

`teams` ∈ `reseau`, `systemes`, `sd` (sert aux onglets « Mon équipe »). Exchange, stockage, SecOps → `systemes` ; postes de travail, navigateurs, Office côté utilisateur → `sd`.
`priority` : P1 = exploitation confirmée ou risque de compromission majeur ; P2 = exploitation sous conditions ou avec privilèges. `NV` = non vérifié.
`key` = identifiant CVE exact (ou clé stable pour un lot).

Déploiement : Netlify (projet `veille-vuln-tpg`), à chaque push sur `main`.
