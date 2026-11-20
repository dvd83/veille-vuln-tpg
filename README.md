# Veille vulnérabilités — Pôle Infrastructure IT tpg

Newsletter quotidienne des vulnérabilités (CVE), site statique sur Netlify, mis à jour chaque matin par une tâche planifiée.

## Règle de contenu (impératif)
La page est publique : **elle ne contient que des informations publiques** (avis éditeurs, CISA, NVD, presse).
Jamais : nom de serveur, adresse IP, version installée chez nous, résultat d'inventaire, statut de correction interne, nom de collaborateur, n° de ticket.
Les lignes `pourNous` sont des vérifications conditionnelles (« si X est utilisé, vérifier Y »), jamais une affirmation sur ce que nous avons.
Le suivi des actions se fait dans Jira (bouton « Préparer le changement Jira » qui copie un texte de ticket).

## Sources structurées (`scripts/collect.py`)
Le script interroge deux flux officiels publiés sur GitHub (seul accès réseau fiable depuis la tâche planifiée) :
- **Catalogue CISA KEV** — `cisagov/kev-data` : ajouts, échéances (`dueDate`), statistiques.
- **Liste officielle des CVE** — `CVEProject/cvelistV5` : clone partiel des seules fiches ajoutées ou modifiées dans la fenêtre (via `cves/deltaLog.json`), avec CVSS, éditeur, produit, versions et références.
Il produit un fichier de candidats **hors du site public** (CVE critiques ≥ 9, CVE ≥ 7 sur la liste de surveillance `WATCH`, CVE de la fenêtre déjà au KEV).
`python3 -I scripts/collect.py --work /tmp/veille-src --since <AAAA-MM-JJ>T07:00:00Z --out /tmp/candidats.json`
La recherche web sert ensuite au contexte (exploitation, contournements, statut Red Hat), pas à la découverte.

## Fichiers
- `public/index.html`, `public/app.js` : la page (charte tpg, tram en en-tête). Config Jira en tête de `app.js` (`CONFIG.jiraCreateUrl`).
- `public/data/edition.json` : l'édition du jour.
- `public/data/editions/AAAA-MM-JJ.json` : archive ; `public/data/editions/index.json` = `{editions:[{date, dateLabel, une}]}`.
- Une édition archivée s'ouvre avec `#ed-AAAA-MM-JJ`.

## Format de `edition.json`
- `date` (AAAA-MM-JJ), `dateLabel`, `publishedAt` (ISO 8601 avec fuseau), `stats{kevYesterday,kevWeek,kevDue7d,source}` (nombre, ou « NV » si non vérifié → affiché « ? · non vérifié »). Les chiffres viennent du catalogue officiel cloné depuis https://github.com/cisagov/kev-data (le site cisa.gov bloque les outils de lecture).
- `essentiel[]` : 2-3 phrases (`**gras**` autorisé, pas de HTML)
- `top[]` : 10 sujets max, tous rubriques confondues, dans l'ordre d'urgence (exploitation avérée > échéance KEV > exposition) : `{key, title, cves[], priority, kevDue, exploited, why, action, teams[]}` — `why` et `action` en une ligne, `action` au conditionnel
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
