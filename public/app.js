(() => {
  // Configuration Jira : renseigner jiraCreateUrl pour transformer le bouton en lien direct.
  // Ex. "https://jira.exemple.ch/secure/CreateIssue!default.jspa"
  const CONFIG = { jiraCreateUrl: '' };

  const TEAMS = [
    { id: 'tous', label: 'Tous' },
    { id: 'reseau', label: 'Réseau' },
    { id: 'systemes', label: 'Systèmes' },
    { id: 'sd', label: 'Service Desk' }
  ];
  const $ = id => document.getElementById(id);
  const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };
  function rich(text) {
    const frag = document.createDocumentFragment();
    String(text || '').split(/(\*\*[^*]+\*\*)/g).forEach(part => {
      if (/^\*\*[^*]+\*\*$/.test(part)) frag.appendChild(el('b', null, part.slice(2, -2)));
      else if (part) frag.appendChild(document.createTextNode(part));
    });
    return frag;
  }
  const safeUrl = u => /^https?:\/\//i.test(u || '') ? u : '#';
  const lvl = l => ({ red: 't-red', amber: 't-amber' }[l] || 't-grey');
  const dmy = d => { const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(d || ''); return m ? m[3] + '.' + m[2] : (d || ''); };
  const daysTo = d => { const t = new Date(); t.setHours(0, 0, 0, 0); return Math.round((new Date(d + 'T00:00:00') - t) / 86400000); };
  const WEEKDAYS = ['dimanche', 'lundi', 'mardi', 'mercredi', 'jeudi', 'vendredi', 'samedi'];

  function prio(p) { if (!p) return null; const x = el('span', 'prio prio-' + String(p).toLowerCase(), p); x.title = p === 'P1' ? 'Exploitation confirmée ou risque de compromission majeur' : 'Exploitation sous conditions ou avec privilèges'; return x; }
  function kevBadge(d) {
    if (!d) return null;
    const n = daysTo(d);
    return el('span', 'tag kevdue' + (n <= 2 ? ' soon' : ''), 'Échéance KEV ' + dmy(d) + (n >= 0 ? ' (J-' + n + ')' : ' (dépassée)'));
  }
  function tags(list) { const t = el('div', 'tags'); (list || []).forEach(x => t.appendChild(el('span', 'tag ' + lvl(x.level), x.label))); return t; }
  function cveLine(cves) { const f = document.createDocumentFragment(); (cves || []).forEach(c => { f.appendChild(document.createTextNode(' ')); f.appendChild(el('span', 'cve', c)); }); return f; }
  function teamChips(teams) {
    const w = el('span', 'teams');
    (teams || []).forEach(t => { const def = TEAMS.find(x => x.id === t); if (def) w.appendChild(el('span', 'team-chip', def.label)); });
    return w;
  }
  function setTeams(node, teams) { node.dataset.teams = (teams && teams.length ? teams : ['reseau', 'systemes', 'sd']).join(' '); }

  // ---------- Jira ----------
  function jiraText(item) {
    const lines = [];
    lines.push('Résumé : [Sécurité] ' + (item.cves && item.cves.length ? item.cves.join(', ') + ' — ' : '') + item.title);
    if (item.priority) lines.push('Priorité veille : ' + item.priority);
    if (item.kevDue) lines.push('Échéance CISA KEV : ' + dmy(item.kevDue) + '.' + item.kevDue.slice(0, 4));
    lines.push('');
    lines.push('Description :');
    if (item.body) lines.push(item.body.replace(/\*\*/g, ''));
    if (item.fix) lines.push('Correctif / remédiation : ' + item.fix);
    if (item.pourNous) lines.push('Vérification proposée : ' + item.pourNous.replace(/\*\*/g, ''));
    if (item.sources && item.sources.length) { lines.push(''); lines.push('Sources :'); item.sources.forEach(s => lines.push('- ' + s.label + ' : ' + s.url)); }
    lines.push(''); lines.push('Source : veille vulnérabilités du ' + (window.__edDate || ''));
    return lines.join('\n');
  }
  function toast(msg) {
    const t = $('toast'); t.textContent = msg; t.classList.add('show');
    clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.remove('show'), 2600);
  }
  async function copyText(text) {
    try { await navigator.clipboard.writeText(text); return true; } catch (e) {}
    try { const ta = el('textarea'); ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0'; document.body.appendChild(ta); ta.select(); const ok = document.execCommand('copy'); ta.remove(); return ok; } catch (e) { return false; }
  }
  function jiraButton(item) {
    const w = el('div', 'jira');
    const b = el('button', 'jira-btn', CONFIG.jiraCreateUrl ? 'Créer le changement Jira' : 'Préparer le changement Jira');
    b.type = 'button';
    b.title = 'Copie un texte de ticket prêt à coller (résumé, priorité, échéance, description, sources)';
    b.addEventListener('click', async () => {
      const ok = await copyText(jiraText(item));
      toast(ok ? 'Texte du ticket copié — collez-le dans Jira' : 'Copie impossible sur ce navigateur');
      if (CONFIG.jiraCreateUrl) window.open(CONFIG.jiraCreateUrl, '_blank', 'noopener');
    });
    w.appendChild(b);
    return w;
  }

  // ---------- blocs ----------
  function card(item, extra) {
    const c = el('div', 'card' + (extra ? ' ' + extra : ''));
    setTeams(c, item.teams);
    const tg = tags(item.tags);
    const kb = kevBadge(item.kevDue); if (kb) tg.prepend(kb);
    const pr = prio(item.priority); if (pr) tg.prepend(pr);
    c.appendChild(tg);
    const h = el('h3', null, item.title); h.appendChild(cveLine(item.cves)); c.appendChild(h);
    if (item.body) { const p = el('p'); p.appendChild(rich(item.body)); c.appendChild(p); }
    const parts = [];
    if (item.epss) parts.push(['EPSS', item.epss]);
    if (item.fix) parts.push(['Correctif', item.fix]);
    if (parts.length) { const m = el('div', 'meta'); parts.forEach(([k, v]) => { const s = el('span'); s.appendChild(el('b', null, k + ' : ')); s.appendChild(document.createTextNode(v)); m.appendChild(s); }); c.appendChild(m); }
    if (item.pourNous) { const d = el('div', 'tpg'); d.appendChild(el('b', null, 'À vérifier → ')); d.appendChild(rich(item.pourNous)); c.appendChild(d); }
    const foot = el('div', 'card-foot');
    if (item.sources && item.sources.length) {
      const s = el('div', 'src', 'Sources : ');
      item.sources.forEach((x, i) => { if (i) s.appendChild(document.createTextNode(' · ')); const a = el('a', null, x.label); a.href = safeUrl(x.url); a.target = '_blank'; a.rel = 'noopener'; s.appendChild(a); });
      foot.appendChild(s);
    }
    foot.appendChild(teamChips(item.teams));
    foot.appendChild(jiraButton(item));
    c.appendChild(foot);
    return c;
  }
  function row(r) {
    const d = el('div', 'row'); setTeams(d, r.teams);
    const w = el('div', 'what');
    const pr = prio(r.priority); if (pr) { w.appendChild(pr); w.appendChild(document.createTextNode(' ')); }
    w.appendChild(el('b', null, r.title)); w.appendChild(cveLine(r.cves));
    if (r.tag) { w.appendChild(document.createTextNode(' ')); w.appendChild(el('span', 'tag ' + lvl(r.tag.level), r.tag.label)); }
    const kb = kevBadge(r.kevDue); if (kb) { w.appendChild(document.createTextNode(' ')); w.appendChild(kb); }
    if (r.sub) { const s = el('div', 'sub'); s.appendChild(rich(r.sub)); w.appendChild(s); }
    d.appendChild(w);
    const right = el('div', 'row-right'); right.appendChild(teamChips(r.teams)); right.appendChild(jiraButton(r));
    d.appendChild(right);
    return d;
  }

  // ---------- filtres par équipe ----------
  let currentTeam = 'tous';
  function buildTabs() {
    const bar = $('tabs');
    TEAMS.forEach(t => {
      const b = el('button', 'tab', t.label); b.type = 'button'; b.dataset.team = t.id;
      b.addEventListener('click', () => { applyTeam(t.id); try { localStorage.setItem('veille-equipe', t.id); } catch (e) {} });
      bar.appendChild(b);
    });
    let saved = 'tous'; try { saved = localStorage.getItem('veille-equipe') || 'tous'; } catch (e) {}
    applyTeam(TEAMS.some(t => t.id === saved) ? saved : 'tous');
  }
  function applyTeam(team) {
    currentTeam = team;
    document.querySelectorAll('.tab').forEach(b => b.setAttribute('aria-pressed', b.dataset.team === team ? 'true' : 'false'));
    document.querySelectorAll('[data-teams]').forEach(n => { n.hidden = team !== 'tous' && !n.dataset.teams.split(' ').includes(team); });
    // masquer les sections devenues vides
    document.querySelectorAll('section[data-filterable]').forEach(s => {
      if (!s.dataset.hasContent) return;
      const visible = [...s.querySelectorAll('[data-teams]')].some(n => !n.hidden);
      s.hidden = !visible;
    });
    const sd = $('secSD'); if (sd.dataset.hasContent) sd.hidden = !(team === 'tous' || team === 'sd');
    $('filterNote').textContent = team === 'tous' ? '' : 'Vue filtrée : ' + TEAMS.find(t => t.id === team).label + '.';
  }

  // ---------- fraîcheur ----------
  function lastBusinessDay(now) {
    const d = new Date(now); d.setHours(0, 0, 0, 0);
    while (d.getDay() === 0 || d.getDay() === 6) d.setDate(d.getDate() - 1);
    return d;
  }
  function freshness(ed, isArchive) {
    const pub = ed.publishedAt ? new Date(ed.publishedAt) : null;
    const pubTxt = pub && !isNaN(pub) ? ' · publiée le ' + pub.toLocaleDateString('fr-CH') + ' à ' + pub.toLocaleTimeString('fr-CH', { hour: '2-digit', minute: '2-digit' }) : '';
    $('pubInfo').textContent = pubTxt;
    if (isArchive) { showBanner('archive', 'Vous consultez une édition archivée (' + (ed.dateLabel || ed.date) + ').', true); return; }
    const edDay = new Date(ed.date + 'T00:00:00');
    const expected = lastBusinessDay(new Date());
    const now = new Date();
    // avant 9h un jour ouvré, l'édition de la veille ouvrée est encore acceptable
    if (now.getDay() >= 1 && now.getDay() <= 5 && now.getHours() < 9) { expected.setDate(expected.getDate() - 1); while (expected.getDay() === 0 || expected.getDay() === 6) expected.setDate(expected.getDate() - 1); }
    if (edDay < expected) showBanner('stale', 'Cette édition date du ' + (ed.dateLabel || ed.date) + ' : l’édition du jour n’a pas encore été publiée.');
  }
  function showBanner(kind, msg, withLink) {
    const b = $('banner'); b.className = 'banner ' + kind; b.textContent = msg;
    if (withLink) { const a = el('a', null, ' Revenir à l’édition du jour'); a.href = '#'; a.addEventListener('click', e => { e.preventDefault(); location.hash = ''; location.reload(); }); b.appendChild(a); }
    b.hidden = false;
  }

  // ---------- calendrier KEV ----------
  function kevCalendar(ed) {
    const map = new Map();
    const add = (key, it) => { if (!it || !it.kevDue) return; const n = daysTo(it.kevDue); if (n < 0 || n > 14) return; if (!map.has(key)) map.set(key, it); };
    if (ed.une) add(ed.une.key, ed.une);
    ['kev', 'correctifs', 'chaud'].forEach(k => (ed[k] || []).forEach(i => add(i.key, i)));
    (ed.kevCalendar || []).forEach(i => add(i.key || i.cves?.join(','), i));
    const items = [...map.values()].sort((a, b) => a.kevDue.localeCompare(b.kevDue));
    if (!items.length) return;
    const list = $('kevcal');
    items.forEach(it => {
      const n = daysTo(it.kevDue);
      const li = el('li', n <= 2 ? 'soon' : null); setTeams(li, it.teams);
      const d = new Date(it.kevDue + 'T12:00:00');
      const date = el('div', 'kc-date');
      date.appendChild(el('b', null, dmy(it.kevDue)));
      date.appendChild(el('span', null, WEEKDAYS[d.getDay()] + ' · J-' + n));
      li.appendChild(date);
      const w = el('div', 'kc-what'); w.appendChild(el('b', null, it.title)); w.appendChild(cveLine(it.cves));
      li.appendChild(w);
      list.appendChild(li);
    });
    $('secCal').dataset.hasContent = '1'; $('secCal').hidden = false;
  }

  // ---------- archive ----------
  async function archive(currentDate) {
    try {
      const r = await fetch('/data/editions/index.json', { cache: 'no-store' });
      if (!r.ok) return;
      const idx = await r.json();
      const ul = $('archive');
      (idx.editions || []).slice().sort((a, b) => b.date.localeCompare(a.date)).forEach(e => {
        const li = el('li');
        const a = el('a', null, e.dateLabel || e.date); a.href = '#ed-' + e.date;
        a.addEventListener('click', ev => { ev.preventDefault(); location.hash = 'ed-' + e.date; location.reload(); });
        if (e.date === currentDate) li.className = 'current';
        li.appendChild(a);
        if (e.une) li.appendChild(el('span', null, ' — ' + e.une));
        ul.appendChild(li);
      });
      $('secArch').hidden = false;
    } catch (e) {}
  }

  // ---------- chargement ----------
  async function init() {
    const m = /^#ed-(\d{4}-\d{2}-\d{2})$/.exec(location.hash || '');
    const url = m ? '/data/editions/' + m[1] + '.json' : '/data/edition.json';
    let ed;
    try { const r = await fetch(url, { cache: 'no-store' }); if (!r.ok) throw 0; ed = await r.json(); }
    catch (e) { $('dateLabel').textContent = 'Édition introuvable'; return; }
    window.__edDate = ed.dateLabel || ed.date || '';

    document.title = 'Veille vulnérabilités – ' + (ed.dateLabel || ed.date || '');
    $('dateLabel').textContent = ed.dateLabel || ed.date || '';
    $('s1').textContent = ed.stats?.kevYesterday ?? '–';
    $('s2').textContent = ed.stats?.kevWeek ?? '–';
    $('s3').textContent = ed.stats?.kevDue7d ?? '–';
    const allItems = [ed.une, ...(ed.kev || []), ...(ed.correctifs || [])].filter(Boolean);
    $('s4').textContent = allItems.filter(i => i.priority === 'P1').length;
    freshness(ed, !!m);

    (ed.essentiel || []).forEach(t => { const p = el('p'); p.appendChild(rich(t)); $('essentiel').appendChild(p); });

    if (ed.semaine?.length) {
      ed.semaine.forEach(t => { const li = el('li'); li.appendChild(rich(t)); $('semaine').appendChild(li); });
      $('secSemaine').hidden = false;
    }
    if (ed.serviceDesk?.length) {
      ed.serviceDesk.forEach(s => {
        const b = el('div', 'sd-item');
        b.appendChild(el('h3', null, s.title));
        if (s.text) { const p = el('p'); p.appendChild(rich(s.text)); b.appendChild(p); }
        if (s.phrase) { const q = el('blockquote'); q.appendChild(el('span', 'q-label', 'À répondre aux utilisateurs : ')); q.appendChild(document.createTextNode('« ' + s.phrase + ' »')); b.appendChild(q); }
        $('sd').appendChild(b);
      });
      $('secSD').dataset.hasContent = '1'; $('secSD').hidden = false;
    }
    const fill = (secId, boxId, list, fn) => { if (!list?.length) return; list.forEach(i => $(boxId).appendChild(fn(i))); $(secId).dataset.hasContent = '1'; $(secId).hidden = false; };
    if (ed.une) fill('secUne', 'une', [ed.une], i => card(i, 'une'));
    fill('secKev', 'kev', ed.kev, i => card(i));
    fill('secCorr', 'corr', ed.correctifs, i => card(i));
    fill('secChaud', 'chaud', ed.chaud, r => row(r));
    kevCalendar(ed);
    if (ed.horsPerimetre?.length) {
      ed.horsPerimetre.forEach(h => {
        const tr = el('tr');
        const c1 = el('td'); c1.appendChild(el('span', 'cve', h.cve)); tr.appendChild(c1);
        tr.appendChild(el('td', 'hp-prod', h.product)); tr.appendChild(el('td', 'hp-cvss', h.cvss || '')); tr.appendChild(el('td', null, h.note || ''));
        $('hors').appendChild(tr);
      });
      $('secHors').hidden = false;
    }
    if (ed.checklist?.length) {
      ed.checklist.forEach(c => { const li = el('li'); setTeams(li, c.teams); li.appendChild(el('b', null, c.team)); li.appendChild(document.createTextNode(' — ' + c.text)); $('check').appendChild(li); });
      $('secCheck').dataset.hasContent = '1'; $('secCheck').hidden = false;
    }
    if (ed.volume) $('volume').textContent = 'Volume du jour : ' + ed.volume.published + ' CVE publiées, dont ' + ed.volume.critical + ' critiques' + (ed.volume.source ? ' (' + ed.volume.source + ')' : '') + '.';
    if (ed.limites) $('limites').textContent = 'Limites de collecte : ' + ed.limites;
    buildTabs();
    archive(ed.date);
  }
  window.addEventListener('hashchange', () => location.reload());
  init();
})();
