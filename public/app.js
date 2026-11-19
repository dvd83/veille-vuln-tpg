(() => {
  const STATUSES = [
    { s: 'todo', label: 'À traiter' },
    { s: 'taken', label: 'Pris en charge' },
    { s: 'na', label: 'Non concerné' },
    { s: 'done', label: 'Corrigé' }
  ];
  const TEAMS = ['Réseau', 'Systèmes', 'Exchange', 'Poste de travail / SD', 'Stockage / Backup', 'SecOps'];
  const $ = id => document.getElementById(id);
  const acks = {};
  const ui = {};
  let keys = [];

  // ---------- helpers ----------
  const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };
  // texte avec **gras**, sans HTML
  function rich(text) {
    const frag = document.createDocumentFragment();
    String(text || '').split(/(\*\*[^*]+\*\*)/g).forEach(part => {
      if (/^\*\*[^*]+\*\*$/.test(part)) frag.appendChild(el('b', null, part.slice(2, -2)));
      else if (part) frag.appendChild(document.createTextNode(part));
    });
    return frag;
  }
  const safeUrl = u => /^https?:\/\//i.test(u || '') ? u : '#';
  const fmt = iso => { try { return new Date(iso).toLocaleString('fr-CH', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }); } catch (e) { return ''; } };
  const lvl = l => ({ red: 't-red', amber: 't-amber' }[l] || 't-grey');
  const dmy = d => { const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(d || ''); return m ? m[3] + '.' + m[2] : (d || ''); };
  function prio(p) { if (!p) return null; const x = el('span', 'prio prio-' + String(p).toLowerCase(), p); x.title = p === 'P1' ? 'Exploitation confirmée ou risque de compromission majeur' : 'Exploitation sous conditions ou avec privilèges'; return x; }
  function kevBadge(d) {
    if (!d) return null;
    const days = Math.round((new Date(d + 'T23:59:59') - new Date()) / 86400000);
    const b = el('span', 'tag kevdue' + (days <= 2 ? ' soon' : ''), 'Échéance KEV ' + dmy(d) + (days >= 0 ? ' (J-' + days + ')' : ' (dépassée)'));
    return b;
  }
  function meta(item) {
    const parts = [];
    if (item.epss) parts.push(['EPSS', item.epss]);
    if (item.fix) parts.push(['Correctif', item.fix]);
    if (!parts.length) return null;
    const m = el('div', 'meta');
    parts.forEach(([k, v]) => { const s = el('span'); s.appendChild(el('b', null, k + ' : ')); s.appendChild(document.createTextNode(v)); m.appendChild(s); });
    return m;
  }

  // ---------- nom ----------
  const me = $('me');
  try { me.value = localStorage.getItem('veille-nom') || ''; } catch (e) {}
  me.addEventListener('change', () => {
    try { localStorage.setItem('veille-nom', me.value.trim()); } catch (e) {}
    $('meSaved').textContent = me.value.trim() ? '✓ enregistré sur ce navigateur' : '';
  });

  // ---------- rendu ----------
  function tags(list) {
    const t = el('div', 'tags');
    (list || []).forEach(x => t.appendChild(el('span', 'tag ' + lvl(x.level), x.label)));
    return t;
  }
  function cveLine(cves) {
    const f = document.createDocumentFragment();
    (cves || []).forEach(c => { f.appendChild(document.createTextNode(' ')); f.appendChild(el('span', 'cve', c)); });
    return f;
  }
  function card(item, extra) {
    const c = el('div', 'card' + (extra ? ' ' + extra : ''));
    c.dataset.key = item.key;
    const tg = tags(item.tags);
    const kb = kevBadge(item.kevDue); if (kb) tg.prepend(kb);
    const pr = prio(item.priority); if (pr) tg.prepend(pr);
    c.appendChild(tg);
    const h = el('h3', null, item.title); h.appendChild(cveLine(item.cves)); c.appendChild(h);
    if (item.body) { const p = el('p'); p.appendChild(rich(item.body)); c.appendChild(p); }
    const mt = meta(item); if (mt) c.appendChild(mt);
    if (item.pourNous) { const d = el('div', 'tpg'); d.appendChild(el('b', null, 'Pour nous → ')); d.appendChild(rich(item.pourNous)); c.appendChild(d); }
    if (item.sources && item.sources.length) {
      const s = el('div', 'src', 'Sources : ');
      item.sources.forEach((x, i) => { if (i) s.appendChild(document.createTextNode(' · ')); const a = el('a', null, x.label); a.href = safeUrl(x.url); a.target = '_blank'; a.rel = 'noopener'; s.appendChild(a); });
      c.appendChild(s);
    }
    addAck(c, item.key);
    return c;
  }
  function row(r) {
    const d = el('div', 'row'); d.dataset.key = r.key;
    const w = el('div', 'what');
    const pr = prio(r.priority); if (pr) { w.appendChild(pr); w.appendChild(document.createTextNode(' ')); }
    w.appendChild(el('b', null, r.title)); w.appendChild(cveLine(r.cves));
    if (r.tag) { w.appendChild(document.createTextNode(' ')); w.appendChild(el('span', 'tag ' + lvl(r.tag.level), r.tag.label)); }
    const kb = kevBadge(r.kevDue); if (kb) { w.appendChild(document.createTextNode(' ')); w.appendChild(kb); }
    if (r.sub) { const s = el('div', 'sub'); s.appendChild(rich(r.sub)); w.appendChild(s); }
    d.appendChild(w); d.appendChild(el('div', 'team', r.team || ''));
    addAck(d, r.key);
    return d;
  }

  function addAck(host, key) {
    if (!key) return;
    keys.push(key);
    const box = el('div', 'ack');
    const r = el('div', 'ack-row'); r.appendChild(el('span', 'ack-label', 'Chez nous :'));
    const btns = STATUSES.map(({ s, label }) => {
      const b = el('button', 'st', label); b.type = 'button'; b.dataset.s = s;
      b.setAttribute('aria-pressed', s === 'todo' ? 'true' : 'false');
      b.addEventListener('click', () => { pick(key, s); box.classList.add('open'); });
      r.appendChild(b); return b;
    });
    const more = el('div', 'ack-more');
    const team = el('select'); const o0 = el('option', null, 'Équipe…'); o0.value = ''; team.appendChild(o0);
    TEAMS.forEach(t => { const o = el('option', null, t); o.value = t; team.appendChild(o); });
    const note = el('input'); note.type = 'text'; note.maxLength = 300; note.placeholder = 'Commentaire (n° de changement Jira, action, échéance…)';
    const save = el('button', 'save', 'Enregistrer'); save.type = 'button';
    save.addEventListener('click', () => persist(key));
    more.append(team, note, save);
    const info = el('div', 'ack-info');
    box.append(r, more, info);
    host.appendChild(box);
    ui[key] = { box, btns, team, note, save, info, pending: 'todo' };
  }

  function pick(key, s) {
    const u = ui[key]; u.pending = s;
    u.btns.forEach(b => b.setAttribute('aria-pressed', b.dataset.s === s ? 'true' : 'false'));
  }

  function renderAck(key) {
    const u = ui[key]; const a = acks[key];
    if (!u.box.classList.contains('open')) { pick(key, a?.status || 'todo'); u.team.value = a?.team || ''; u.note.value = a?.note || ''; }
    u.info.textContent = '';
    if (!a) return;
    const lab = (STATUSES.find(x => x.s === a.status) || {}).label || a.status;
    u.info.append(el('b', null, lab), document.createTextNode(' · ' + (a.name || 'Anonyme') + ' · ' + fmt(a.at) + (a.team ? ' · ' + a.team : '') + (a.note ? ' — ' + a.note : '')));
  }

  function summary() {
    const c = { done: 0, taken: 0, na: 0, todo: 0 };
    keys.forEach(k => { const s = acks[k]?.status || 'todo'; c[s] = (c[s] || 0) + 1; });
    const n = keys.length || 1;
    const bar = $('bar'); bar.textContent = '';
    ['done', 'taken', 'na'].forEach(s => { const i = el('i', 'b-' + s); i.style.width = (100 * c[s] / n) + '%'; bar.appendChild(i); });
    $('barTxt').textContent = (c.done + c.taken + c.na) + ' / ' + keys.length + ' traités';
    $('statTaken').textContent = (c.done + c.taken) + '/' + keys.length;
  }

  async function loadAcks() {
    try {
      const r = await fetch('/api/acks', { cache: 'no-store' });
      if (!r.ok) throw new Error(r.status);
      const data = await r.json();
      Object.keys(acks).forEach(k => delete acks[k]);
      Object.assign(acks, data);
      $('notice').textContent = '';
    } catch (e) {
      $('notice').textContent = 'Les acquittements ne peuvent pas être chargés pour le moment.';
    }
    keys.forEach(renderAck); summary();
  }

  async function persist(key) {
    const u = ui[key];
    const name = me.value.trim();
    if (!name) { me.focus(); $('meSaved').textContent = '← indiquez votre nom avant d’acquitter'; return; }
    try { localStorage.setItem('veille-nom', name); } catch (e) {}
    u.save.disabled = true; u.save.textContent = 'Enregistrement…';
    try {
      const r = await fetch('/api/acks', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ key, status: u.pending, team: u.team.value, note: u.note.value, name }) });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || r.status);
      acks[key] = d;
      u.box.classList.remove('open');
      renderAck(key); summary();
    } catch (e) {
      u.info.textContent = 'Échec de l’enregistrement (' + e.message + '), réessayez.';
    } finally { u.save.disabled = false; u.save.textContent = 'Enregistrer'; }
  }

  // ---------- chargement de l'édition ----------
  async function init() {
    let ed;
    try {
      const r = await fetch('/data/edition.json', { cache: 'no-store' });
      ed = await r.json();
    } catch (e) { $('dateLabel').textContent = 'Édition introuvable'; return; }

    document.title = 'Veille vulnérabilités – ' + (ed.dateLabel || ed.date || '');
    $('dateLabel').textContent = ed.dateLabel || ed.date || '';
    $('s1').textContent = ed.stats?.kevYesterday ?? '–';
    $('s2').textContent = ed.stats?.kevWeek ?? '–';
    $('s3').textContent = ed.stats?.kevDue7d ?? '–';
    (ed.essentiel || []).forEach(t => { const p = el('p'); p.appendChild(rich(t)); $('essentiel').appendChild(p); });

    if (ed.une) { $('une').appendChild(card(ed.une, 'une')); $('secUne').hidden = false; }
    if (ed.kev?.length) { ed.kev.forEach(i => $('kev').appendChild(card(i))); $('secKev').hidden = false; }
    if (ed.correctifs?.length) { ed.correctifs.forEach(i => $('corr').appendChild(card(i))); $('secCorr').hidden = false; }
    if (ed.chaud?.length) { ed.chaud.forEach(r => $('chaud').appendChild(row(r))); $('secChaud').hidden = false; }
    if (ed.horsPerimetre?.length) {
      const t = $('hors');
      ed.horsPerimetre.forEach(h => {
        const tr = el('tr');
        const c1 = el('td'); c1.appendChild(el('span', 'cve', h.cve)); tr.appendChild(c1);
        tr.appendChild(el('td', 'hp-prod', h.product));
        tr.appendChild(el('td', 'hp-cvss', h.cvss || ''));
        tr.appendChild(el('td', null, h.note || ''));
        t.appendChild(tr);
      });
      $('secHors').hidden = false;
    }
    if (ed.volume) $('volume').textContent = 'Volume du jour : ' + ed.volume.published + ' CVE publiées, dont ' + ed.volume.critical + ' critiques' + (ed.volume.source ? ' (' + ed.volume.source + ')' : '') + '.';
    if (ed.limites) $('limites').textContent = 'Limites de collecte : ' + ed.limites;
    if (ed.checklist?.length) {
      ed.checklist.forEach(c => { const li = el('li'); li.appendChild(el('b', null, c.team)); li.appendChild(document.createTextNode(' — ' + c.text)); $('check').appendChild(li); });
      $('secCheck').hidden = false;
    }
    summary();
    await loadAcks();
    setInterval(() => { if (!document.hidden && !document.querySelector('.ack.open')) loadAcks(); }, 60000);
  }
  init();
})();
