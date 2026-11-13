// Cuentas para Subastas Futboleras (Vercel serverless, sin dependencias).
// Necesita una base Redis de Upstash conectada al proyecto (Vercel > Storage > Upstash Redis).
// Variables que acepta: UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN  o  KV_REST_API_URL / KV_REST_API_TOKEN
const crypto = require('crypto');
const URL_ = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
const TOK_ = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;
const SESS = 60 * 60 * 24 * 365; // la sesión dura 1 año y se renueva cada vez que entras

async function redis(cmds) {
  if (!URL_ || !TOK_) throw new Error('db');
  const r = await fetch(URL_ + '/pipeline', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + TOK_, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmds)
  });
  if (!r.ok) {
    let t = ''; try { t = await r.text(); } catch (e) {}
    throw new Error(r.status === 429 || /limit|quota|exceed/i.test(t) ? 'limit' : 'db');
  }
  const j = await r.json();
  return j.map(x => {
    if (x && x.error) {
      const m = String(x.error);
      if (/max .*limit|limit exceeded|quota|exceeded/i.test(m)) throw new Error('limit');
      if (/noauth|wrongpass|unauthor/i.test(m)) throw new Error('db');
    }
    return x.result;
  });
}

const hash = (p, salt) => crypto.scryptSync(String(p), salt, 32).toString('hex');
const tokenOf = () => crypto.randomBytes(24).toString('hex');
// Nombres libres: cualquier texto (sin < > & \" ' ni saltos), hasta 24 caracteres.
const cleanName = u => String(u == null ? '' : u).replace(/[\u0000-\u001f<>&"'`]/g, '').replace(/\s+/g, ' ').trim().slice(0, 24);
const okMail = e => typeof e === 'string' && e.length <= 80 && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e);
const randName = () => 'user' + (1000 + Math.floor(Math.random() * 9000));
const hid = () => crypto.randomBytes(5).toString('hex');
const now_ = () => Date.now();
const okPass = p => typeof p === 'string' && p.length >= 4 && p.length <= 64;

const ints = (a, n) => (Array.isArray(a) ? a.slice(0, n).map(x => Math.floor(+x)).filter(x => Number.isFinite(x) && x >= 0 && x < 100000) : []);
const intMap = (o, n) => {
  const r = {};
  if (o && typeof o === 'object') Object.keys(o).slice(0, n).forEach(k => { const v = Math.floor(+o[k]); if (/^\d{1,6}$/.test(k) && Number.isFinite(v) && v >= 0 && v <= 60) r[k] = v; });
  return r;
};
function cleanSq(q) {
  if (!q || typeof q !== 'object') return undefined;
  const done = {};
  if (q.done && typeof q.done === 'object') Object.keys(q.done).slice(0, 160).forEach(k => { if (/^[a-z0-9]{1,6}$/.test(k)) done[k] = 1; });
  const pub = q.pub && typeof q.pub === 'object' && Number.isFinite(+q.pub.r) ? { r: Math.min(99.9, Math.max(0, +q.pub.r)), t: Math.floor(+q.pub.t) || 0 } : null;
  return { s: ints(q.s, 11), ev: intMap(q.ev, 60), inv: ints(q.inv, 400), tok: Math.min(999, Math.max(0, Math.floor(+q.tok) || 0)), done, pub, sd: typeof q.sd === 'string' ? cleanName(q.sd) : undefined };
}
function clean(d) {
  d = d && typeof d === 'object' ? d : {};
  const arr = (a, n) => (Array.isArray(a) ? a.slice(-n) : undefined);
  const out = {
    coins: Math.min(1e9, Math.max(0, Math.floor(+d.coins || 0))),
    obj: d.obj && typeof d.obj === 'object' && !Array.isArray(d.obj) ? d.obj : {},
    hist: arr(d.hist, 40),
    sim: arr(d.sim, 40)
  };
  out.sq = cleanSq(d.sq);
  if (JSON.stringify(out).length > 30000) throw new Error('big');
  return out;
}

async function userOf(token) {
  if (!token || !/^[a-f0-9]{48}$/.test(token)) return null;
  const [u] = await redis([['GET', 's:' + token]]);
  return u || null;
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).json({ error: 'method' });
  let b = req.body;
  if (typeof b === 'string') { try { b = JSON.parse(b); } catch (e) { b = {}; } }
  b = b || {};
  try {
    if (b.op === 'register') {
      const legacy = !b.e;
      const email = String(b.e || '').trim().toLowerCase();
      if (!legacy && !okMail(email)) return res.status(400).json({ error: 'Escribe un correo válido' });
      if (!okPass(b.p)) return res.status(400).json({ error: 'La contraseña debe tener entre 4 y 64 caracteres' });
      const want = cleanName(b.u);
      if (legacy && !want) return res.status(400).json({ error: 'Escribe un usuario' });
      if (!legacy) {
        const [ok] = await redis([['SET', 'e:' + email, 'pending', 'NX']]);
        if (ok !== 'OK') return res.status(409).json({ error: 'Ese correo ya tiene una cuenta' });
      }
      const salt = crypto.randomBytes(16).toString('hex');
      const data = clean(b.data);
      data.coins = Math.min(1e9, data.coins + 100); // monedas iniciales
      let name = want || randName(), made = false, key = '', rec = null;
      for (let i = 0; i < 40 && !made; i++) {
        key = 'u:' + name.toLowerCase();
        rec = { u: name, e: legacy ? null : email, salt, h: hash(b.p, salt), data, t: now_() };
        const [set] = await redis([['SET', key, JSON.stringify(rec), 'NX']]);
        if (set === 'OK') { made = true; break; }
        if (legacy) return res.status(409).json({ error: 'Ese usuario ya existe' });
        name = randName();
      }
      if (!made) { if (!legacy) await redis([['DEL', 'e:' + email]]); return res.status(503).json({ error: 'Inténtalo de nuevo' }); }
      const low = name.toLowerCase(), token = tokenOf(), day = new Date().toISOString().slice(0, 10);
      const cmds = [['SET', 's:' + token, low, 'EX', SESS], ['SADD', 'an:users', low], ['HSET', 'an:u:' + low, 'created', now_()], ['HINCRBY', 'an:d:' + day, 'reg', 1], ['ZADD', 'names', 0, low], ['HSET', 'dn', low, name]];
      if (!legacy) cmds.push(['SET', 'e:' + email, low]);
      await redis(cmds);
      return res.status(200).json({ token, u: name, e: legacy ? null : email, data, bonus: 100, random: !want || name !== want });
    }
    if (b.op === 'login') {
      const id = String(b.id != null ? b.id : b.u || '').trim();
      if (!id || !okPass(b.p)) return res.status(400).json({ error: 'Usuario o contraseña incorrectos' });
      let low = id.toLowerCase();
      if (id.indexOf('@') > 0) { const [l] = await redis([['GET', 'e:' + low]]); low = l && l !== 'pending' ? l : ''; }
      if (!low) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
      const [raw] = await redis([['GET', 'u:' + low]]);
      if (!raw) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
      const rec = JSON.parse(raw);
      const a = Buffer.from(hash(b.p, rec.salt)), c = Buffer.from(rec.h);
      if (a.length !== c.length || !crypto.timingSafeEqual(a, c)) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
      const token = tokenOf();
      await redis([['SET', 's:' + token, low, 'EX', SESS]]);
      return res.status(200).json({ token, u: rec.u, e: rec.e || null, data: rec.data });
    }
    if (b.op === 'me') {
      const u = await userOf(b.token);
      if (!u) return res.status(401).json({ error: 'auth' });
      const [raw] = await redis([['GET', 'u:' + u]]);
      if (!raw) return res.status(401).json({ error: 'auth' });
      const rec = JSON.parse(raw);
      await redis([['EXPIRE', 's:' + b.token, SESS]]).catch(() => {});
      return res.status(200).json({ u: rec.u, e: rec.e || null, data: rec.data });
    }
    if (b.op === 'save') {
      const u = await userOf(b.token);
      if (!u) return res.status(401).json({ error: 'auth' });
      const [raw] = await redis([['GET', 'u:' + u]]);
      if (!raw) return res.status(401).json({ error: 'auth' });
      const rec = JSON.parse(raw);
      rec.data = clean(b.data);
      rec.t = Date.now();
      await redis([['SET', 'u:' + u, JSON.stringify(rec)]]);
      return res.status(200).json({ ok: 1 });
    }
    if (b.op === 'publish') {
      const u = await userOf(b.token);
      if (!u) return res.status(401).json({ error: 'auth' });
      const [raw] = await redis([['GET', 'u:' + u]]);
      if (!raw) return res.status(401).json({ error: 'auth' });
      const rec = JSON.parse(raw);
      const r = Math.round(+b.rating * 10) / 10;
      if (!Number.isFinite(r) || r < 0 || r > 99.9) return res.status(400).json({ error: 'Valoración inválida' });
      await redis([['ZADD', 'rank', r, rec.u]]);
      const [pos] = await redis([['ZREVRANK', 'rank', rec.u]]);
      return res.status(200).json({ ok: 1, rank: (pos || 0) + 1, rating: r });
    }
    if (b.op === 'rank') {
      const [flat] = await redis([['ZREVRANGE', 'rank', 0, 49, 'WITHSCORES']]);
      const list = [];
      for (let i = 0; i + 1 < (flat || []).length; i += 2) list.push({ u: flat[i], r: +flat[i + 1] });
      return res.status(200).json({ list });
    }
    if (b.op === 'ping') {
      const u = await userOf(b.token);
      if (!u) return res.status(401).json({ error: 'auth' });
      const ev = b.ev && typeof b.ev === 'object' ? b.ev : {};
      const secs = Math.min(60, Math.max(0, Math.floor(+b.secs) || 0));
      const n = k => Math.min(50, Math.max(0, Math.floor(+ev[k]) || 0));
      const day = new Date().toISOString().slice(0, 10);
      const cmds = [['HINCRBY', 'an:u:' + u, 'secs', secs], ['HSET', 'an:u:' + u, 'last', Date.now()], ['SADD', 'an:users', u], ['HINCRBY', 'an:d:' + day, 'secs', secs], ['SADD', 'an:da:' + day, u]];
      ['g', 'ai', 'ch', 'onl', 'loc', 'w'].forEach(k => { const v = n(k); if (v) { cmds.push(['HINCRBY', 'an:u:' + u, k, v]); cmds.push(['HINCRBY', 'an:d:' + day, k, v]); } });
      cmds.push(['SET', 'pr:' + u, JSON.stringify({ st: String(b.st || '').replace(/[^a-z]/g, '').slice(0, 12), r: Math.min(99.9, Math.max(0, +b.r || 0)) }), 'EX', 80], ['ZADD', 'on', now_(), u]);
      if (b.s) { cmds.push(['HINCRBY', 'an:u:' + u, 'ses', 1]); cmds.push(['HINCRBY', 'an:d:' + day, 'ses', 1]); }
      await redis(cmds);
      return res.status(200).json({ ok: 1 });
    }
    if (b.op === 'stats') {
      const key = process.env.ADMIN_KEY;
      const same = (x, y) => { const A = Buffer.from(String(x)), B = Buffer.from(String(y)); return A.length === B.length && crypto.timingSafeEqual(A, B); };
      if (!key || typeof b.key !== 'string' || !same(b.key, key)) return res.status(403).json({ error: 'forbidden' });
      const toObj = a => { const o = {}; for (let i = 0; Array.isArray(a) && i + 1 < a.length; i += 2) o[a[i]] = a[i + 1]; return o; };
      const [members] = await redis([['SMEMBERS', 'an:users']]);
      const us = (members || []).slice(0, 500);
      const days = [];
      for (let i = 0; i < 14; i++) days.push(new Date(Date.now() - i * 864e5).toISOString().slice(0, 10));
      const cmds = [];
      us.forEach(u => { cmds.push(['HGETALL', 'an:u:' + u]); cmds.push(['GET', 'u:' + u]); });
      days.forEach(d => { cmds.push(['HGETALL', 'an:d:' + d]); cmds.push(['SCARD', 'an:da:' + d]); });
      const out = cmds.length ? await redis(cmds) : [];
      const now = Date.now();
      const rows = us.map((u, i) => {
        const h = toObj(out[2 * i]);
        let rec = null; try { rec = JSON.parse(out[2 * i + 1]); } catch (e) {}
        return { u: rec ? rec.u : u, created: +h.created || (rec && rec.t) || 0, secs: +h.secs || 0, ses: +h.ses || 0, g: +h.g || 0, ai: +h.ai || 0, ch: +h.ch || 0, onl: +h.onl || 0, loc: +h.loc || 0, w: +h.w || 0, last: +h.last || 0 };
      }).sort((a, b) => b.secs - a.secs);
      const off = 2 * us.length;
      const dl = days.map((d, i) => { const h = toObj(out[off + 2 * i]); return { d, dau: +out[off + 2 * i + 1] || 0, secs: +h.secs || 0, ses: +h.ses || 0, g: +h.g || 0, reg: +h.reg || 0 }; });
      const sum = k => rows.reduce((a, r) => a + r[k], 0);
      return res.status(200).json({
        totals: { users: rows.length, secs: sum('secs'), ses: sum('ses'), g: sum('g'), w: sum('w'), ai: sum('ai'), ch: sum('ch'), onl: sum('onl'), loc: sum('loc'), a1: rows.filter(r => now - r.last < 864e5).length, a7: rows.filter(r => now - r.last < 7 * 864e5).length },
        users: rows, days: dl
      });
    }
    if (b.op === 'logout') {
      if (b.token && /^[a-f0-9]{48}$/.test(b.token)) await redis([['DEL', 's:' + b.token]]);
      return res.status(200).json({ ok: 1 });
    }
    const SOC = ['rename', 'find', 'online', 'fr_list', 'fr_add', 'fr_answer', 'fr_del', 'invite', 'inbox', 'profile', 'trade_offer', 'trade_answer', 'trade_cancel'];
    if (SOC.indexOf(b.op) >= 0) {
      const me = await userOf(b.token);
      if (!me) return res.status(401).json({ error: 'auth' });
      const J = x => { try { return JSON.parse(x); } catch (e) { return null; } };
      const dnOf = async arr => { if (!arr.length) return []; const [r] = await redis([['HMGET', 'dn'].concat(arr)]); return arr.map((x, i) => (r && r[i]) || x); };
      const mutual = async o => { const [a1, a2] = await redis([['SISMEMBER', 'fr:' + me, o], ['SISMEMBER', 'fr:' + o, me]]); return a1 === 1 && a2 === 1; };
      const tgt = () => cleanName(b.to != null ? b.to : b.from != null ? b.from : b.u).toLowerCase();
      if (b.op === 'rename') {
        const name = cleanName(b.u);
        if (!name) return res.status(400).json({ error: 'Escribe un nombre de usuario' });
        const nl = name.toLowerCase(), [raw] = await redis([['GET', 'u:' + me]]);
        if (!raw) return res.status(401).json({ error: 'auth' });
        const rec = J(raw), old = rec.u;
        if (nl === me) {
          rec.u = name;
          await redis([['SET', 'u:' + me, JSON.stringify(rec)], ['HSET', 'dn', me, name]]);
          const [sc] = await redis([['ZSCORE', 'rank', old]]);
          if (sc != null && old !== name) await redis([['ZREM', 'rank', old], ['ZADD', 'rank', +sc, name]]);
          return res.status(200).json({ ok: 1, u: name });
        }
        rec.u = name;
        const [set] = await redis([['SET', 'u:' + nl, JSON.stringify(rec), 'NX']]);
        if (set !== 'OK') return res.status(409).json({ error: 'Ese nombre ya está en uso' });
        const [fo, fi, sc] = await redis([['SMEMBERS', 'fr:' + me], ['SMEMBERS', 'fq:' + me], ['ZSCORE', 'rank', old]]);
        const others = Array.from(new Set((fo || []).concat(fi || []))).slice(0, 300);
        const chk = [];
        others.forEach(f => { chk.push(['SISMEMBER', 'fr:' + f, me]); chk.push(['SISMEMBER', 'fq:' + f, me]); });
        const chr = chk.length ? await redis(chk) : [];
        const cmds = [['DEL', 'u:' + me], ['SET', 's:' + b.token, nl, 'EX', SESS], ['ZREM', 'names', me], ['ZADD', 'names', 0, nl], ['HDEL', 'dn', me], ['HSET', 'dn', nl, name], ['SREM', 'an:users', me], ['SADD', 'an:users', nl]];
        if (rec.e) cmds.push(['SET', 'e:' + rec.e, nl]);
        if (sc != null) { cmds.push(['ZREM', 'rank', old]); cmds.push(['ZADD', 'rank', +sc, name]); }
        ['an:u:', 'fr:', 'fq:', 'ib:', 'ml:', 'tro:', 'trs:', 'pr:'].forEach(k => cmds.push(['RENAME', k + me, k + nl]));
        others.forEach((f, i) => {
          if (chr[2 * i] === 1) { cmds.push(['SREM', 'fr:' + f, me]); cmds.push(['SADD', 'fr:' + f, nl]); }
          if (chr[2 * i + 1] === 1) { cmds.push(['SREM', 'fq:' + f, me]); cmds.push(['SADD', 'fq:' + f, nl]); }
        });
        await redis(cmds);
        return res.status(200).json({ ok: 1, u: name });
      }
      if (b.op === 'find') {
        const q = cleanName(b.q).toLowerCase();
        if (!q) return res.status(200).json({ list: [] });
        const [r] = await redis([['ZRANGEBYLEX', 'names', '[' + q, '[' + q + '\u00ff', 'LIMIT', 0, 13]]);
        const arr = (r || []).filter(x => x !== me).slice(0, 12);
        const dn = await dnOf(arr);
        return res.status(200).json({ list: dn });
      }
      if (b.op === 'online') {
        const [r] = await redis([['ZRANGEBYSCORE', 'on', now_() - 75000, '+inf']]);
        const arr = (r || []).slice(0, 80);
        if (!arr.length) return res.status(200).json({ n: 0, list: [] });
        const out = await redis([['MGET'].concat(arr.map(x => 'pr:' + x)), ['HMGET', 'dn'].concat(arr)]);
        const list = [];
        arr.forEach((x, i) => { const pr = J(out[0] && out[0][i]); if (pr) list.push({ u: (out[1] && out[1][i]) || x, st: pr.st, r: pr.r, me: x === me ? 1 : 0 }); });
        return res.status(200).json({ n: list.length, list });
      }
      if (b.op === 'fr_list') {
        const [fo, fi] = await redis([['SMEMBERS', 'fr:' + me], ['SMEMBERS', 'fq:' + me]]);
        const fl = (fo || []).slice(0, 200), cmds = [];
        fl.forEach(f => { cmds.push(['SISMEMBER', 'fr:' + f, me]); cmds.push(['GET', 'pr:' + f]); });
        const rr = cmds.length ? await redis(cmds) : [];
        const dn = await dnOf(fl.concat(fi || []));
        const friends = [], out = [];
        fl.forEach((f, i) => {
          if (rr[2 * i] === 1) { const pr = J(rr[2 * i + 1]); friends.push({ u: dn[i], on: pr ? 1 : 0, st: pr ? pr.st : '', r: pr ? pr.r : 0 }); } else out.push(dn[i]);
        });
        const inc = (fi || []).map((f, i) => dn[fl.length + i]);
        return res.status(200).json({ friends, out, inc });
      }
      if (b.op === 'fr_add') {
        const o = tgt();
        if (!o || o === me) return res.status(400).json({ error: 'Ese usuario no es válido' });
        const [ex] = await redis([['ZSCORE', 'names', o]]);
        if (ex == null) return res.status(404).json({ error: 'No existe ese usuario' });
        const [cnt] = await redis([['SCARD', 'fr:' + me]]);
        if (cnt >= 200) return res.status(400).json({ error: 'Tienes demasiados amigos agregados' });
        await redis([['SADD', 'fr:' + me, o]]);
        const [back] = await redis([['SISMEMBER', 'fr:' + o, me]]);
        if (back !== 1) await redis([['SADD', 'fq:' + o, me]]); else await redis([['SREM', 'fq:' + me, o]]);
        return res.status(200).json({ ok: 1, mutual: back === 1 });
      }
      if (b.op === 'fr_answer') {
        const o = tgt();
        if (!o) return res.status(400).json({ error: 'op' });
        if (b.ok) await redis([['SADD', 'fr:' + me, o], ['SREM', 'fq:' + me, o]]);
        else await redis([['SREM', 'fq:' + me, o], ['SREM', 'fr:' + o, me]]);
        return res.status(200).json({ ok: 1 });
      }
      if (b.op === 'fr_del') {
        const o = tgt();
        await redis([['SREM', 'fr:' + me, o], ['SREM', 'fr:' + o, me], ['SREM', 'fq:' + me, o], ['SREM', 'fq:' + o, me]]);
        return res.status(200).json({ ok: 1 });
      }
      if (b.op === 'invite') {
        const o = tgt(), kind = b.kind === 'room' ? 'room' : b.kind === 'eve' ? 'eve' : '';
        if (!o || !kind || !/^[A-Za-z0-9]{3,16}$/.test(String(b.code || ''))) return res.status(400).json({ error: 'Invitación inválida' });
        if (!(await mutual(o))) return res.status(403).json({ error: 'Solo puedes invitar a amigos que también te agregaron' });
        const [pr] = await redis([['GET', 'pr:' + o]]);
        if (!pr) return res.status(409).json({ error: 'Ese jugador no está conectado ahora' });
        const [mine] = await redis([['HGET', 'dn', me]]);
        await redis([['LPUSH', 'ib:' + o, JSON.stringify({ f: mine || me, k: kind, c: String(b.code), t: now_() })], ['LTRIM', 'ib:' + o, 0, 9], ['EXPIRE', 'ib:' + o, 150]]);
        return res.status(200).json({ ok: 1 });
      }
      if (b.op === 'inbox') {
        const [ib, , fi, tro, ml, , trs] = await redis([['LRANGE', 'ib:' + me, 0, -1], ['DEL', 'ib:' + me], ['SMEMBERS', 'fq:' + me], ['SMEMBERS', 'tro:' + me], ['LRANGE', 'ml:' + me, 0, -1], ['DEL', 'ml:' + me], ['SMEMBERS', 'trs:' + me]]);
        const inv = (ib || []).map(J).filter(x => x && now_() - x.t < 100000);
        const mail = (ml || []).map(J).filter(x => x && Number.isFinite(+x.p));
        const ids = Array.from(new Set((tro || []).concat(trs || []))).slice(0, 40);
        const offs = ids.length ? (await redis([['MGET'].concat(ids.map(i => 'tr:' + i))]))[0] : [];
        const trades = [], outs = [], dead = [];
        ids.forEach((id, i) => { const o = J(offs[i]); if (!o) { dead.push(id); return; } if (o.to === me) trades.push(o); else if (o.from === me) outs.push(o); });
        if (dead.length) await redis(dead.map(id => ['SREM', 'tro:' + me, id]).concat(dead.map(id => ['SREM', 'trs:' + me, id])));
        const dn = await dnOf(fi || []);
        return res.status(200).json({ inv, inc: dn, trades, out: outs, mail });
      }
      if (b.op === 'profile') {
        const o = tgt();
        if (!o || !(await mutual(o))) return res.status(403).json({ error: 'Solo puedes ver el equipo de tus amigos' });
        const [raw] = await redis([['GET', 'u:' + o]]);
        const rec = J(raw);
        if (!rec) return res.status(404).json({ error: 'No existe' });
        const sq = (rec.data && rec.data.sq) || {};
        return res.status(200).json({ u: rec.u, inv: sq.inv || [], s: sq.s || [] });
      }
      if (b.op === 'trade_offer') {
        const o = tgt(), give = Math.floor(+b.give), want = Math.floor(+b.want);
        if (!o || !Number.isFinite(give) || !Number.isFinite(want) || give < 0 || want < 0 || give >= 100000 || want >= 100000) return res.status(400).json({ error: 'Oferta inválida' });
        if (!(await mutual(o))) return res.status(403).json({ error: 'Solo puedes cambiar jugadores con tus amigos' });
        const [cnt] = await redis([['SCARD', 'trs:' + me]]);
        if (cnt >= 10) return res.status(400).json({ error: 'Ya tienes 10 ofertas pendientes' });
        const [mine, theirs] = await redis([['HGET', 'dn', me], ['HGET', 'dn', o]]);
        const id = hid(), off = { id, from: me, fn: mine || me, to: o, tn: theirs || o, give, want, t: now_() };
        await redis([['SET', 'tr:' + id, JSON.stringify(off)], ['SADD', 'tro:' + o, id], ['SADD', 'trs:' + me, id]]);
        return res.status(200).json({ ok: 1, id });
      }
      if (b.op === 'trade_answer' || b.op === 'trade_cancel') {
        const id = String(b.id || '');
        if (!/^[a-f0-9]{10}$/.test(id)) return res.status(400).json({ error: 'op' });
        const [raw] = await redis([['GETDEL', 'tr:' + id]]);
        const off = J(raw);
        if (!off) return res.status(404).json({ error: 'La oferta ya no existe' });
        const cancel = b.op === 'trade_cancel';
        if ((cancel && off.from !== me) || (!cancel && off.to !== me)) { await redis([['SET', 'tr:' + id, raw]]); return res.status(403).json({ error: 'No es tu oferta' }); }
        const cmds = [['SREM', 'tro:' + off.to, id], ['SREM', 'trs:' + off.from, id]];
        if (!cancel && b.ok) cmds.push(['RPUSH', 'ml:' + off.from, JSON.stringify({ p: off.want, w: 'ok', f: off.tn })]);
        else if (!cancel) cmds.push(['RPUSH', 'ml:' + off.from, JSON.stringify({ p: off.give, w: 'back', f: off.tn })]);
        await redis(cmds);
        return res.status(200).json({ ok: 1, give: off.give, want: off.want });
      }
    }
    return res.status(400).json({ error: 'op' });
  } catch (e) {
    if (e && e.message === 'big') return res.status(413).json({ error: 'Datos demasiado grandes' });
    if (e && e.message === 'limit') return res.status(503).json({ error: 'db', why: 'limit' });
    return res.status(500).json({ error: 'db' });
  }
};
