#!/usr/bin/env node
'use strict';
/*
 * Astralia RPG -- lekki serwer "Online" (globalny czat + ranking graczy).
 * Celowo ZERO zaleznosci zewnetrznych (tylko wbudowane moduly Node) -- dziala
 * samym `node server.js`, bez `npm install`, wiec latwo go wystawic na
 * dowolnym darmowym hostingu (Render/Railway/Fly.io) albo uruchomic lokalnie.
 *
 * Gracze NIE maja tu prawdziwych kont -- to celowo uproszczona wersja dla
 * grupy znajomych: kazdy klient generuje sobie losowy `playerId` (trzymany
 * lokalnie w jego przegladarce) i podpisuje sie dowolnym nickiem. Nick nie
 * jest unikalny/chroniony haslem -- wystarczajace dla wspolnego rankingu
 * i czatu, ale NIE nadaje sie jako podstawa realnego systemu kont.
 *
 * Endpointy:
 *   GET  /api/health                 -> { ok, players, messages }
 *   GET  /api/leaderboard            -> { players: [...] }  (top 50)
 *   POST /api/leaderboard            -> zapisuje/aktualizuje wpis gracza
 *   GET  /api/chat?since=<ts>        -> wiadomosci nowsze niz `since`
 *   POST /api/chat                   -> wysyla wiadomosc na czacie
 */
const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 8787;
const DATA_DIR = path.join(__dirname, 'data');
const LEADERBOARD_FILE = path.join(DATA_DIR, 'leaderboard.json');
const CHAT_FILE = path.join(DATA_DIR, 'chat.json');
const MAX_CHAT_MESSAGES = 300;
const MAX_LEADERBOARD_ENTRIES = 500;
const NICK_MAX_LEN = 20;
const TEXT_MAX_LEN = 300;
const CONTROL_CHAR_MAX = 31;
const DEL_CHAR = 127;

function ensureDataFiles() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(LEADERBOARD_FILE)) fs.writeFileSync(LEADERBOARD_FILE, '{}');
  if (!fs.existsSync(CHAT_FILE)) fs.writeFileSync(CHAT_FILE, '[]');
}

function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { return fallback; }
}
function writeJson(file, data) {
  try { fs.writeFileSync(file, JSON.stringify(data)); } catch (e) { /* dysk pelny/read-only -- nie wywalaj serwera */ }
}

// Strips control characters (charCode <= 31, or DEL/127) without relying on a
// regex escape range in source (kept as an explicit char-code loop so this
// file can't accidentally get mangled into literal control bytes by an editor
// or copy-paste, the way a - regex literal can).
function sanitizeText(s, maxLen) {
  if (typeof s !== 'string') return '';
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code <= CONTROL_CHAR_MAX || code === DEL_CHAR) continue;
    out += s[i];
  }
  return out.trim().slice(0, maxLen);
}

// Prosty rate-limit per IP (okno czasowe w pamieci -- resetuje sie przy
// restarcie, co jest akceptowalne dla malej, kolezenskiej instancji).
const rateLimitMap = new Map();
function isRateLimited(ip, limit, windowMs) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip) || { count: 0, resetAt: now + windowMs };
  if (now > entry.resetAt) { entry.count = 0; entry.resetAt = now + windowMs; }
  entry.count += 1;
  rateLimitMap.set(ip, entry);
  return entry.count > limit;
}

function send(res, status, body) {
  const json = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  });
  res.end(json);
}

function readBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    let data = '';
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > maxBytes) { reject(new Error('payload too large')); req.destroy(); return; }
      data += chunk;
    });
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}); } catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

ensureDataFiles();
let leaderboard = readJson(LEADERBOARD_FILE, {}); // keyed by playerId
let chat = readJson(CHAT_FILE, []); // [{id, nick, text, ts}]
let chatIdCounter = chat.length ? chat[chat.length - 1].id + 1 : 1;

const server = http.createServer(async (req, res) => {
  const ip = req.socket.remoteAddress || 'unknown';
  let url;
  try { url = new URL(req.url, `http://${req.headers.host}`); } catch (e) { send(res, 400, { error: 'bad url' }); return; }

  if (req.method === 'OPTIONS') { send(res, 204, {}); return; }

  try {
    if (url.pathname === '/api/health' && req.method === 'GET') {
      send(res, 200, { ok: true, players: Object.keys(leaderboard).length, messages: chat.length });
      return;
    }

    if (url.pathname === '/api/leaderboard' && req.method === 'GET') {
      const top = Object.values(leaderboard)
        .sort((a, b) => (b.level - a.level) || (b.gold - a.gold))
        .slice(0, 50);
      send(res, 200, { players: top });
      return;
    }

    if (url.pathname === '/api/leaderboard' && req.method === 'POST') {
      if (isRateLimited(ip, 10, 10000)) { send(res, 429, { error: 'too many requests' }); return; }
      const body = await readBody(req, 5000);
      const playerId = sanitizeText(body.playerId, 40);
      if (!playerId) { send(res, 400, { error: 'missing playerId' }); return; }
      leaderboard[playerId] = {
        playerId,
        nick: sanitizeText(body.nick, NICK_MAX_LEN) || 'Bezimienny',
        level: Math.max(1, Math.min(9999, Math.round(Number(body.level)) || 1)),
        charClass: sanitizeText(body.charClass, 20) || 'warrior',
        gold: Math.max(0, Math.min(100000000, Math.round(Number(body.gold)) || 0)),
        bossKills: Math.max(0, Math.round(Number(body.bossKills)) || 0),
        bossKills2: Math.max(0, Math.round(Number(body.bossKills2)) || 0),
        bossKills3: Math.max(0, Math.round(Number(body.bossKills3)) || 0),
        updatedAt: Date.now(),
      };
      const keys = Object.keys(leaderboard);
      if (keys.length > MAX_LEADERBOARD_ENTRIES) {
        keys.sort((a, b) => leaderboard[a].updatedAt - leaderboard[b].updatedAt);
        delete leaderboard[keys[0]];
      }
      writeJson(LEADERBOARD_FILE, leaderboard);
      send(res, 200, { ok: true });
      return;
    }

    if (url.pathname === '/api/chat' && req.method === 'GET') {
      const since = Number(url.searchParams.get('since')) || 0;
      const recent = chat.filter((m) => m.ts > since).slice(-100);
      send(res, 200, { messages: recent, now: Date.now() });
      return;
    }

    if (url.pathname === '/api/chat' && req.method === 'POST') {
      if (isRateLimited(ip, 8, 10000)) { send(res, 429, { error: 'too many requests' }); return; }
      const body = await readBody(req, 2000);
      const text = sanitizeText(body.text, TEXT_MAX_LEN);
      const nick = sanitizeText(body.nick, NICK_MAX_LEN) || 'Bezimienny';
      if (!text) { send(res, 400, { error: 'empty message' }); return; }
      const msg = { id: chatIdCounter++, nick, text, ts: Date.now() };
      chat.push(msg);
      if (chat.length > MAX_CHAT_MESSAGES) chat = chat.slice(-MAX_CHAT_MESSAGES);
      writeJson(CHAT_FILE, chat);
      send(res, 200, { ok: true, message: msg });
      return;
    }

    send(res, 404, { error: 'not found' });
  } catch (e) {
    send(res, 400, { error: 'bad request' });
  }
});

server.listen(PORT, () => {
  console.log(`Astralia RPG online-server nasluchuje na porcie ${PORT}`);
});
