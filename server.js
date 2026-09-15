#!/usr/bin/env node
'use strict';
/*
 * Astralia RPG -- lekki serwer "Online": globalny czat, ranking graczy,
 * oraz PRAWDZIWE konta (login+haslo) z postacia zapisywana na serwerze.
 * Celowo ZERO zaleznosci zewnetrznych (tylko wbudowane moduly Node) -- dziala
 * samym `node server.js`, bez `npm install`, wiec latwo go wystawic na
 * dowolnym darmowym hostingu (Render/Railway/Fly.io) albo uruchomic lokalnie.
 *
 * Konta sa prawdziwe (haslo nigdy nie jest zapisywane jawnym tekstem -- tylko
 * solony hash scrypt), ale to wciaz mala, kolezenska instancja: nie ma
 * odzyskiwania hasla przez e-mail, weryfikacji adresu, 2FA ani limitu
 * proby-nie-zgadnij poza prostym rate-limitem per IP. Nie uzywaj tu hasla,
 * ktorego uzywasz gdzie indziej.
 *
 * Endpointy:
 *   GET  /api/health                 -> { ok, players, messages, accounts }
 *   GET  /api/leaderboard            -> { players: [...] }  (top 50)
 *   POST /api/leaderboard            -> zapisuje/aktualizuje wpis gracza
 *   GET  /api/chat?since=<ts>        -> wiadomosci nowsze niz `since`
 *   POST /api/chat                   -> wysyla wiadomosc na czacie
 *   POST /api/register               -> { username, password } -> { ok, token, username }
 *   POST /api/login                  -> { username, password } -> { ok, token, username }
 *   POST /api/logout                 -> { token } -> { ok }
 *   GET  /api/character?token=...    -> { character: {...} | null }
 *   POST /api/character              -> { token, character } -> { ok, updatedAt }
 *
 * Dom Aukcyjny (auction house) -- asynchroniczny handel miedzy graczami.
 * Serwer nie zna semantyki przedmiotow (traktuje `item` jako nieprzezroczysty
 * JSON, tak jak `character`), wiec dziala jak depozyt: sprzedajacy "wklada"
 * przedmiot na serwer (znika z jego lokalnego ekwipunku), kupujacy odbiera go
 * natychmiast w odpowiedzi na /buy, a zloto dla sprzedajacego czeka w
 * `pendingGold` do odebrania przez /claim (bo gracz moze byc offline gdy ktos
 * kupi jego przedmiot -- nie ma tu live-polaczenia miedzy graczami):
 *   GET  /api/auction                -> { listings: [...] }  (aktywne oferty, max 200 najnowszych)
 *   POST /api/auction/list           -> { token, item, price } -> { ok, listing }
 *   POST /api/auction/buy            -> { token, listingId } -> { ok, item }
 *   POST /api/auction/cancel         -> { token, listingId } -> { ok }  (przedmiot trafia do pendingItems)
 *   GET  /api/auction/mine?token=... -> { myListings, pendingGold, pendingItems }
 *   POST /api/auction/claim          -> { token } -> { ok, gold, items }  (zeruje pendingGold/pendingItems)
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 8787;
const DATA_DIR = path.join(__dirname, 'data');
const LEADERBOARD_FILE = path.join(DATA_DIR, 'leaderboard.json');
const CHAT_FILE = path.join(DATA_DIR, 'chat.json');
const ACCOUNTS_FILE = path.join(DATA_DIR, 'accounts.json');
const CHARACTERS_FILE = path.join(DATA_DIR, 'characters.json');
const TOKENS_FILE = path.join(DATA_DIR, 'tokens.json');
const AUCTIONS_FILE = path.join(DATA_DIR, 'auctions.json');

const MAX_CHAT_MESSAGES = 300;
const MAX_LEADERBOARD_ENTRIES = 500;
const NICK_MAX_LEN = 20;
const TEXT_MAX_LEN = 300;
const CONTROL_CHAR_MAX = 31;
const DEL_CHAR = 127;

const USERNAME_MIN_LEN = 3;
const USERNAME_MAX_LEN = 20;
const USERNAME_RE = /^[A-Za-z0-9_]+$/;
const PASSWORD_MIN_LEN = 4;
const PASSWORD_MAX_LEN = 200;
const CHARACTER_MAX_BYTES = 400000; // pelny stan gracza (ekwipunek, questy...) moze byc spory
const SCRYPT_KEYLEN = 64;

function ensureDataFiles() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(LEADERBOARD_FILE)) fs.writeFileSync(LEADERBOARD_FILE, '{}');
  if (!fs.existsSync(CHAT_FILE)) fs.writeFileSync(CHAT_FILE, '[]');
  if (!fs.existsSync(ACCOUNTS_FILE)) fs.writeFileSync(ACCOUNTS_FILE, '{}');
  if (!fs.existsSync(CHARACTERS_FILE)) fs.writeFileSync(CHARACTERS_FILE, '{}');
  if (!fs.existsSync(TOKENS_FILE)) fs.writeFileSync(TOKENS_FILE, '{}');
  if (!fs.existsSync(AUCTIONS_FILE)) fs.writeFileSync(AUCTIONS_FILE, JSON.stringify({ listings: [], pendingGold: {}, pendingItems: {} }));
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

// --- Hasla: solony scrypt, nigdy jawny tekst. scryptSync blokuje na chwile
// (rzedu dziesiatek ms) -- akceptowalne, bo logowanie/rejestracja sa rzadkie
// w tej skali, a trzymanie zero-dependency wyklucza biblioteki typu bcrypt.
function hashPassword(password, saltHex) {
  const salt = saltHex ? Buffer.from(saltHex, 'hex') : crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, SCRYPT_KEYLEN);
  return { hash: hash.toString('hex'), salt: salt.toString('hex') };
}
function verifyPassword(password, saltHex, hashHex) {
  const salt = Buffer.from(saltHex, 'hex');
  const computed = crypto.scryptSync(password, salt, SCRYPT_KEYLEN);
  const expected = Buffer.from(hashHex, 'hex');
  if (computed.length !== expected.length) return false;
  return crypto.timingSafeEqual(computed, expected);
}
function makeToken() {
  return crypto.randomBytes(24).toString('hex');
}
function validUsername(u) {
  return typeof u === 'string' && u.length >= USERNAME_MIN_LEN && u.length <= USERNAME_MAX_LEN && USERNAME_RE.test(u);
}

ensureDataFiles();
let leaderboard = readJson(LEADERBOARD_FILE, {}); // keyed by playerId
let chat = readJson(CHAT_FILE, []); // [{id, nick, text, ts}]
let chatIdCounter = chat.length ? chat[chat.length - 1].id + 1 : 1;
let accounts = readJson(ACCOUNTS_FILE, {}); // { usernameLower: { username, salt, hash, createdAt } }
let characters = readJson(CHARACTERS_FILE, {}); // { usernameLower: { character, updatedAt } }
let tokens = readJson(TOKENS_FILE, {}); // { token: usernameLower }
let auctions = readJson(AUCTIONS_FILE, { listings: [], pendingGold: {}, pendingItems: {} });
if (!auctions.listings) auctions.listings = [];
if (!auctions.pendingGold) auctions.pendingGold = {};
if (!auctions.pendingItems) auctions.pendingItems = {};
let auctionIdCounter = auctions.listings.reduce((max, l) => Math.max(max, l.id), 0) + 1;

const AUCTION_MAX_ACTIVE_PER_SELLER = 8;
const AUCTION_MAX_TOTAL_LISTINGS = 500;
const AUCTION_MIN_PRICE = 1;
const AUCTION_MAX_PRICE = 50000000;
const AUCTION_ITEM_MAX_BYTES = 4000;
const AUCTION_PENDING_ITEMS_MAX = 40; // na gracza -- zabezpieczenie przed nieograniczonym magazynem, gdy ktos nie odbiera

function usernameForToken(token) {
  if (typeof token !== 'string' || !token) return null;
  return tokens[token] || null;
}

const server = http.createServer(async (req, res) => {
  const ip = req.socket.remoteAddress || 'unknown';
  let url;
  try { url = new URL(req.url, `http://${req.headers.host}`); } catch (e) { send(res, 400, { error: 'bad url' }); return; }

  if (req.method === 'OPTIONS') { send(res, 204, {}); return; }

  try {
    if (url.pathname === '/api/health' && req.method === 'GET') {
      send(res, 200, { ok: true, players: Object.keys(leaderboard).length, messages: chat.length, accounts: Object.keys(accounts).length, auctionListings: auctions.listings.length });
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

    if (url.pathname === '/api/register' && req.method === 'POST') {
      if (isRateLimited(ip, 5, 60000)) { send(res, 429, { error: 'too many requests' }); return; }
      const body = await readBody(req, 2000);
      const username = typeof body.username === 'string' ? body.username.trim() : '';
      const password = typeof body.password === 'string' ? body.password : '';
      if (!validUsername(username)) { send(res, 400, { error: 'invalid_username' }); return; }
      if (password.length < PASSWORD_MIN_LEN || password.length > PASSWORD_MAX_LEN) { send(res, 400, { error: 'invalid_password' }); return; }
      const key = username.toLowerCase();
      if (accounts[key]) { send(res, 409, { error: 'username_taken' }); return; }
      const { hash, salt } = hashPassword(password);
      accounts[key] = { username, salt, hash, createdAt: Date.now() };
      writeJson(ACCOUNTS_FILE, accounts);
      const token = makeToken();
      tokens[token] = key;
      writeJson(TOKENS_FILE, tokens);
      send(res, 200, { ok: true, token, username });
      return;
    }

    if (url.pathname === '/api/login' && req.method === 'POST') {
      if (isRateLimited(ip, 10, 60000)) { send(res, 429, { error: 'too many requests' }); return; }
      const body = await readBody(req, 2000);
      const username = typeof body.username === 'string' ? body.username.trim() : '';
      const password = typeof body.password === 'string' ? body.password : '';
      const key = username.toLowerCase();
      const acct = accounts[key];
      if (!acct || !verifyPassword(password, acct.salt, acct.hash)) { send(res, 401, { error: 'invalid_credentials' }); return; }
      const token = makeToken();
      tokens[token] = key;
      writeJson(TOKENS_FILE, tokens);
      send(res, 200, { ok: true, token, username: acct.username });
      return;
    }

    if (url.pathname === '/api/logout' && req.method === 'POST') {
      const body = await readBody(req, 500);
      if (typeof body.token === 'string' && tokens[body.token]) {
        delete tokens[body.token];
        writeJson(TOKENS_FILE, tokens);
      }
      send(res, 200, { ok: true });
      return;
    }

    if (url.pathname === '/api/character' && req.method === 'GET') {
      const token = url.searchParams.get('token');
      const key = usernameForToken(token);
      if (!key) { send(res, 401, { error: 'invalid_token' }); return; }
      const entry = characters[key];
      send(res, 200, { character: entry ? entry.character : null, updatedAt: entry ? entry.updatedAt : null });
      return;
    }

    if (url.pathname === '/api/character' && req.method === 'POST') {
      if (isRateLimited(ip, 20, 60000)) { send(res, 429, { error: 'too many requests' }); return; }
      const body = await readBody(req, CHARACTER_MAX_BYTES);
      const key = usernameForToken(body.token);
      if (!key) { send(res, 401, { error: 'invalid_token' }); return; }
      if (body.character === undefined || body.character === null || typeof body.character !== 'object') {
        send(res, 400, { error: 'missing_character' }); return;
      }
      const updatedAt = Date.now();
      characters[key] = { character: body.character, updatedAt };
      writeJson(CHARACTERS_FILE, characters);
      send(res, 200, { ok: true, updatedAt });
      return;
    }

    if (url.pathname === '/api/auction' && req.method === 'GET') {
      const list = auctions.listings.slice(-200).reverse();
      send(res, 200, { listings: list });
      return;
    }

    if (url.pathname === '/api/auction/list' && req.method === 'POST') {
      if (isRateLimited(ip, 10, 60000)) { send(res, 429, { error: 'too many requests' }); return; }
      const body = await readBody(req, AUCTION_ITEM_MAX_BYTES + 1000);
      const key = usernameForToken(body.token);
      if (!key) { send(res, 401, { error: 'invalid_token' }); return; }
      const price = Math.round(Number(body.price));
      if (!Number.isFinite(price) || price < AUCTION_MIN_PRICE || price > AUCTION_MAX_PRICE) { send(res, 400, { error: 'invalid_price' }); return; }
      if (body.item === undefined || body.item === null || typeof body.item !== 'object') { send(res, 400, { error: 'missing_item' }); return; }
      if (JSON.stringify(body.item).length > AUCTION_ITEM_MAX_BYTES) { send(res, 400, { error: 'item_too_large' }); return; }
      const activeCount = auctions.listings.filter((l) => l.sellerKey === key).length;
      if (activeCount >= AUCTION_MAX_ACTIVE_PER_SELLER) { send(res, 400, { error: 'too_many_listings' }); return; }
      if (auctions.listings.length >= AUCTION_MAX_TOTAL_LISTINGS) { send(res, 400, { error: 'auction_house_full' }); return; }
      const acct = accounts[key];
      const listing = {
        id: auctionIdCounter++,
        sellerKey: key,
        sellerNick: acct ? acct.username : key,
        item: body.item,
        price,
        createdAt: Date.now(),
      };
      auctions.listings.push(listing);
      writeJson(AUCTIONS_FILE, auctions);
      send(res, 200, { ok: true, listing });
      return;
    }

    if (url.pathname === '/api/auction/buy' && req.method === 'POST') {
      if (isRateLimited(ip, 10, 60000)) { send(res, 429, { error: 'too many requests' }); return; }
      const body = await readBody(req, 500);
      const key = usernameForToken(body.token);
      if (!key) { send(res, 401, { error: 'invalid_token' }); return; }
      const listingId = Math.round(Number(body.listingId));
      const idx = auctions.listings.findIndex((l) => l.id === listingId);
      if (idx === -1) { send(res, 404, { error: 'listing_not_found' }); return; }
      const listing = auctions.listings[idx];
      if (listing.sellerKey === key) { send(res, 400, { error: 'cannot_buy_own_listing' }); return; }
      auctions.listings.splice(idx, 1);
      auctions.pendingGold[listing.sellerKey] = (auctions.pendingGold[listing.sellerKey] || 0) + listing.price;
      writeJson(AUCTIONS_FILE, auctions);
      send(res, 200, { ok: true, item: listing.item });
      return;
    }

    if (url.pathname === '/api/auction/cancel' && req.method === 'POST') {
      if (isRateLimited(ip, 10, 60000)) { send(res, 429, { error: 'too many requests' }); return; }
      const body = await readBody(req, 500);
      const key = usernameForToken(body.token);
      if (!key) { send(res, 401, { error: 'invalid_token' }); return; }
      const listingId = Math.round(Number(body.listingId));
      const idx = auctions.listings.findIndex((l) => l.id === listingId);
      if (idx === -1) { send(res, 404, { error: 'listing_not_found' }); return; }
      const listing = auctions.listings[idx];
      if (listing.sellerKey !== key) { send(res, 403, { error: 'not_your_listing' }); return; }
      auctions.listings.splice(idx, 1);
      if (!auctions.pendingItems[key]) auctions.pendingItems[key] = [];
      if (auctions.pendingItems[key].length < AUCTION_PENDING_ITEMS_MAX) auctions.pendingItems[key].push(listing.item);
      writeJson(AUCTIONS_FILE, auctions);
      send(res, 200, { ok: true });
      return;
    }

    if (url.pathname === '/api/auction/mine' && req.method === 'GET') {
      const token = url.searchParams.get('token');
      const key = usernameForToken(token);
      if (!key) { send(res, 401, { error: 'invalid_token' }); return; }
      const myListings = auctions.listings.filter((l) => l.sellerKey === key);
      send(res, 200, {
        myListings,
        pendingGold: auctions.pendingGold[key] || 0,
        pendingItems: auctions.pendingItems[key] || [],
      });
      return;
    }

    if (url.pathname === '/api/auction/claim' && req.method === 'POST') {
      if (isRateLimited(ip, 10, 60000)) { send(res, 429, { error: 'too many requests' }); return; }
      const body = await readBody(req, 500);
      const key = usernameForToken(body.token);
      if (!key) { send(res, 401, { error: 'invalid_token' }); return; }
      const gold = auctions.pendingGold[key] || 0;
      const items = auctions.pendingItems[key] || [];
      delete auctions.pendingGold[key];
      delete auctions.pendingItems[key];
      writeJson(AUCTIONS_FILE, auctions);
      send(res, 200, { ok: true, gold, items });
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
