/* =========================
   Encodify | script.js (Best Compact + Stable)
   - Uses 8192 Persian words (13 bits/word) from window.WORDS_RAW
   - Bit-packing => much shorter output + less repetition
   - Header: packed nonce+flags (no repetitive start)
   - Body: length-prefixed packed => robust decode
   - Optional: gzip (before whitening/encryption)
   - No password: whitening (nonce-based XOR) => breaks patterns
   - With password: AES-GCM + PBKDF2
   - Emojis/punctuation: decorative only, stripped on decode
   - Random 16-char key generator
   ========================= */

/* ---------- CONFIG ---------- */
const VERSION = 1;
const DICT_SIZE = 8192;
const BITS_PER_WORD = 13;

const HEADER_NONCE_LEN = 12;
const HEADER_LEN = 14; // nonce(12) + flags(1) + version(1)
const HEADER_WORD_COUNT = Math.ceil((HEADER_LEN * 8) / BITS_PER_WORD);

const PBKDF2_ITERATIONS = 150000;
const MAX_PLAINTEXT_BYTES = 200_000;

// Decorative emojis
const EMOJI_RATE = 0.03; // 3% (low, not bloating output)
const EMOJI_MIN_GAP = 18;
const EMOJI_MAX_GAP = 34;

/* ---------- UI helpers ---------- */
const te = new TextEncoder();
const td = new TextDecoder();
const $ = (id) => document.getElementById(id);
const msg = $("msg");

function ok(t) { msg.textContent = "✔ " + t; }
function err(t) { msg.textContent = "❌ " + t; }
function info(t) { msg.textContent = "ℹ️ " + t; }

/* ---------- Emoji Pool (decorative only) ---------- */
const EMOJI_POOL = [
  "😀","😃","😄","😁","😆","😅","😂","🤣","🙂","😉","😊","😇","😍","😘","😗","😙","😚","😋","😛","😜","😝","😎","🤓","🧐","🤗","🤔",
  "💛","💚","💙","💜","🧡","🤍","🖤","💘","💝","💖","💗","💓","💞","💕","💟","❣","💯","✨","🌟","⭐","⚡","🔥","💧","🌈","🌙",
  "🌸","🌼","🌻","🌺","🌷","🌹","🥀","🌿","🍀","🌱","🌳","🌲","🌴","🌵","🍁","🍂","🍃","🌊",
  "🎈","🎉","🎊","🎁","🏆","🎯","🎵","🎶","📌","📍","⏰","📅","📝","📚","📖","✏","🧠","🔑","🔒","🔓","⚙","🔧","🔨","💡","🔦",
  "📷","🎥","📱","💻","🚀","✈","🚗","🚲","🚶","🏃","🤝","👏","🙌","🙏","☀","☁","🌧","❄","⛅","⛈","🌦","🌤",
];

function isSafeEmoji(e) {
  if (e.includes("\u200D")) return false;
  if (e.includes("\uFE0F")) return false;
  if (/\s/.test(e)) return false;
  return true;
}

const SAFE_EMOJIS = EMOJI_POOL.filter(isSafeEmoji);
const SAFE_EMOJI_SET = new Set(SAFE_EMOJIS);

/* ---------- Punctuation (decorative) ---------- */
const PUNCT = ["،", "،", ".", ".", "؛", "؟"];

/* ---------- PRNG + hash ---------- */
function xorshift32(seed) {
  let x = seed >>> 0;
  return () => {
    x ^= x << 13; x >>>= 0;
    x ^= x >> 17; x >>>= 0;
    x ^= x << 5;  x >>>= 0;
    return x >>> 0;
  };
}

function fnv1a32FromString(str) {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h >>> 0;
}

function u32ToBytes(n) {
  return new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
}
function bytesToU32(b) {
  return ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
}

function concatBytes(...arrays) {
  const len = arrays.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

/* ---------- gzip ---------- */
async function gzipCompress(u8) {
  if (!("CompressionStream" in window)) return u8;
  const cs = new CompressionStream("gzip");
  const stream = new Blob([u8]).stream().pipeThrough(cs);
  const ab = await new Response(stream).arrayBuffer();
  return new Uint8Array(ab);
}

async function gzipDecompress(u8) {
  if (!("DecompressionStream" in window)) return u8;
  const ds = new DecompressionStream("gzip");
  const stream = new Blob([u8]).stream().pipeThrough(ds);
  const ab = await new Response(stream).arrayBuffer();
  return new Uint8Array(ab);
}

/* ---------- Whitening (no-password) ---------- */
async function keystream(seedBytes, length) {
  const out = new Uint8Array(length);
  let produced = 0;
  let counter = 0;

  while (produced < length) {
    const c = u32ToBytes(counter++);
    const block = new Uint8Array(seedBytes.length + 4);
    block.set(seedBytes, 0);
    block.set(c, seedBytes.length);

    const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", block));
    const take = Math.min(hash.length, length - produced);
    out.set(hash.slice(0, take), produced);
    produced += take;
  }

  return out;
}

async function xorWhiten(bytes, nonceBytes) {
  const seed = new Uint8Array(nonceBytes.length + 1);
  seed.set(nonceBytes, 0);
  seed[nonceBytes.length] = VERSION;

  const ks = await keystream(seed, bytes.length);
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) out[i] = bytes[i] ^ ks[i];
  return out;
}

/* ---------- AES-GCM ---------- */
async function deriveKey(pass, salt) {
  const baseKey = await crypto.subtle.importKey(
      "raw",
      te.encode(pass),
      "PBKDF2",
      false,
      ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
  );
}

async function encryptAESGCM(payload, pass) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(pass, salt);

  const cipherAB = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, payload);
  return concatBytes(salt, iv, new Uint8Array(cipherAB));
}

async function decryptAESGCM(packed, pass) {
  if (packed.length < 28) throw new Error("داده ناقص است");
  const salt = packed.slice(0, 16);
  const iv = packed.slice(16, 28);
  const cipher = packed.slice(28);

  const key = await deriveKey(pass, salt);

  let plainAB;
  try {
    plainAB = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher);
  } catch {
    throw new Error("کلید نادرست است یا داده دستکاری شده");
  }
  return new Uint8Array(plainAB);
}

/* ---------- Dictionary loading from window.WORDS_RAW ---------- */
const ZWNJ = "\u200c";
const PERSIAN_WORD_RE = /^[\u0600-\u06FF\u200c]+$/;

function normalizeWord(w) {
  if (!w) return "";
  w = w.trim().replace(/^\uFEFF/, "");
  w = w.replace(/\u064A/g, "\u06CC").replace(/\u0643/g, "\u06A9");
  w = w.replace(/\s+/g, ZWNJ);
  w = w.replace(/[،؛,.!?:"'()\[\]{}<>«»…ـ]/g, "");
  w = w.replace(/\u200c{2,}/g, "\u200c");
  w = w.replace(/^\u200c+/, "").replace(/\u200c+$/, "");
  if (!w) return "";
  if (!PERSIAN_WORD_RE.test(w)) return "";
  // allow more lengths for 8192 to increase variety
  if (w.length < 2 || w.length > 16) return "";
  return w;
}

function stableSeedFromWords(words) {
  let h = 2166136261 >>> 0;
  const step = Math.max(1, Math.floor(words.length / 97));
  for (let i = 0; i < words.length; i += step) {
    const s = words[i];
    for (let j = 0; j < s.length; j++) {
      h ^= s.charCodeAt(j);
      h = Math.imul(h, 16777619) >>> 0;
    }
  }
  h ^= words.length >>> 0;
  return h >>> 0;
}

function shuffleArray(arr, rand) {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = (rand() % (i + 1)) >>> 0;
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

let WORDS = null;
let HEADER_INDEX = null;

function makeWordIndexMap(wordlist) {
  const m = new Map();
  for (let i = 0; i < wordlist.length; i++) m.set(wordlist[i], i);
  return m;
}

function loadDictFromGlobal(targetSize) {
  const raw = window.WORDS_RAW;
  if (!raw || typeof raw !== "string") {
    throw new Error("WORDS_RAW پیدا نشد. مطمئن شوید words-fa.js قبل از script.js لود شده است.");
  }

  const lines = raw.split(/\r?\n/);
  const set = new Set();

  for (const line of lines) {
    const w = normalizeWord(line);
    if (w) set.add(w);
  }

  const all = Array.from(set);
  if (all.length < targetSize) throw new Error(`کلمات معتبر کافی نیست (${all.length} < ${targetSize}).`);

  const seed = stableSeedFromWords(all);
  const rand = xorshift32(seed);
  const shuffled = shuffleArray(all, rand);

  const dict = shuffled.slice(0, targetSize);
  return dict;
}

/* ---------- Tokenization for decode (strip emojis + punctuation) ---------- */
function tokenizeInput(text) {
  if (!text) return [];

  text = text.replace(/\uFE0F/g, "").replace(/\u200D/g, "");
  text = text.replace(/\s+/g, " ").trim();
  if (!text) return [];

  const raw = text.split(" ").filter(Boolean);
  const out = [];

  for (let t of raw) {
    // remove punctuation edges
    t = t
        .replace(/^[\u061B\uFF1B\u060C\u066B\u066C\uFF0C\u061F\uFF1F.!?,:;"'()\[\]{}<>«»…ـ]+/g, "")
        .replace(/[\u061B\uFF1B\u060C\u066B\u066C\uFF0C\u061F\uFF1F.!?,:;"'()\[\]{}<>«»…ـ]+$/g, "");

    if (!t) continue;

    // drop decorative emojis
    if (SAFE_EMOJI_SET.has(t)) continue;

    out.push(t);
  }
  return out;
}

/* ---------- Packing / Unpacking 13-bit ---------- */
function rawBytesToWords(bytes, wordlist) {
  let bits = 0;
  let buf = 0;
  const mask = (1 << BITS_PER_WORD) - 1;
  const res = [];

  for (const b of bytes) {
    buf = (buf << 8) | b;
    bits += 8;

    while (bits >= BITS_PER_WORD) {
      bits -= BITS_PER_WORD;
      res.push(wordlist[(buf >> bits) & mask]);
    }
    buf = buf & ((1 << bits) - 1);
  }

  if (bits > 0) {
    res.push(wordlist[(buf << (BITS_PER_WORD - bits)) & mask]);
  }

  return res;
}

function wordsToRawBytes(tokens, byteLen, wordlist, indexMap) {
  let bits = 0;
  let buf = 0;
  const out = [];
  const mask = (1 << BITS_PER_WORD) - 1;

  for (const w of tokens) {
    const idx = indexMap.get(w);
    if (idx === undefined) throw new Error("کلمه نامعتبر: " + w);

    buf = (buf << BITS_PER_WORD) | (idx & mask);
    bits += BITS_PER_WORD;

    while (bits >= 8) {
      bits -= 8;
      out.push((buf >> bits) & 255);
      buf = buf & ((1 << bits) - 1);
      if (out.length === byteLen) return new Uint8Array(out);
    }
  }

  throw new Error("هدر ناقص است");
}

function bytesToWordsPacked(bytes, wordlist) {
  const len = bytes.length >>> 0;
  const data = concatBytes(u32ToBytes(len), bytes);
  return rawBytesToWords(data, wordlist);
}

function wordsToBytesPacked(tokens, wordlist, indexMap) {
  let bits = 0;
  let buf = 0;
  const out = [];
  const mask = (1 << BITS_PER_WORD) - 1;

  for (const w of tokens) {
    const idx = indexMap.get(w);
    if (idx === undefined) throw new Error("کلمه نامعتبر: " + w);

    buf = (buf << BITS_PER_WORD) | (idx & mask);
    bits += BITS_PER_WORD;

    while (bits >= 8) {
      bits -= 8;
      out.push((buf >> bits) & 255);
      buf = buf & ((1 << bits) - 1);
    }
  }

  const all = new Uint8Array(out);
  if (all.length < 4) throw new Error("داده کافی نیست");

  const len = bytesToU32(all.slice(0, 4));
  const payload = all.slice(4);
  if (payload.length < len) throw new Error("داده ناقص/دستکاری شده");
  return payload.slice(0, len);
}

/* ---------- Decorative injection (no length bloat for short texts) ---------- */
function decorate(words, nonceBytes) {
  const seed = bytesToU32(nonceBytes.slice(0, 4)) ^ 0x9e3779b9;
  const rand = xorshift32(seed);

  const header = words.slice(0, HEADER_WORD_COUNT);
  const body = words.slice(HEADER_WORD_COUNT);

  const out = header.slice();

  // target emoji count based on body length
  const targetEmojis = Math.floor(body.length * EMOJI_RATE);
  let emitted = 0;
  let nextEmojiAt = EMOJI_MIN_GAP + (rand() % (EMOJI_MAX_GAP - EMOJI_MIN_GAP + 1));

  for (let i = 0; i < body.length; i++) {
    let w = body[i];

    // punctuation rarely
    if (i > 0 && (rand() % 100) < 8) {
      w = w + PUNCT[rand() % PUNCT.length];
    }

    out.push(w);

    // emojis very rare and only for long bodies
    if (body.length > 40 && emitted < targetEmojis && i >= nextEmojiAt) {
      out.push(SAFE_EMOJIS[rand() % SAFE_EMOJIS.length]);
      emitted++;
      nextEmojiAt = i + EMOJI_MIN_GAP + (rand() % (EMOJI_MAX_GAP - EMOJI_MIN_GAP + 1));
    }
  }

  // end punctuation sometimes
  if (out.length > HEADER_WORD_COUNT + 14 && (rand() % 100) < 15) {
    out[out.length - 1] = out[out.length - 1] + ((rand() % 2) ? "." : "!");
  }

  return out.join(" ");
}

/* ---------- Header encode/decode ---------- */
function encodeHeader(nonceBytes, flags) {
  const headerBytes = new Uint8Array(HEADER_LEN);
  headerBytes.set(nonceBytes, 0);
  headerBytes[HEADER_NONCE_LEN] = flags & 255;
  headerBytes[HEADER_NONCE_LEN + 1] = VERSION & 255;
  return rawBytesToWords(headerBytes, WORDS);
}

function decodeHeader(tokens) {
  if (tokens.length < HEADER_WORD_COUNT + 1) throw new Error("متن خیلی کوتاه است");

  const headerTokens = tokens.slice(0, HEADER_WORD_COUNT);
  const headerBytes = wordsToRawBytes(headerTokens, HEADER_LEN, WORDS, HEADER_INDEX);

  const nonce = headerBytes.slice(0, HEADER_NONCE_LEN);
  const flags = headerBytes[HEADER_NONCE_LEN];
  const ver = headerBytes[HEADER_NONCE_LEN + 1];
  if (ver !== VERSION) throw new Error("نسخه پشتیبانی نمی‌شود");

  const rest = tokens.slice(HEADER_WORD_COUNT);
  if (!rest.length) throw new Error("داده ناقص است");

  return { nonce, flags, restTokens: rest };
}

/* ---------- Main encode/decode ---------- */
async function encodeText(inputText, password) {
  const pass = (password || "").trim();
  const raw = te.encode(inputText);
  if (raw.length > MAX_PLAINTEXT_BYTES) throw new Error("متن خیلی بزرگ است");

  const nonce = crypto.getRandomValues(new Uint8Array(HEADER_NONCE_LEN));

  // gzip first
  const gz = await gzipCompress(raw);
  const useGzip = gz.length < raw.length;
  let payload = useGzip ? gz : raw;

  // flags: bit0 encrypted, bit1 gz, bit2 whiten
  const isEncrypted = !!pass;
  const useWhiten = !isEncrypted;
  const flags = (isEncrypted ? 1 : 0) | (useGzip ? 2 : 0) | (useWhiten ? 4 : 0);

  // whitening for plaintext
  if (useWhiten) {
    payload = await xorWhiten(payload, nonce);
  }

  // encryption if pass
  if (isEncrypted) {
    payload = await encryptAESGCM(payload, pass);
  }

  const headerWords = encodeHeader(nonce, flags);
  const bodyWords = bytesToWordsPacked(payload, WORDS);

  return decorate([...headerWords, ...bodyWords], nonce);
}

async function decodeText(inputWords, password) {
  const pass = (password || "").trim();
  const tokens = tokenizeInput(inputWords);
  if (!tokens.length) throw new Error("ورودی خالی است");

  const { nonce, flags, restTokens } = decodeHeader(tokens);

  const isEncrypted = (flags & 1) === 1;
  const isGzip = (flags & 2) === 2;
  const isWhiten = (flags & 4) === 4;

  if (isEncrypted && !pass) throw new Error("این متن با کلید رمز شده است");

  let payload = wordsToBytesPacked(restTokens, WORDS, HEADER_INDEX);

  if (isEncrypted) {
    payload = await decryptAESGCM(payload, pass);
  }

  if (isWhiten) {
    payload = await xorWhiten(payload, nonce);
  }

  if (isGzip) {
    payload = await gzipDecompress(payload);
  }

  return td.decode(payload);
}

/* ---------- Random key generator ---------- */
function generateRandomKey(length = 16) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  let out = "";
  for (let i = 0; i < length; i++) out += alphabet[bytes[i] % alphabet.length];
  return out;
}

function setPasswordRandom() {
  const key = generateRandomKey(16);
  const passEl = $("pass");
  passEl.value = key;
  passEl.focus();
  passEl.setSelectionRange(0, key.length);
  info("کلید رندوم ساخته شد");
}

/* ---------- UI Actions ---------- */
async function doEncrypt() {
  msg.textContent = "";
  const text = $("plain").value;
  if (!text.trim()) {
    $("out").value = "";
    info("ورودی خالی است");
    return;
  }

  const key = $("pass").value || "";
  $("out").value = await encodeText(text, key);
  ok(key.trim() ? "رمزنگاری انجام شد" : "مخدوش‌سازی انجام شد");
}

async function doDecrypt() {
  msg.textContent = "";
  const coded = $("plain").value;
  if (!coded.trim()) {
    $("out").value = "";
    info("ورودی خالی است");
    return;
  }

  const key = $("pass").value || "";
  $("out").value = await decodeText(coded, key);
  ok("بازگردانی انجام شد");
}

function swap() {
  [$("plain").value, $("out").value] = [$("out").value, $("plain").value];
  info("جابجا شد");
}

async function copyOut() {
  const v = $("out").value;
  if (!v.trim()) {
    info("چیزی برای کپی نیست");
    return;
  }
  await navigator.clipboard.writeText(v);
  info("کپی شد");
}

function clearForm() {
  $("plain").value = "";
  $("out").value = "";
  $("pass").value = "";
  info("پاک شد");
}

/* ---------- Bootstrapping ---------- */
function setButtonsEnabled(enabled) {
  $("encBtn").disabled = !enabled;
  $("decBtn").disabled = !enabled;
  $("swapBtn").disabled = !enabled;
  $("copyBtn").disabled = !enabled;
  $("clearBtn").disabled = !enabled;

  const passGenBtn = $("passGenBtn");
  if (passGenBtn) passGenBtn.disabled = !enabled;
}

async function init() {
  try {
    setButtonsEnabled(false);
    info("در حال آماده‌سازی...");

    WORDS = loadDictFromGlobal(DICT_SIZE);
    HEADER_INDEX = makeWordIndexMap(WORDS);

    $("encBtn").addEventListener("click", () => doEncrypt().catch((e) => err(e.message)));
    $("decBtn").addEventListener("click", () => doDecrypt().catch((e) => err(e.message)));
    $("swapBtn").addEventListener("click", swap);
    $("copyBtn").addEventListener("click", copyOut);
    $("clearBtn").addEventListener("click", clearForm);

    const passGenBtn = $("passGenBtn");
    if (passGenBtn) {
      passGenBtn.addEventListener("click", () => {
        try { setPasswordRandom(); }
        catch (e) { err(e?.message || "خطا در ساخت کلید"); }
      });
    }

    ok(`آماده است (${DICT_SIZE} کلمه).`);
    setButtonsEnabled(true);
  } catch (e) {
    err(e?.message || "خطا در راه‌اندازی");
  }
}

document.addEventListener("DOMContentLoaded", init);
