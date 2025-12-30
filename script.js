/* =========================
   Encodify | script.js (Final)
   - Uses window.WORDS_RAW (loaded via words.js BEFORE this file)
   - Picks 8192 cleaned unique Persian words (13 bits/word)
   - Header: fixed-size raw-packed (no length prefix) => no repetitive start
   - Body: length-prefixed packed => robust decode
   - Natural punctuation (body only)
   - No password: reversible obfuscation
   - With password: real encryption (AES-GCM)
   - Performance: caches dynamic dictionaries per (seed,passwordHash)
   - Robustness: stronger normalization & better error messages
   ========================= */

/* ---------- CONFIG ---------- */
const DICT_SIZE = 8192;           // Must be power of two
const BITS_PER_WORD = 13;         // log2(8192) = 13
const HEADER_NONCE_LEN = 12;      // 12 bytes nonce
const HEADER_LEN = 13;            // nonce(12) + flags(1)
const HEADER_WORD_COUNT = Math.ceil((HEADER_LEN * 8) / BITS_PER_WORD); // 8 words
const PBKDF2_ITERATIONS = 250000; // crypto strength
const MAX_PLAINTEXT_BYTES = 200_000;

/* ---------- UI helpers ---------- */
const te = new TextEncoder();
const td = new TextDecoder();
const $ = (id) => document.getElementById(id);

const msg = $("msg");
function ok(t) { msg.textContent = "✔ " + t; }
function err(t) { msg.textContent = "❌ " + t; }
function info(t) { msg.textContent = "ℹ️ " + t; }

/* ---------- Punctuation ---------- */
const PUNCT = ["،", "،", "،", ".", ".", "؛", "؟"]; // weighted

function normalizeInputToTokens(text) {
  return text
    .replace(/[،؛,.!?]/g, " ")
    .trim()
    .split(/\s+/)
    .filter(Boolean);
}

/* ---------- PRNG + shuffle ---------- */
function xorshift32(seed) {
  let x = seed >>> 0;
  return () => {
    x ^= x << 13; x >>>= 0;
    x ^= x >> 17; x >>>= 0;
    x ^= x << 5;  x >>>= 0;
    return x >>> 0;
  };
}

function shuffleArray(arr, rand) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = (rand() % (i + 1)) >>> 0;
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

/* ---------- bytes helpers ---------- */
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

function u32ToBytes(n) {
  return new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
}

function bytesToU32(b) {
  return ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
}

/* ---------- hashing helpers (cache keys only) ---------- */
function fnv1a32FromString(str) {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h >>> 0;
}

/* ---------- Dictionary parsing (from window.WORDS_RAW) ---------- */
const PERSIAN_WORD_RE = /^[\u0600-\u06FF\u200c]+$/;

function normalizeWord(w) {
  if (!w) return "";
  w = w.trim();
  w = w.replace(/^\uFEFF/, "");
  w = w.replace(/\s+/g, "");

  // Normalize Arabic Yeh/Kaf to Persian
  w = w.replace(/\u064A/g, "\u06CC").replace(/\u0643/g, "\u06A9");

  if (!PERSIAN_WORD_RE.test(w)) return "";
  if (w.length < 2 || w.length > 24) return "";
  if (w.includes("\u200c\u200c")) return "";

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

function makeWordIndexMap(wordlist) {
  const m = new Map();
  for (let i = 0; i < wordlist.length; i++) m.set(wordlist[i], i);
  return m;
}

function parseDictionaryFromGlobal(targetSize) {
  const raw = window.WORDS_RAW;
  if (!raw || typeof raw !== "string") {
    throw new Error("WORDS_RAW پیدا نشد. مطمئن شوید words.js قبل از script.js لود شده است.");
  }

  const lines = raw.split(/\r?\n/);
  const set = new Set();

  for (const line of lines) {
    const w = normalizeWord(line);
    if (!w) continue;
    set.add(w);
  }

  const all = Array.from(set);
  if (all.length < targetSize) {
    throw new Error(`تعداد کلمات معتبر کافی نیست (${all.length} < ${targetSize}).`);
  }

  const seed = stableSeedFromWords(all);
  const rand = xorshift32(seed);
  const shuffled = shuffleArray(all, rand);

  const dict = shuffled.slice(0, targetSize);
  if (new Set(dict).size !== targetSize) {
    throw new Error("دیکشنری خروجی تکراری دارد (مشکل در پردازش).");
  }

  return dict;
}

/* ---------- Packing ---------- */
function rawBytesToWords(bytes, wordlist, bitsPerWord) {
  let bits = 0;
  let buf = 0;
  const mask = (1 << bitsPerWord) - 1;

  const res = [];
  for (const b of bytes) {
    buf = (buf << 8) | b;
    bits += 8;
    while (bits >= bitsPerWord) {
      bits -= bitsPerWord;
      const v = (buf >> bits) & mask;
      res.push(wordlist[v]);
    }
    buf = buf & ((1 << bits) - 1);
  }

  if (bits > 0) {
    const v = (buf << (bitsPerWord - bits)) & mask;
    res.push(wordlist[v]);
  }

  return res;
}

function wordsToRawBytes(tokens, byteLen, wordlist, indexMap, bitsPerWord) {
  let bits = 0;
  let buf = 0;
  const out = [];
  const mask = (1 << bitsPerWord) - 1;

  for (const w of tokens) {
    const idx = indexMap.get(w);
    if (idx === undefined) throw new Error("کلمه نامعتبر: " + w);

    buf = (buf << bitsPerWord) | (idx & mask);
    bits += bitsPerWord;

    while (bits >= 8) {
      bits -= 8;
      out.push((buf >> bits) & 255);
      buf = buf & ((1 << bits) - 1);
      if (out.length === byteLen) return new Uint8Array(out);
    }
  }

  throw new Error("هدر ناقص است");
}

function bytesToWordsPacked(bytes, wordlist, bitsPerWord) {
  const len = bytes.length >>> 0;
  const data = concatBytes(u32ToBytes(len), bytes);

  let bits = 0;
  let buf = 0;
  const mask = (1 << bitsPerWord) - 1;
  const res = [];

  for (const b of data) {
    buf = (buf << 8) | b;
    bits += 8;
    while (bits >= bitsPerWord) {
      bits -= bitsPerWord;
      const v = (buf >> bits) & mask;
      res.push(wordlist[v]);
    }
    buf = buf & ((1 << bits) - 1);
  }

  if (bits > 0) {
    const v = (buf << (bitsPerWord - bits)) & mask;
    res.push(wordlist[v]);
  }

  return res;
}

function wordsToBytesPacked(tokens, wordlist, indexMap, bitsPerWord) {
  let bits = 0;
  let buf = 0;
  const out = [];
  const mask = (1 << bitsPerWord) - 1;

  for (const w of tokens) {
    const idx = indexMap.get(w);
    if (idx === undefined) throw new Error("کلمه نامعتبر: " + w);

    buf = (buf << bitsPerWord) | (idx & mask);
    bits += bitsPerWord;

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
  if (payload.length < len) throw new Error("داده ناقص است یا دستکاری شده");
  return payload.slice(0, len);
}

/* ---------- Natural punctuation injection (no noise) ---------- */
function injectPunctuation(words, rand, protectCount) {
  const out = [];
  let run = 0;

  for (let i = 0; i < words.length; i++) {
    out.push(words[i]);

    // Never touch header tokens
    if (i < protectCount) continue;

    run++;

    // Punctuation: every ~10..22 words, ~45%
    if (run >= 10) {
      const threshold = 10 + (rand() % 13); // 10..22
      if (run >= threshold) {
        if ((rand() % 100) < 45) {
          out[out.length - 1] = out[out.length - 1] + PUNCT[rand() % PUNCT.length];
        }
        run = 0;
      }
    }
  }

  // End punctuation sometimes
  if (out.length > protectCount + 12 && (rand() % 100) < 25) {
    out[out.length - 1] = out[out.length - 1] + ((rand() % 2) ? "." : "!");
  }

  return out.join(" ");
}

/* ---------- AES-GCM encryption/decryption ---------- */
async function deriveKey(password, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    te.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptAESGCM(plainText, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);

  const cipherBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    te.encode(plainText)
  );

  return concatBytes(salt, iv, new Uint8Array(cipherBuf));
}

async function decryptAESGCM(packed, password) {
  if (packed.length < 28) throw new Error("داده ناقص است");

  const salt = packed.slice(0, 16);
  const iv = packed.slice(16, 28);
  const cipherBytes = packed.slice(28);

  const key = await deriveKey(password, salt);

  let plainBuf;
  try {
    plainBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      cipherBytes
    );
  } catch {
    throw new Error("کلید نادرست است یا داده دستکاری شده");
  }

  return td.decode(plainBuf);
}

/* ---------- Runtime dictionary state ---------- */
let WORDS = null;
let HEADER_INDEX = null;

// Cache dynamic dictionaries per (seedU32,passwordHash)
const DYN_CACHE = new Map();
const DYN_CACHE_MAX = 64;

function cacheSet(key, val) {
  if (DYN_CACHE.has(key)) DYN_CACHE.delete(key);
  DYN_CACHE.set(key, val);
  if (DYN_CACHE.size > DYN_CACHE_MAX) {
    const firstKey = DYN_CACHE.keys().next().value;
    DYN_CACHE.delete(firstKey);
  }
}

function nonceToSeedU32(nonceBytes) {
  return bytesToU32(nonceBytes.slice(0, 4));
}

function buildDynamicWordlist(nonceU32, password) {
  const pass = (password || "").trim();
  const passHash = pass ? fnv1a32FromString(pass) : 0;
  const seed = (nonceU32 ^ passHash) >>> 0;
  const cacheKey = seed + ":" + passHash;

  const cached = DYN_CACHE.get(cacheKey);
  if (cached) return cached;

  const rand = xorshift32(seed);
  const wordlist = shuffleArray(WORDS, rand);
  const indexMap = makeWordIndexMap(wordlist);

  const obj = { wordlist, indexMap };
  cacheSet(cacheKey, obj);
  return obj;
}

function encodeHeader(nonceBytes, flags) {
  const headerBytes = new Uint8Array(HEADER_LEN);
  headerBytes.set(nonceBytes, 0);
  headerBytes[HEADER_NONCE_LEN] = flags & 255;
  return rawBytesToWords(headerBytes, WORDS, BITS_PER_WORD);
}

function decodeHeader(allTokens) {
  if (allTokens.length < HEADER_WORD_COUNT + 1) throw new Error("متن خیلی کوتاه است");

  const headerTokens = allTokens.slice(0, HEADER_WORD_COUNT);
  const headerBytes = wordsToRawBytes(
    headerTokens,
    HEADER_LEN,
    WORDS,
    HEADER_INDEX,
    BITS_PER_WORD
  );

  const nonce = headerBytes.slice(0, HEADER_NONCE_LEN);
  const flags = headerBytes[HEADER_NONCE_LEN];
  const rest = allTokens.slice(HEADER_WORD_COUNT);
  if (!rest.length) throw new Error("داده ناقص است");

  return { nonce, flags, restTokens: rest };
}

/* ---------- Main encode/decode ---------- */
async function encodeText(inputText, password) {
  const pass = (password || "").trim();
  const plainBytes = te.encode(inputText);

  if (plainBytes.length > MAX_PLAINTEXT_BYTES) {
    throw new Error(`متن خیلی بزرگ است (${plainBytes.length} بایت).`);
  }

  const nonce = crypto.getRandomValues(new Uint8Array(HEADER_NONCE_LEN));
  const seedU32 = nonceToSeedU32(nonce);

  const isEncrypted = !!pass;
  const flags = isEncrypted ? 1 : 0;

  const headerWords = encodeHeader(nonce, flags);

  const { wordlist: bodyWordlist } = buildDynamicWordlist(seedU32, pass);

  let bodyBytes;
  if (!isEncrypted) {
    bodyBytes = plainBytes;
  } else {
    bodyBytes = await encryptAESGCM(inputText, pass);
  }

  const bodyWords = bytesToWordsPacked(bodyBytes, bodyWordlist, BITS_PER_WORD);

  const rand = xorshift32(seedU32 ^ 0x9e3779b9);
  return injectPunctuation([...headerWords, ...bodyWords], rand, HEADER_WORD_COUNT);
}

async function decodeText(inputWords, password) {
  const tokens = normalizeInputToTokens(inputWords);
  if (!tokens.length) throw new Error("ورودی خالی است");

  const { nonce, flags, restTokens } = decodeHeader(tokens);
  const seedU32 = nonceToSeedU32(nonce);

  const isEncrypted = (flags & 1) === 1;
  const pass = (password || "").trim();

  if (isEncrypted && !pass) throw new Error("این متن با کلید رمز شده است");

  const { wordlist: bodyWordlist, indexMap: bodyIndexMap } = buildDynamicWordlist(seedU32, pass);
  const bodyBytes = wordsToBytesPacked(restTokens, bodyWordlist, bodyIndexMap, BITS_PER_WORD);

  if (!isEncrypted) return td.decode(bodyBytes);
  return decryptAESGCM(bodyBytes, pass);
}

/* ---------- UI Actions ---------- */
function generateRandomKey(length = 16) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  let out = "";
  for (let i = 0; i < length; i++) {
    out += alphabet[bytes[i] % alphabet.length];
  }
  return out;
}

function setPasswordRandom() {
  const key = generateRandomKey(16);
  const passEl = $("pass");
  passEl.value = key;
  passEl.focus();
  passEl.setSelectionRange(0, key.length);
}

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
  ok(key.trim() ? "رمزنگاری امن انجام شد (با کلید)" : "مخدوش‌سازی انجام شد (بدون کلید)");
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
  info("فرم پاکسازی شد");
}

/* ---------- Bootstrapping ---------- */
function setButtonsEnabled(enabled) {
  $("encBtn").disabled = !enabled;
  $("decBtn").disabled = !enabled;
  $("swapBtn").disabled = !enabled;
  $("copyBtn").disabled = !enabled;
  $("clearBtn").disabled = !enabled;
}

async function init() {
  try {
    setButtonsEnabled(false);

    WORDS = parseDictionaryFromGlobal(DICT_SIZE);
    HEADER_INDEX = makeWordIndexMap(WORDS);
    
    $("encBtn").addEventListener("click", () => doEncrypt().catch((e) => err(e.message)));
    $("decBtn").addEventListener("click", () => doDecrypt().catch((e) => err(e.message)));
    $("swapBtn").addEventListener("click", swap);
    $("copyBtn").addEventListener("click", copyOut);
    $("clearBtn").addEventListener("click", clearForm);

    setButtonsEnabled(true);

  } catch (e) {
    err(e?.message || "خطا در راه‌اندازی");
  }

  const passGenBtn = $("passGenBtn");
    if (passGenBtn) {
      passGenBtn.addEventListener("click", () => {
        try {
          setPasswordRandom();
        } catch (e) {
          err(e?.message || "خطا در ساخت کلید");
        }
      });
    }
}

document.addEventListener("DOMContentLoaded", init);
