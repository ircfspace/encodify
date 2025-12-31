const WORDS_64 = [
  "آب",
  "آسمان",
  "آتش",
  "ابر",
  "امید",
  "انسان",
  "ایران",
  "باد",
  "باران",
  "باغ",
  "برف",
  "بهار",
  "پرواز",
  "پنجره",
  "پیام",
  "تلاش",
  "توسعه",
  "جاده",
  "جهان",
  "حقیقت",
  "خورشید",
  "دریا",
  "درخت",
  "دل",
  "دوست",
  "راه",
  "رود",
  "رویا",
  "روز",
  "زمان",
  "زمین",
  "زیبا",
  "سفر",
  "سلام",
  "سنگ",
  "سکوت",
  "شادی",
  "شب",
  "صبح",
  "صدا",
  "طبیعت",
  "طلوع",
  "عشق",
  "علم",
  "فردا",
  "فرصت",
  "فصل",
  "فکر",
  "قلم",
  "قلب",
  "کار",
  "کتاب",
  "کوه",
  "کودک",
  "گل",
  "لبخند",
  "لحظه",
  "مردم",
  "مهر",
  "مهتاب",
  "موج",
  "نور",
  "نگاه",
  "هدف",
  "هوا",
  "یاد",
];

const WORDS_POOL = [
  "زندگی",
  "آرامش",
  "محبت",
  "مهربانی",
  "دوستی",
  "امروز",
  "اکنون",
  "آینده",
  "باور",
  "شوق",
  "انگیزه",
  "توان",
  "حرکت",
  "رشد",
  "پیشرفت",
  "اندیشه",
  "خرد",
  "دانش",
  "آگاهی",
  "پیروزی",
  "تجربه",
  "تمرین",
  "توجه",
  "امتحان",
  "پایداری",
  "یاری",
  "همراه",
  "همسفر",
  "رهایی",
  "آغاز",
  "پایان",
  "خاطره",
  "داستان",
  "تصویر",
  "نقش",
  "راز",
  "حس",
  "احساس",
  "دیدار",
  "گفتگو",
  "پرسش",
  "پاسخ",
  "آواز",
  "ترانه",
  "نغمه",
  "رنگ",
  "عطر",
  "خانه",
  "خانواده",
  "دوام",
  "مسیر",
  "قدم",
  "گام",
  "ساحل",
  "افق",
  "سپیده",
  "پرتو",
  "روشنایی",
  "گرما",
  "نسیم",
  "سایه",
  "پناه",
  "سپاس",
  "لب",
  "چشم",
  "دست",
  "خنده",
  "لبخند",
  "یادگار",
  "بیداری",
  "بخشش",
  "امانت",
  "شکوفه",
  "آبی",
  "زرین",
  "سپید",
  "سبز",
  "سرخ",
  "نقره",
  "بلور",
  "چشمه",
  "جوی",
  "آبشار",
  "دشت",
  "کشتزار",
  "پرنده",
  "آهو",
  "ماه",
  "ستاره",
  "خورشید",
  "صبحگاه",
  "شامگاه",
  "بارقه",
  "آذرخش",
  "رعد",
  "برق",
];

const EMOJI_POOL = [
  "😀",
  "😃",
  "😄",
  "😁",
  "😆",
  "😅",
  "😂",
  "🤣",
  "🙂",
  "😉",
  "😊",
  "😇",
  "😍",
  "😘",
  "😗",
  "😙",
  "😚",
  "😋",
  "😛",
  "😜",
  "😝",
  "😎",
  "🤓",
  "🧐",
  "🤗",
  "🤔",
  "😐",
  "😑",
  "🙄",
  "😬",
  "😌",
  "😔",
  "😪",
  "😴",
  "🥳",
  "💛",
  "💚",
  "💙",
  "💜",
  "🧡",
  "🤍",
  "🖤",
  "💘",
  "💝",
  "💖",
  "💗",
  "💓",
  "💞",
  "💕",
  "💟",
  "❣",
  "💯",
  "✨",
  "🌟",
  "⭐",
  "⚡",
  "🔥",
  "💧",
  "🌈",
  "🌙",
  "🌍",
  "🌎",
  "🌏",
  "🌸",
  "🌼",
  "🌻",
  "🌺",
  "🌷",
  "🌹",
  "🥀",
  "🌿",
  "🍀",
  "🌱",
  "🌳",
  "🌲",
  "🌴",
  "🌵",
  "🍁",
  "🍂",
  "🍃",
  "🌊",
  "⛰",
  "🏔",
  "🏕",
  "🎈",
  "🎉",
  "🎊",
  "🎁",
  "🏆",
  "🎯",
  "🎵",
  "🎶",
  "📌",
  "📍",
  "🧭",
  "⏰",
  "📅",
  "📝",
  "📚",
  "📖",
  "✏",
  "🧠",
  "🔑",
  "🔒",
  "🔓",
  "🛡",
  "⚙",
  "🔧",
  "🔨",
  "🧰",
  "🔬",
  "💡",
  "🔦",
  "📷",
  "🎥",
  "📱",
  "💻",
  "🖥",
  "🛰",
  "🚀",
  "✈",
  "🚗",
  "🚲",
  "🚶",
  "🏃",
  "🧘",
  "🤝",
  "👏",
  "🙌",
  "🙏",
  "🌞",
  "☀",
  "☁",
  "🌧",
  "❄",
  "🌨",
  "⛅",
  "⛈",
  "🌦",
  "🌤",
];

function isSafeWord(w) {
  return /^[\u0600-\u06FF]+$/.test(w);
}
function isSafeEmoji(e) {
  if (e.includes("\u200D")) return false;
  if (e.includes("\uFE0F")) return false;
  if (/\s/.test(e)) return false;
  return true;
}

function pickUnique(list, n, predicate) {
  const out = [];
  const seen = new Set();
  for (const x of list) {
    if (predicate && !predicate(x)) continue;
    if (seen.has(x)) continue;
    seen.add(x);
    out.push(x);
    if (out.length === n) break;
  }
  return out;
}

const WORDS = (() => {
  const merged = [...WORDS_64, ...WORDS_POOL];
  const picked = pickUnique(merged, 128, isSafeWord);
  if (picked.length !== 128)
    throw new Error("Not enough safe Persian words: " + picked.length);
  return picked;
})();

const EMOJIS = (() => {
  const picked = pickUnique(EMOJI_POOL, 128, isSafeEmoji);
  if (picked.length !== 128)
    throw new Error("Not enough safe emojis: " + picked.length);
  return picked;
})();

const TOKENS = [...WORDS, ...EMOJIS];
if (TOKENS.length !== 256) throw new Error("TOKENS must be 256");

const TOKEN_TO_INDEX = new Map(TOKENS.map((t, i) => [t, i]));

const te = new TextEncoder();
const td = new TextDecoder();

const $ = (id) => document.getElementById(id);
const msg = $("msg");

function ok(t) {
  msg.textContent = "✔ " + t;
}
function err(t) {
  msg.textContent = "❌ " + t;
}
function info(t) {
  msg.textContent = "ℹ️ " + t;
}

function bytesToTokens(bytes) {
  const len = bytes.length >>> 0;
  const data = new Uint8Array(4 + len);
  data[0] = (len >>> 24) & 255;
  data[1] = (len >>> 16) & 255;
  data[2] = (len >>> 8) & 255;
  data[3] = len & 255;
  data.set(bytes, 4);

  const out = [];
  for (const b of data) out.push(TOKENS[b]);
  return out.join(" ");
}

function tokensToBytes(text) {
  const tokens = text.trim().split(/\s+/).filter(Boolean);
  if (!tokens.length) throw new Error("ورودی خالی است");

  const out = new Uint8Array(tokens.length);
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    const idx = TOKEN_TO_INDEX.get(t);
    if (idx === undefined) throw new Error("توکن نامعتبر: " + t);
    out[i] = idx;
  }

  if (out.length < 4) throw new Error("داده کافی نیست");
  const len = ((out[0] << 24) | (out[1] << 16) | (out[2] << 8) | out[3]) >>> 0;
  const payload = out.slice(4);
  if (payload.length < len) throw new Error("داده ناقص/دستکاری شده");
  return payload.slice(0, len);
}

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

function randBytes(n) {
  const u = new Uint8Array(n);
  crypto.getRandomValues(u);
  return u;
}

async function deriveKey(pass, salt) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    te.encode(pass),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 150000, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function packText(text, pass) {
  const raw = te.encode(text);

  const gz = await gzipCompress(raw);
  const useGzip = gz.length < raw.length;
  const payload = useGzip ? gz : raw;

  const version = 1;
  const encrypted = !!pass;
  const flags = (encrypted ? 1 : 0) | (useGzip ? 2 : 0);

  if (!encrypted) {
    const out = new Uint8Array(2 + payload.length);
    out[0] = version;
    out[1] = flags;
    out.set(payload, 2);
    return out;
  }

  const salt = randBytes(16);
  const iv = randBytes(12);
  const key = await deriveKey(pass, salt);

  const cipherAB = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    payload
  );
  const cipher = new Uint8Array(cipherAB);

  const out = new Uint8Array(2 + 16 + 12 + cipher.length);
  out[0] = version;
  out[1] = flags;
  out.set(salt, 2);
  out.set(iv, 18);
  out.set(cipher, 30);
  return out;
}

async function unpackToText(bytes, pass) {
  if (bytes.length < 2) throw new Error("داده خراب است");
  const version = bytes[0];
  const flags = bytes[1];
  if (version !== 1) throw new Error("نسخه پشتیبانی نمی‌شود");

  const encrypted = (flags & 1) === 1;
  const compressed = (flags & 2) === 2;

  let payload;
  if (!encrypted) {
    payload = bytes.slice(2);
  } else {
    if (!pass) throw new Error("کلید لازم است");
    if (bytes.length < 31) throw new Error("داده ناقص است");

    const salt = bytes.slice(2, 18);
    const iv = bytes.slice(18, 30);
    const cipher = bytes.slice(30);

    const key = await deriveKey(pass, salt);

    let plainAB;
    try {
      plainAB = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        key,
        cipher
      );
    } catch {
      throw new Error("کلید نادرست است یا داده دستکاری شده");
    }
    payload = new Uint8Array(plainAB);
  }

  const raw2 = compressed ? await gzipDecompress(payload) : payload;
  return td.decode(raw2);
}

async function encrypt() {
  msg.textContent = "";
  const text = $("plain").value;
  if (!text.trim()) {
    $("out").value = "";
    info("ورودی خالی است");
    return;
  }
  const pass = ($("pass").value || "").trim();
  const bytes = await packText(text, pass);
  $("out").value = bytesToTokens(bytes);
  ok("انجام شد");
}

async function decrypt() {
  msg.textContent = "";
  const coded = $("plain").value;
  if (!coded.trim()) {
    $("out").value = "";
    info("ورودی خالی است");
    return;
  }
  const pass = ($("pass").value || "").trim();
  const bytes = tokensToBytes(coded);
  const text = await unpackToText(bytes, pass);
  $("out").value = text;
  ok("انجام شد");
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

$("encBtn").addEventListener("click", () =>
  encrypt().catch((e) => err(e.message))
);
$("decBtn").addEventListener("click", () =>
  decrypt().catch((e) => err(e.message))
);
$("swapBtn").addEventListener("click", swap);
$("copyBtn").addEventListener("click", () =>
  copyOut().catch((e) => err(e.message))
);
$("clearBtn").addEventListener("click", clearForm);
