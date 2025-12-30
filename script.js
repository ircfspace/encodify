// Short words (2-3 chars) to save SMS space.
const WORDS = [
  "آب", "آر", "آن", "باد", "بار", "باز", "بام", "برگ", 
  "بید", "پا", "پر", "پس", "پل", "پن", "پی", "تار", 
  "تب", "تک", "تور", "تیر", "جا", "جم", "جو", "چین", 
  "خاک", "خم", "خون", "داد", "دار", "در", "دم", "دی", 
  "راز", "راه", "رخ", "رز", "رگ", "زن", "ساز", "سر", 
  "سد", "سگ", "سنگ", "شب", "شط", "شک", "شهر", "شور", 
  "صدا", "صف", "طاق", "طل", "ظن", "عاج", "عود", "فال", 
  "فن", "قر", "قو", "کاخ", "کار", "کام", "کوه", "کی"
]; // 64 words => 6 bits

const $ = (id) => document.getElementById(id);
const msg = $("msg");

function info(t) { msg.textContent = "ℹ️ " + t; }
function ok(t) { msg.textContent = "✔ " + t; }
function err(t) { msg.textContent = "❌ " + t; }

// 2. XOR ENCRYPTION: Adds security without adding JSON length overhead
function xorTransform(bytes, keyString) {
  if (!keyString) return bytes;
  const keyBytes = new TextEncoder().encode(keyString);
  return bytes.map((b, i) => b ^ keyBytes[i % keyBytes.length]);
}

// 3. GZIP COMPRESSION: Shrinks VPN configs significantly
async function compress(text) {
  const stream = new Blob([text]).stream().pipeThrough(new CompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function decompress(bytes) {
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip"));
  return await new Response(stream).text();
}

function bytesToWords(bytes) {
  let bits = 0, buf = 0, res = [];
  // Use a simple terminator approach or just raw flow
  for (const b of bytes) {
    buf = (buf << 8) | b;
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      res.push(WORDS[(buf >> bits) & 63]);
    }
    buf = buf & ((1 << bits) - 1);
  }
  if (bits > 0) res.push(WORDS[(buf << (6 - bits)) & 63]);
  return res.join(" ");
}

function wordsToBytes(text) {
  const tokens = text.trim().split(/\s+/).filter(Boolean);
  if (!tokens.length) throw Error("Empty input");
  
  let bits = 0, buf = 0, out = [];
  for (const w of tokens) {
    const i = WORDS.indexOf(w);
    if (i < 0) throw Error("Invalid word: " + w);
    buf = (buf << 6) | i;
    bits += 6;
    while (bits >= 8) {
      bits -= 8;
      out.push((buf >> bits) & 255);
      buf = buf & ((1 << bits) - 1);
    }
  }
  return new Uint8Array(out);
}

// --- Actions ---

async function encrypt() {
  try {
    const text = $("plain").value.trim();
    const pass = $("pass").value;
    if (!text) return info("ورودی خالی است");

    // 1. Compress
    let data = await compress(text);
    // 2. Encrypt (XOR) if pass exists
    data = xorTransform(data, pass);
    
    // 3. Map to Words
    const result = bytesToWords(data);
    
    $("out").value = result;
    ok(`تبدیل شد! (${result.length} کاراکتر)`);
  } catch (e) {
    err(e.message);
  }
}

async function decrypt() {
  try {
    const coded = $("out").value.trim(); // Assuming user pastes into Output box to decrypt, or Swap
    const pass = $("pass").value;
    // Allow reading from 'plain' if 'out' is empty (bidirectional UI)
    const source = coded || $("plain").value.trim(); 
    
    if (!source) return info("ورودی خالی است");

    // 1. Map from Words
    let data = wordsToBytes(source);
    
    // 2. Decrypt (XOR)
    data = xorTransform(data, pass);
    
    // 3. Decompress
    try {
      const text = await decompress(data);
      // Logic: If decrypt was called, put result in the "other" box
      if(coded) $("plain").value = text; 
      else $("out").value = text;
      
      ok("بازگشایی موفقیت‌آمیز بود");
    } catch (e) {
      throw Error("رمز اشتباه است یا داده خراب شده");
    }
  } catch (e) {
    err(e.message);
  }
}

function copyOut() {
  const v = $("out").value;
  if(v) navigator.clipboard.writeText(v).then(()=>info("کپی شد"));
}

function swap() {
  const temp = $("plain").value;
  $("plain").value = $("out").value;
  $("out").value = temp;
}

$("encBtn").addEventListener("click", encrypt);
$("decBtn").addEventListener("click", decrypt);
$("swapBtn").addEventListener("click", swap);
$("copyBtn").addEventListener("click", copyOut);
$("clearBtn").addEventListener("click", () => {
    $("plain").value = ""; $("out").value = ""; $("pass").value = ""; info("پاک شد");
});