// The README was added by Gemini.

// ==========================================
// 1. ثابت‌ها و تنظیمات اولیه
// ==========================================

// لیست کلمات کوتاه (۲ و ۳ حرفی) برای کاهش حجم پیام متنی
// این لیست جایگزین الگوریتم پیچیده قبلی شده است
const SHORT_WORDS = [
  "آب", "آت", "آد", "آر", "آز", "آس", "آش", "آل", "آن", "آه",
  "اب", "ات", "اد", "ار", "از", "اس", "اش", "ال", "ام", "ان",
  "او", "ای", "با", "بت", "بج", "بچ", "بخ", "بد", "بر", "بز",
  "بس", "بش", "بط", "بغ", "بک", "بل", "بم", "بن", "بو", "به",
  "بی", "پا", "پت", "پچ", "پخ", "پد", "پر", "پز", "پس", "پش",
  "پل", "پم", "پن", "پو", "په", "پی", "تا", "تب", "تخ", "تر",
  "تک", "تل", "تم", "تن", "تو", "ته", "تی", "جا", "جد", "جر",
  "جز", "جس", "جش", "جع", "جف", "جک", "جل", "جم", "جن", "جو",
  "جه", "جی", "چا", "چپ", "چت", "چخ", "چر", "چس", "چش", "چغ",
  "چک", "چل", "چم", "چن", "چو", "چه", "چی", "حا", "حب", "حت",
  "حد", "حر", "حس", "حق", "حک", "حل", "حم", "حی", "خا", "خب",
  "خت", "خد", "خر", "خز", "خس", "خش", "خط", "خل", "خم", "خن",
  "خو", "خی", "دا", "دب", "دج", "دخ", "دد", "در"
];

// لیست ایموجی‌ها برای ترکیب با کلمات
const EMOJI_POOL = [
  "😀", "😃", "😄", "😁", "😆", "😅", "😂", "🤣", "🙂", "😉", "😊", "😇", "😍", "😘", "😗",
  "😙", "😚", "😋", "😛", "😜", "😝", "😎", "🤓", "🧐", "🤗", "🤔", "😐", "😑", "🙄", "😬",
  "😌", "😔", "😪", "😴", "🥳", "💛", "💚", "💙", "💜", "🧡", "🤍", "🖤", "💘", "💝", "💖",
  "💗", "💓", "💞", "💕", "💟", "❣", "💯", "✨", "🌟", "⭐", "⚡", "🔥", "💧", "🌈", "🌙",
  "🌍", "🌎", "🌏", "🌸", "🌼", "🌻", "🌺", "🌷", "🌹", "🥀", "🌿", "🍀", "🌱", "🌳", "🌲",
  "🌴", "🌵", "🍁", "🍂", "🍃", "🌊", "⛰", "🏔", "🏕", "🎈", "🎉", "🎊", "🎁", "🏆", "🎯",
  "🎵", "🎶", "📌", "📍", "🧭", "⏰", "📅", "📝", "📚", "📖", "✏", "🧠", "🔑", "🔒", "🔓",
  "🛡", "⚙", "🔧", "🔨", "🧰", "🔬", "💡", "🔦", "📷", "🎥", "📱", "💻", "🖥", "🛰", "🚀",
  "✈", "🚗", "🚲", "🚶", "🏃", "🧘", "🤝", "👏", "🙌", "🙏", "🌞", "☀", "☁", "🌧", "❄",
  "🌨", "⛅", "⛈", "🌦", "🌤",
];

// ساخت لیست نهایی توکن‌ها (۱۲۸ کلمه + ۱۲۸ ایموجی = ۲۵۶ حالت برای ۱ بایت)
const WORDS = SHORT_WORDS.slice(0, 128);
const EMOJIS = EMOJI_POOL.slice(0, 128);
const TOKENS = [...WORDS, ...EMOJIS];

// اگر لیست کمتر از ۲۵۶ تا بود، با مقادیر مصنوعی پر می‌شود تا برنامه کرش نکند
while(TOKENS.length < 256) TOKENS.push("R"+TOKENS.length);

// ایجاد Map برای جستجوی سریع (تبدیل کلمه به عدد)
const TOKEN_TO_INDEX = new Map(TOKENS.map((t, i) => [t, i]));

// ابزارهای تبدیل متن
const te = new TextEncoder();
const td = new TextDecoder();
// تابع میانبر برای گرفتن المنت‌ها از HTML
const $ = (id) => document.getElementById(id);

// ==========================================
// 2. توابع رابط کاربری (UI)
// ==========================================

// نمایش پیام‌های Toast (موفقیت/خطا)
function showToast(message, type = "info") {
  const container = $("toast-container");
  if(!container) return;
  
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  
  let icon = type === "success" ? "✔" : type === "error" ? "✖" : "ℹ️";
  toast.innerHTML = `<span>${icon}</span> <span>${message}</span>`;
  
  container.appendChild(toast);
  
  // حذف خودکار بعد از ۳ ثانیه
  setTimeout(() => {
    toast.style.animation = "fadeOut 0.3s forwards";
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

// توابع کمکی کوتاه برای پیام‌ها
const ok = (t) => showToast(t, "success");
const err = (t) => showToast(t, "error");
const info = (t) => showToast(t, "info");

// مدیریت تب‌ها (جابجایی بین "فایل" و "متن")
const tabs = document.querySelectorAll(".tab-btn");
const tabContents = document.querySelectorAll(".tab-content");
tabs.forEach(tab => {
  tab.addEventListener("click", () => {
    tabs.forEach(t => t.classList.remove("active"));
    tabContents.forEach(c => c.classList.remove("active"));
    
    tab.classList.add("active");
    $(tab.dataset.target).classList.add("active");
  });
});

// مدیریت Drag & Drop فایل
const dropZone = $("dropZone");
const fileInput = $("fileIn");
const fileNameDisplay = $("fileNameDisplay");

dropZone.addEventListener("click", () => fileInput.click());

// وقتی فایل انتخاب شد
fileInput.addEventListener("change", () => {
  if (fileInput.files.length) {
    fileNameDisplay.textContent = "انتخاب شد: " + fileInput.files[0].name;
    validateFile(fileInput.files[0]);
  }
});

// افکت‌های ظاهری هنگام کشیدن فایل
dropZone.addEventListener("dragover", (e) => { e.preventDefault(); dropZone.classList.add("drag-over"); });
dropZone.addEventListener("dragleave", () => { dropZone.classList.remove("drag-over"); });
dropZone.addEventListener("drop", (e) => {
  e.preventDefault(); dropZone.classList.remove("drag-over");
  if (e.dataTransfer.files.length) {
    fileInput.files = e.dataTransfer.files;
    fileNameDisplay.textContent = "انتخاب شد: " + e.dataTransfer.files[0].name;
    validateFile(fileInput.files[0]);
  }
});

// هشدار حجم فایل (چون پردازش تصویر در مرورگر سنگین است)
function validateFile(file) {
  if (file.size > 30 * 1024 * 1024) showToast("⚠️ فایل‌های بالای ۳۰ مگابایت ممکن است کند باشند.", "error");
}

// نوار پیشرفت (Progress Bar)
const progressContainer = $("progressContainer");
const progressBar = $("progressBar");
const progressText = $("progressText");

function updateProgress(percent) {
  progressContainer.style.display = "block";
  progressBar.style.width = percent + "%";
  progressText.textContent = percent + "%";
  // یک وقفه کوتاه می‌دهیم تا UI مرورگر فرصت آپدیت شدن داشته باشد
  return new Promise(resolve => setTimeout(resolve, 10));
}

function resetProgress() {
  setTimeout(() => { progressContainer.style.display = "none"; progressBar.style.width = "0%"; }, 2000);
}

// ==========================================
// 3. هسته اصلی تبدیل داده‌ها (Core Logic)
// ==========================================

// تبدیل بایت‌ها به رشته‌ای از کلمات فارسی (روش ۱: متن)
function bytesToTokens(bytes) {
  const len = bytes.length >>> 0;
  // اضافه کردن ۴ بایت اول برای ذخیره طول داده
  const data = new Uint8Array(4 + len);
  data[0] = (len >>> 24) & 255; data[1] = (len >>> 16) & 255;
  data[2] = (len >>> 8) & 255; data[3] = len & 255;
  data.set(bytes, 4);

  const out = [];
  for (const b of data) out.push(TOKENS[b]);
  return out.join(" ");
}

// تبدیل رشته کلمات فارسی به آرایه بایت
function tokensToBytes(text) {
  const tokens = text.trim().split(/\s+/).filter(Boolean);
  if (!tokens.length) throw new Error("ورودی خالی است");

  const out = new Uint8Array(tokens.length);
  for (let i = 0; i < tokens.length; i++) {
    const idx = TOKEN_TO_INDEX.get(tokens[i]);
    if (idx === undefined) throw new Error("توکن نامعتبر: " + tokens[i]);
    out[i] = idx;
  }
  
  // بررسی صحت طول داده
  if (out.length < 4) throw new Error("داده کافی نیست");
  const len = ((out[0] << 24) | (out[1] << 16) | (out[2] << 8) | out[3]) >>> 0;
  const payload = out.slice(4);
  if (payload.length < len) throw new Error("داده ناقص یا دستکاری شده");
  return payload.slice(0, len);
}

// تبدیل بایت‌ها به پیکسل‌های تصویر (روش ۴: استگانوگرافی)
async function bytesToImage(bytes, onProgress) {
  const len = bytes.length;
  const totalBytes = len + 4; // داده + ۴ بایت هدر
  
  // محاسبه ابعاد تصویر مورد نیاز
  const pixelsNeeded = Math.ceil(totalBytes / 3); // هر پیکسل ۳ بایت (RGB) جا می‌دهد
  const width = Math.ceil(Math.sqrt(pixelsNeeded));
  const height = Math.ceil(pixelsNeeded / width);
  
  const canvas = document.createElement('canvas');
  canvas.width = width; canvas.height = height;
  const ctx = canvas.getContext('2d');
  const imgData = ctx.createImageData(width, height);
  const d = imgData.data;
  
  // ۴ بایت اول طول فایل است
  const header = [(len >>> 24) & 255, (len >>> 16) & 255, (len >>> 8) & 255, len & 255];
  
  let byteIndex = 0;
  // پر کردن پیکسل‌ها
  for (let i = 0; i < pixelsNeeded; i++) {
    const pixelBase = i * 4; // موقعیت در آرایه پیکسل (R,G,B,A)
    for (let channel = 0; channel < 3; channel++) { // فقط R, G, B
        let val = 0;
        if (byteIndex < 4) val = header[byteIndex];
        else if (byteIndex < totalBytes) val = bytes[byteIndex - 4];
        
        d[pixelBase + channel] = val;
        byteIndex++;
    }
    d[pixelBase + 3] = 255; // Alpha همیشه ۲۵۵ (کاملاً مات)
  }
  
  ctx.putImageData(imgData, 0, 0);
  if(onProgress) await onProgress(95);
  
  // تبدیل Canvas به Blob (فایل تصویر)
  return new Promise(resolve => canvas.toBlob(resolve, 'image/png'));
}

// استخراج بایت‌ها از تصویر آپلود شده
async function imageToBytes(imageBlob, onProgress) {
    if(onProgress) await onProgress(15);
    
    // کشیدن تصویر روی Canvas برای خواندن پیکسل‌ها
    const img = await createImageBitmap(imageBlob);
    const canvas = document.createElement('canvas');
    canvas.width = img.width; canvas.height = img.height;
    const ctx = canvas.getContext('2d');
    ctx.drawImage(img, 0, 0);
    
    const d = ctx.getImageData(0, 0, img.width, img.height).data;
    if(onProgress) await onProgress(30);

    // خواندن ۴ بایت اول (طول فایل)
    let header = [];
    for(let i=0; i<4; i++) header.push(d[Math.floor(i/3)*4 + (i%3)]);
    
    const dataLen = ((header[0] << 24) | (header[1] << 16) | (header[2] << 8) | header[3]) >>> 0;
    
    // اعتبارسنجی
    if (dataLen > d.length) throw new Error("تصویر نامعتبر یا خراب است");

    const out = new Uint8Array(dataLen);
    let outIdx = 0;
    const totalBytes = dataLen + 4;
    
    // استخراج داده‌های اصلی
    for (let i = 4; i < totalBytes; i++) {
        out[outIdx++] = d[Math.floor(i/3)*4 + (i%3)];
    }
    return out;
}

// ==========================================
// 4. توابع رمزنگاری و فشرده‌سازی
// ==========================================

// فشرده‌سازی Gzip
async function gzipCompress(u8) {
  if (!("CompressionStream" in window)) return u8; // اگر مرورگر قدیمی بود
  const stream = new Blob([u8]).stream().pipeThrough(new CompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

// باز کردن Gzip
async function gzipDecompress(u8) {
  if (!("DecompressionStream" in window)) return u8;
  const stream = new Blob([u8]).stream().pipeThrough(new DecompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

// تولید بایت‌های تصادفی (برای Salt و IV)
function randBytes(n) { const u = new Uint8Array(n); crypto.getRandomValues(u); return u; }

// تولید کلید رمزنگاری از پسورد کاربر (PBKDF2)
async function deriveKey(pass, salt) {
  const base = await crypto.subtle.importKey("raw", te.encode(pass), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

// بسته‌بندی داده‌ها (فشرده‌سازی + رمزنگاری اختیاری)
async function packData(input, pass, onProgress) {
  if(onProgress) await onProgress(10);
  
  // ۱. فشرده‌سازی
  const gz = await gzipCompress(input);
  if(onProgress) await onProgress(40);
  
  // اگر فشرده‌سازی حجم را زیاد کرد (فایل کوچک)، از اصل فایل استفاده کن
  const useGzip = gz.length < input.length;
  const payload = useGzip ? gz : input;
  
  // فلگ‌ها: بیت ۱ برای رمزنگاری، بیت ۲ برای فشرده‌سازی
  const flags = (pass ? 1 : 0) | (useGzip ? 2 : 0);
  
  // اگر رمزنگاری نخواست
  if (!pass) {
    const out = new Uint8Array(2 + payload.length);
    out[0] = 1; // Version
    out[1] = flags; 
    out.set(payload, 2);
    return out;
  }
  
  // ۲. رمزنگاری (AES-GCM)
  const salt = randBytes(16); 
  const iv = randBytes(12);
  const key = await deriveKey(pass, salt);
  if(onProgress) await onProgress(60);
  
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, payload));
  
  // ترکیب همه بخش‌ها: Version + Flags + Salt + IV + CipherText
  const out = new Uint8Array(30 + cipher.length);
  out[0] = 1; out[1] = flags; out.set(salt, 2); out.set(iv, 18); out.set(cipher, 30);
  return out;
}

// بازگشایی داده‌ها
async function unpackData(bytes, pass, onProgress) {
  if(onProgress) await onProgress(40);
  if (bytes.length < 2 || bytes[0] !== 1) throw new Error("فرمت فایل نامعتبر یا قدیمی است");
  
  const flags = bytes[1];
  const encrypted = (flags & 1) === 1;
  const compressed = (flags & 2) === 2;
  
  let payload;
  if (!encrypted) {
    payload = bytes.slice(2);
  } else {
    // بازگشایی رمز
    if (!pass) throw new Error("این فایل رمز دارد. لطفاً کلید را وارد کنید.");
    if (bytes.length < 31) throw new Error("داده ناقص است");
    
    const salt = bytes.slice(2, 18); 
    const iv = bytes.slice(18, 30); 
    const cipher = bytes.slice(30);
    
    const key = await deriveKey(pass, salt);
    if(onProgress) await onProgress(60);
    
    try { 
        payload = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher)); 
    } catch { 
        throw new Error("کلید اشتباه است یا فایل دستکاری شده."); 
    }
  }
  
  // باز کردن فشرده‌سازی در صورت نیاز
  const raw = compressed ? await gzipDecompress(payload) : payload;
  if(onProgress) await onProgress(80);
  return raw;
}

// ==========================================
// 5. هندلرها (اتصال دکمه‌ها به توابع)
// ==========================================

// تابع دانلود فایل در مرورگر
function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  setTimeout(() => { document.body.removeChild(a); window.URL.revokeObjectURL(url); }, 0);
}

// --- دکمه‌های متن ---
async function encryptText() {
  const text = $("plain").value;
  if (!text.trim()) { info("ورودی خالی است"); return; }
  try {
      const bytes = await packData(te.encode(text), ($("pass").value || "").trim());
      const out = bytesToTokens(bytes);
      $("out").value = out;
      await navigator.clipboard.writeText(out);
      ok("متن رمز شد و کپی گردید!");
  } catch(e) { err(e.message); }
}

async function decryptText() {
  const coded = $("plain").value;
  if (!coded.trim()) { info("ورودی خالی است"); return; }
  try {
    const raw = await unpackData(tokensToBytes(coded), ($("pass").value || "").trim());
    $("out").value = td.decode(raw);
    ok("متن بازگشایی شد");
  } catch (e) { err(e.message); }
}

// --- دکمه‌های فایل ---
async function processFileEncrypt() {
  const fileInput = $("fileIn");
  if (!fileInput.files.length) { info("فایل انتخاب نشده"); return; }
  try {
    const file = fileInput.files[0];
    validateFile(file); await updateProgress(5);
    
    // خواندن فایل و تبدیل به بایت
    const bytes = new Uint8Array(await file.arrayBuffer());
    
    // رمزنگاری و فشرده‌سازی
    const packed = await packData(bytes, ($("pass").value || "").trim(), updateProgress);
    await updateProgress(80);
    
    // تبدیل بایت‌ها به تصویر (Steganography)
    const imgBlob = await bytesToImage(packed, updateProgress);
    await updateProgress(100);
    
    // دانلود با پسوند .E.png
    downloadBlob(imgBlob, file.name + ".E.png");
    ok(`تبدیل شد! (${(imgBlob.size/1024).toFixed(0)} KB)`);
    resetProgress();
  } catch (e) { err(e.message); resetProgress(); }
}

async function processFileDecrypt() {
  const fileInput = $("fileIn");
  if (!fileInput.files.length) { info("فایل انتخاب نشده"); return; }
  try {
    const file = fileInput.files[0]; await updateProgress(5);
    const pass = ($("pass").value || "").trim();
    let originalBytes;
    
    // اگر فایل عکس بود -> استخراج از تصویر
    // اگر فایل متنی بود -> استخراج از متن (برای پشتیبانی از نسخه‌های قدیمی)
    if (file.type.startsWith("image/") || file.name.endsWith(".png")) {
        const packed = await imageToBytes(file, updateProgress);
        originalBytes = await unpackData(packed, pass, updateProgress);
    } else {
        const text = await file.text(); await updateProgress(20);
        originalBytes = await unpackData(tokensToBytes(text), pass, updateProgress);
    }
    await updateProgress(100);

    // تمیز کردن نام فایل خروجی (حذف پسوندهای اضافه شده)
    let name = file.name
        .replace(".E.png", "")
        .replace(".encoded.png", "")
        .replace(".encoded.txt", "")
        .replace(".png", "");
        
    // اگر پسوند پاک شد، یک پسوند پیش‌فرض بگذار
    if (!name.includes(".")) name += ".bin";

    // دانلود با پیشوند D_
    downloadBlob(new Blob([originalBytes]), "D_" + name);
    ok("بازگشایی شد!");
    resetProgress();
  } catch (e) { err("خطا: " + e.message); resetProgress(); }
}

// --- رویدادهای کلیک (Event Listeners) ---
$("encBtn").addEventListener("click", encryptText);
$("decBtn").addEventListener("click", decryptText);
$("swapBtn").addEventListener("click", () => { [$("plain").value, $("out").value] = [$("out").value, $("plain").value]; });
$("copyBtn").addEventListener("click", () => { if($("out").value) navigator.clipboard.writeText($("out").value).then(()=>ok("کپی شد")); });
$("clearBtn").addEventListener("click", () => { $("plain").value=""; $("out").value=""; $("pass").value=""; $("fileIn").value=""; $("fileNameDisplay").textContent=""; info("پاک شد"); });

$("fileEncBtn").addEventListener("click", processFileEncrypt);
$("fileDecBtn").addEventListener("click", processFileDecrypt);

// ثبت Service Worker برای حالت آفلاین (PWA)
if ("serviceWorker" in navigator) window.addEventListener("load", () => navigator.serviceWorker.register("./sw.js").catch(console.error));

// مدیریت دکمه نصب برنامه
let deferredPrompt; const installBtn = $("installBtn");
window.addEventListener("beforeinstallprompt", (e) => { e.preventDefault(); deferredPrompt = e; installBtn.style.display = "block"; });
installBtn.addEventListener("click", async () => { if(!deferredPrompt)return; deferredPrompt.prompt(); deferredPrompt=null; installBtn.style.display="none"; });

// دکمه نمایش/مخفی کردن پسورد
const passInput = $("pass"); const toggleBtn = $("togglePass");
toggleBtn.addEventListener("click", (e) => { 
    e.preventDefault(); 
    const isP = passInput.type === "password"; 
    passInput.type = isP ? "text" : "password"; 
    toggleBtn.textContent = isP ? "🙈" : "👁️"; 
    toggleBtn.style.opacity = isP ? "1" : "0.5"; 
});