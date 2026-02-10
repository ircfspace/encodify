const CACHE_NAME = 'encodify-offline-v3'; // ورژن را تغییر دادیم تا کش قبلی پاک شود
const ASSETS_TO_CACHE = [
  './',
  './index.html',
  './script.js',
  './manifest.json',
  './assets/css/style.css',
  
  // فایل‌های جدید که باید حتما وجود داشته باشند:
  './assets/fonts/Vazirmatn.woff2',
  './assets/icons/icon-192.png',
  './assets/icons/icon-512.png'
];

// نصب و کش کردن
self.addEventListener('install', (event) => {
  self.skipWaiting(); // اجبار به نصب فوری سرویس ورکر جدید
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      console.log('Caching assets...');
      return cache.addAll(ASSETS_TO_CACHE);
    })
  );
});

// فعال‌سازی و پاک کردن کش‌های قدیمی
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cache) => {
          if (cache !== CACHE_NAME) {
            console.log('Deleting old cache:', cache);
            return caches.delete(cache);
          }
        })
      );
    })
  );
});

// استراتژی شبکه، سپس کش (یا برعکس بسته به نیاز)
// این روش: اول کش را چک میکند، اگر نبود از شبکه می‌گیرد
self.addEventListener('fetch', (event) => {
  event.respondWith(
    caches.match(event.request).then((response) => {
      return response || fetch(event.request);
    }).catch(() => {
        // اگر شبکه قطع بود و فایل در کش نبود، اینجا هندل می‌شود
        // فعلا نیازی نیست چون همه چیز کش شده
    })
  );
});