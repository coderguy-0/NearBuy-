'use strict';
/*
 * NearBuy Customer Portal API + shared seller/runner workflow.
 *
 *   /api/customer/*   customer session (browse is public, mutations need a session)
 *   /api/partner/*    seller and runner sessions on the same records
 *   /api/admin/*      role-protected platform administration
 *
 * Security model
 *   - scrypt password hashes, random session tokens stored hashed, HttpOnly cookie
 *   - every mutation needs X-NearBuy-Request: 1 (CSRF guard) and a same-origin check
 *   - signed-in mutations also need the per-session X-NearBuy-CSRF token
 *   - prices, stock, discounts and totals are always recalculated on the server
 *   - stock moves inside BEGIN IMMEDIATE transactions with conditional updates
 *   - delivery OTPs are derived with HMAC and never stored in plain text
 */
const { createHmac, randomBytes, randomUUID } = require('node:crypto');
const {
  db, now, uid, sha, makePassword, checkPassword, deriveCode, safeEqual,
  transaction, audit, pincodeArea, haversineKm
} = require('./db');
const seed = require('./seed');

const SESSION_COOKIE = 'nb_session';
const PARTNER_COOKIE = 'nb_partner_session';
const ADMIN_COOKIE = 'nb_admin_session';
const SESSION_HOURS = 24 * 7;
const DEMO = process.env.NODE_ENV !== 'production' || process.env.SEED_DEMO === '1';
const DEV_CODES = process.env.NODE_ENV !== 'production' || process.env.DEV_MAIL_PREVIEW === '1';
const GATEWAY = {
  provider: 'razorpay',
  keyId: process.env.RAZORPAY_KEY_ID || '',
  keySecret: process.env.RAZORPAY_KEY_SECRET || '',
  get configured() { return Boolean(this.keyId && this.keySecret); }
};

/* Seed once, at startup, without blocking the server if it fails. */
try { seed(); } catch (err) { console.error('[nearbuy] seed failed:', err.message); }

/* ------------------------------------------------------------------ */
/* HTTP helpers                                                        */
/* ------------------------------------------------------------------ */

class HttpError extends Error {
  constructor(status, message, extra) {
    super(message);
    this.status = status;
    this.extra = extra || null;
  }
}
const fail = (status, message, extra) => { throw new HttpError(status, message, extra); };

function send(res, status, payload, headers = {}) {
  const body = JSON.stringify(payload === undefined ? null : payload);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Content-Length': Buffer.byteLength(body),
    ...headers
  });
  res.end(body);
}

function sendHtml(res, status, html) {
  const body = Buffer.from(html, 'utf8');
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': "default-src 'self'; style-src 'unsafe-inline'; img-src 'self' data: https:; base-uri 'none'; form-action 'none'; frame-ancestors 'self'",
    'Content-Length': body.length
  });
  res.end(body);
}

function parseCookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function readBody(req, limit = 65536) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    let done = false;
    req.on('data', (chunk) => {
      if (done) return;
      total += chunk.length;
      if (total > limit) {
        done = true;
        req.resume();
        reject(new HttpError(413, 'Request body is too large'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (done) return;
      done = true;
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw) { resolve({}); return; }
      try {
        const parsed = JSON.parse(raw);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          reject(new HttpError(400, 'A JSON object is required'));
          return;
        }
        resolve(parsed);
      } catch {
        reject(new HttpError(400, 'Invalid JSON body'));
      }
    });
    req.on('error', (err) => { if (!done) { done = true; reject(err); } });
  });
}

const clientIp = (req) => String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').split(',')[0].trim();
const buckets = new Map();
function rateLimit(key, limit, windowMs) {
  const at = Date.now();
  let b = buckets.get(key);
  if (!b || b.reset < at) { b = { count: 0, reset: at + windowMs }; buckets.set(key, b); }
  b.count += 1;
  if (b.count > limit) fail(429, 'Too many attempts. Please wait a moment and try again.');
  if (buckets.size > 5000) {
    for (const [k, v] of buckets) if (v.reset < at) buckets.delete(k);
  }
}

const isHttps = (req) => req.headers['x-forwarded-proto'] === 'https' || Boolean(req.socket.encrypted);
const cookieAttrs = (req) => {
  const secure = isHttps(req) || process.env.COOKIE_SECURE === '1';
  return `Path=/; HttpOnly; SameSite=${secure ? 'None' : 'Lax'}${secure ? '; Secure; Partitioned' : ''}`;
};

function startSession(req, user, cookieName = SESSION_COOKIE, hours = SESSION_HOURS) {
  const token = randomBytes(32).toString('hex');
  const csrf = randomBytes(24).toString('hex');
  db.prepare('INSERT INTO nb_sessions(token_hash,user_id,role,csrf,created_at,expires_at,user_agent) VALUES(?,?,?,?,?,?,?)')
    .run(sha(token), user.id, user.role, csrf,
      now(), new Date(Date.now() + hours * 3600e3).toISOString(), String(req.headers['user-agent'] || '').slice(0, 200));
  return { cookie: `${cookieName}=${token}; ${cookieAttrs(req)}; Max-Age=${hours * 3600}`, csrf, token };
}

function sessionFor(req, cookieName = SESSION_COOKIE) {
  const token = parseCookies(req)[cookieName];
  if (!token || !/^[a-f0-9]{64}$/.test(token)) return null;
  const row = db.prepare(`SELECT s.user_id, s.role, s.csrf, s.expires_at, u.name, u.email, u.phone, u.avatar, u.status
    FROM nb_sessions s JOIN nb_users u ON u.id=s.user_id WHERE s.token_hash=?`).get(sha(token));
  if (!row) return null;
  if (new Date(row.expires_at).getTime() < Date.now()) {
    db.prepare('DELETE FROM nb_sessions WHERE token_hash=?').run(sha(token));
    return null;
  }
  if (row.status !== 'active') return null;
  return { ...row, token };
}

function requireUser(req, roles, cookieName = SESSION_COOKIE) {
  const s = sessionFor(req, cookieName);
  if (!s) fail(401, 'Please sign in to continue');
  if (roles && !roles.includes(s.role)) fail(403, 'You do not have access to this area');
  return s;
}

function requireCustomer(req) { return requireUser(req, ['customer']); }

function checkMutation(req, session) {
  if (req.headers['x-nearbuy-request'] !== '1') fail(403, 'Request verification header is missing');
  const origin = req.headers.origin;
  if (origin) {
    try {
      const host = new URL(origin).host;
      const expected = String(req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0].trim();
      if (expected && host !== expected) fail(403, 'Cross-origin request refused');
    } catch { fail(403, 'Invalid origin'); }
  }
  if (session && req.headers['x-nearbuy-csrf'] !== session.csrf) {
    fail(403, 'Your session security token is missing. Refresh the page and try again.');
  }
}

const str = (v, min, max) => typeof v === 'string' && v.trim().length >= min && v.trim().length <= max;
const emailOk = (v) => typeof v === 'string' && v.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v.trim());
const phoneOk = (v) => {
  const digits = String(v || '').replace(/[^\d]/g, '').replace(/^91(?=\d{10}$)/, '');
  return /^[6-9]\d{9}$/.test(digits);
};
const normalPhone = (v) => String(v || '').replace(/[^\d]/g, '').replace(/^91(?=\d{10}$)/, '');
const pincodeOk = (v) => /^[1-9]\d{5}$/.test(String(v || ''));
const clampInt = (v, min, max) => {
  const n = Number(v);
  if (!Number.isFinite(n)) return min;
  return Math.min(max, Math.max(min, Math.trunc(n)));
};
const round2 = (n) => Math.round(Number(n || 0) * 100) / 100;
const NB_SLUG = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');

/* ------------------------------------------------------------------ */
/* Serialisers                                                         */
/* ------------------------------------------------------------------ */

const STATUS_LABELS = {
  placed: 'Order placed',
  accepted: 'Seller accepted',
  preparing: 'Preparing order',
  ready: 'Ready for pickup',
  ready_dispatch: 'Ready for dispatch',
  runner_requested: 'Finding a delivery partner',
  runner_assigned: 'Delivery partner assigned',
  picked_up: 'Picked up',
  out_for_delivery: 'Out for delivery',
  arriving_soon: 'Arriving soon',
  delivered: 'Delivered',
  completed: 'Completed',
  rejected: 'Rejected by seller',
  cancelled: 'Cancelled',
  return_requested: 'Return requested',
  returned: 'Returned',
  payment_failed: 'Payment failed'
};

function shopRow(row) {
  if (!row) return null;
  let pins = [];
  try { pins = String(row.service_pincodes || '').split(',').map((s) => s.trim()).filter(Boolean); } catch { pins = []; }
  return { ...row, service_pincodes: pins };
}

function shopCard(row, location) {
  if (!row) return null;
  let distanceKm = null;
  if (location && Number.isFinite(Number(location.lat)) && Number.isFinite(Number(location.lng))) {
    distanceKm = haversineKm(Number(location.lat), Number(location.lng), row.lat, row.lng);
  }
  let serviceable = true;
  if (location && location.pincode) {
    const pins = String(row.service_pincodes || '').split(',').map((s) => s.trim()).filter(Boolean);
    serviceable = pins.includes(String(location.pincode)) && (distanceKm == null || distanceKm <= row.radius_km + 0.75);
  }
  const counts = db.prepare('SELECT COUNT(*) AS total, SUM(CASE WHEN stock-reserved>0 THEN 1 ELSE 0 END) AS in_stock FROM nb_products WHERE shop_id=? AND active=1').get(row.id);
  return {
    id: row.id, slug: row.slug, name: row.name, categorySlug: row.category_slug,
    category: db.prepare('SELECT name FROM nb_categories WHERE slug=?').get(row.category_slug)?.name || row.category_slug,
    tagline: row.tagline, description: row.description, emoji: row.emoji, tone: row.tone,
    rating: row.rating, reviewCount: row.review_count, verified: Boolean(row.verified), isOpen: Boolean(row.is_open),
    opensAt: row.opens_at, closesAt: row.closes_at, prepMinutes: row.prep_minutes,
    deliveryEnabled: Boolean(row.delivery_enabled), pickupEnabled: Boolean(row.pickup_enabled),
    deliveryFee: row.delivery_fee_paise, freeDeliveryOver: row.free_delivery_over_paise,
    pickupFee: row.pickup_fee_paise, minOrder: row.min_order_paise, radiusKm: row.radius_km,
    address: row.address, locality: row.locality, city: row.city, pincode: row.pincode,
    lat: row.lat, lng: row.lng, distanceKm, serviceable, servicePincodes: row.service_pincodes,
    badge: row.badge, productCount: Number(counts?.total || 0), inStockCount: Number(counts?.in_stock || 0)
  };
}

function productCard(row, opts = {}) {
  if (!row) return null;
  const shop = opts.shop || db.prepare('SELECT * FROM nb_shops WHERE id=?').get(row.shop_id);
  const available = Math.max(0, Number(row.stock) - Number(row.reserved || 0));
  const discount = row.mrp_paise && row.mrp_paise > row.price_paise
    ? Math.round(((row.mrp_paise - row.price_paise) / row.mrp_paise) * 100) : 0;
  return {
    id: row.id, name: row.name, brand: row.brand, categorySlug: row.category_slug,
    category: db.prepare('SELECT name FROM nb_categories WHERE slug=?').get(row.category_slug)?.name || row.category_slug,
    compareKey: row.compare_key, unit: row.unit, packSize: row.pack_size, emoji: row.emoji,
    imageUrl: row.image_url, price: row.price_paise, mrp: row.mrp_paise, discount,
    taxRate: row.tax_rate, stock: available, lowStock: available > 0 && available <= row.low_stock,
    available: available > 0, returnDays: row.return_days, rating: row.rating, reviewCount: row.review_count,
    shop: shop ? { id: shop.id, slug: shop.slug, name: shop.name, emoji: shop.emoji, tone: shop.tone, rating: shop.rating } : null,
    distanceKm: opts.location && shop ? haversineKm(Number(opts.location.lat), Number(opts.location.lng), shop.lat, shop.lng) : null,
    deliveryEnabled: shop ? Boolean(shop.delivery_enabled) : false,
    pickupEnabled: shop ? Boolean(shop.pickup_enabled) : false,
    isDemo: Boolean(row.is_demo)
  };
}

function userPayload(s) {
  if (!s) return null;
  const profile = db.prepare('SELECT * FROM nb_customer_profiles WHERE user_id=?').get(s.user_id);
  return {
    id: s.user_id, role: s.role, name: s.name, email: s.email, phone: s.phone, avatar: s.avatar || '👤',
    emailVerified: Boolean(db.prepare('SELECT email_verified FROM nb_users WHERE id=?').get(s.user_id)?.email_verified),
    phoneVerified: Boolean(db.prepare('SELECT phone_verified FROM nb_users WHERE id=?').get(s.user_id)?.phone_verified),
    marketingOptIn: profile ? Boolean(profile.marketing_opt_in) : true,
    orderUpdates: profile ? Boolean(profile.order_updates) : true,
    csrf: s.csrf
  };
}

function categoryList() {
  return db.prepare('SELECT * FROM nb_categories WHERE active=1 ORDER BY sort').all().map((c) => {
    const count = db.prepare('SELECT COUNT(*) AS n FROM nb_products WHERE category_slug=? AND active=1').get(c.slug);
    const shops = db.prepare('SELECT COUNT(DISTINCT shop_id) AS n FROM nb_products WHERE category_slug=? AND active=1').get(c.slug);
    return { slug: c.slug, name: c.name, icon: c.icon, tone: c.tone, productCount: Number(count?.n || 0), shopCount: Number(shops?.n || 0) };
  });
}

function locationFromQuery(q) {
  const pincode = q.get('pincode') || '';
  const lat = Number(q.get('lat'));
  const lng = Number(q.get('lng'));
  const hasCoords = Number.isFinite(lat) && Number.isFinite(lng) && lat !== 0 && lng !== 0;
  let locality = q.get('locality') || '';
  let city = q.get('city') || 'New Delhi';
  let resolvedPin = pincode;
  if (pincodeOk(pincode)) {
    const area = pincodeArea(pincode);
    if (area) {
      locality = locality || area.locality;
      city = area.city;
      if (!hasCoords) return { pincode, locality, city, lat: area.lat, lng: area.lng };
    }
  }
  if (!hasCoords && !pincode) return null;
  return {
    pincode: resolvedPin || '',
    locality, city,
    lat: hasCoords ? lat : null,
    lng: hasCoords ? lng : null
  };
}

function pincodeMatchesShop(shop, pincode) {
  if (!pincode) return true;
  return String(shop.service_pincodes || '').split(',').map((s) => s.trim()).includes(String(pincode));
}

/* ------------------------------------------------------------------ */
/* Catalogue queries                                                   */
/* ------------------------------------------------------------------ */

function queryShops({ location, category, q, sort = 'distance', open, delivery, pickup, verified, minRating, maxDistance, includeUnserviceable, limit = 12, page = 1 }) {
  const where = [];
  const params = [];
  if (category) { where.push('s.category_slug=?'); params.push(category); }
  if (q) {
    where.push('(LOWER(s.name) LIKE ? OR LOWER(s.tagline) LIKE ? OR LOWER(s.locality) LIKE ? OR LOWER(s.category_slug) LIKE ?)');
    const like = `%${String(q).toLowerCase()}%`;
    params.push(like, like, like, like);
  }
  if (open === '1') where.push('s.is_open=1');
  if (delivery === '1') where.push('s.delivery_enabled=1');
  if (pickup === '1') where.push('s.pickup_enabled=1');
  if (verified === '1') where.push('s.verified=1');
  if (minRating) { where.push('s.rating>=?'); params.push(Number(minRating)); }
  const sql = `SELECT s.* FROM nb_shops s ${where.length ? 'WHERE ' + where.join(' AND ') : ''}`;
  let rows = db.prepare(sql).all(...params).map(shopRow);
  let cards = rows.map((r) => shopCard(r, location));
  if (location) {
    if (!includeUnserviceable) cards = cards.filter((c) => c.serviceable);
    if (maxDistance) cards = cards.filter((c) => c.distanceKm == null || c.distanceKm <= Number(maxDistance));
  } else if (maxDistance) {
    cards = cards.filter(() => true);
  }
  if (sort === 'rating') cards.sort((a, b) => b.rating - a.rating || b.reviewCount - a.reviewCount);
  else if (sort === 'name') cards.sort((a, b) => a.name.localeCompare(b.name));
  else if (sort === 'prep') cards.sort((a, b) => a.prepMinutes - b.prepMinutes);
  else cards.sort((a, b) => (a.distanceKm == null ? 99 : a.distanceKm) - (b.distanceKm == null ? 99 : b.distanceKm) || b.rating - a.rating);
  const total = cards.length;
  const start = (Math.max(1, page) - 1) * limit;
  return { shops: cards.slice(start, start + limit), total, page, pages: Math.max(1, Math.ceil(total / limit)) };
}

function queryProducts({ location, q, category, shop, brand, minPrice, maxPrice, rating, available, delivery, pickup, sort = 'relevance', limit = 12, page = 1, compareKey }) {
  const where = ['p.active=1', 's.is_open IN (0,1)'];
  const params = [];
  if (compareKey) { where.push('p.compare_key=?'); params.push(compareKey); }
  if (category) { where.push('p.category_slug=?'); params.push(category); }
  if (shop) { where.push('s.slug=?'); params.push(shop); }
  if (brand) { where.push('LOWER(p.brand)=?'); params.push(String(brand).toLowerCase()); }
  if (q) {
    const like = `%${String(q).toLowerCase()}%`;
    where.push('(LOWER(p.name) LIKE ? OR LOWER(p.brand) LIKE ? OR LOWER(p.category_slug) LIKE ? OR LOWER(p.description) LIKE ? OR LOWER(s.name) LIKE ?)');
    params.push(like, like, like, like, like);
  }
  if (minPrice) { where.push('p.price_paise>=?'); params.push(Math.round(Number(minPrice) * 100)); }
  if (maxPrice) { where.push('p.price_paise<=?'); params.push(Math.round(Number(maxPrice) * 100)); }
  if (rating) { where.push('p.rating>=?'); params.push(Number(rating)); }
  if (available === '1') where.push('(p.stock-p.reserved)>0');
  if (delivery === '1') where.push('s.delivery_enabled=1');
  if (pickup === '1') where.push('s.pickup_enabled=1');
  const rows = db.prepare(`SELECT p.*, s.name AS shop_name, s.slug AS shop_slug, s.lat AS shop_lat, s.lng AS shop_lng,
      s.delivery_enabled, s.pickup_enabled, s.service_pincodes, s.radius_km, s.is_open, s.rating AS shop_rating
    FROM nb_products p JOIN nb_shops s ON s.id=p.shop_id
    WHERE ${where.join(' AND ')}`).all(...params);
  let items = rows.map((r) => productCard(r, { location }));
  if (location && location.pincode) {
    items = items.filter((i) => {
      const s = rows.find((r) => r.id === i.id);
      return pincodeMatchesShop(s, location.pincode);
    });
  }
  if (sort === 'price_low') items.sort((a, b) => a.price - b.price);
  else if (sort === 'price_high') items.sort((a, b) => b.price - a.price);
  else if (sort === 'rating') items.sort((a, b) => b.rating - a.rating || b.reviewCount - a.reviewCount);
  else if (sort === 'discount') items.sort((a, b) => b.discount - a.discount);
  else if (sort === 'distance') items.sort((a, b) => (a.distanceKm == null ? 99 : a.distanceKm) - (b.distanceKm == null ? 99 : b.distanceKm));
  else if (sort === 'nearest') items.sort((a, b) => (a.distanceKm == null ? 99 : a.distanceKm) - (b.distanceKm == null ? 99 : b.distanceKm));
  else items.sort((a, b) => (b.available - a.available) || b.rating - a.rating);
  const total = items.length;
  const start = (Math.max(1, page) - 1) * limit;
  return { products: items.slice(start, start + limit), total, page, pages: Math.max(1, Math.ceil(total / limit)) };
}

function activeOffers(location) {
  const at = now();
  const rows = db.prepare(`SELECT * FROM nb_coupons WHERE active=1 AND starts_at<=? AND ends_at>=? AND (usage_limit IS NULL OR used_count<usage_limit) ORDER BY ends_at ASC`).all(at, at);
  return rows.map((c) => {
    const shop = c.shop_id ? db.prepare('SELECT name, slug FROM nb_shops WHERE id=?').get(c.shop_id) : null;
    const redemptions = db.prepare('SELECT COUNT(*) AS n FROM nb_coupon_redemptions WHERE coupon_code=?').get(c.code);
    return {
      code: c.code, title: c.title, description: c.description, type: c.type, value: c.value,
      minOrder: c.min_order_paise, maxDiscount: c.max_discount_paise,
      shop: shop ? { name: shop.name, slug: shop.slug } : null,
      endsAt: c.ends_at, startsAt: c.starts_at, usedCount: Number(redemptions?.n || 0),
      usageLimit: c.usage_limit,
      savingsLabel: c.type === 'percent' ? `${c.value}% off${c.max_discount_paise ? ' up to ₹' + Math.round(c.max_discount_paise / 100) : ''}`
        : c.type === 'fixed' ? `₹${Math.round(c.value / 100)} off` : 'Free delivery',
      expiringSoon: new Date(c.ends_at).getTime() - Date.now() < 3 * 864e5
    };
  });
}

/* ------------------------------------------------------------------ */
/* Cart + pricing                                                      */
/* ------------------------------------------------------------------ */

function getCartRow(userId, create = false) {
  let row = db.prepare('SELECT * FROM nb_carts WHERE user_id=?').get(userId);
  if (!row && create) {
    db.prepare('INSERT INTO nb_carts(user_id,coupon_code,updated_at) VALUES(?,NULL,?)').run(userId, now());
    row = db.prepare('SELECT * FROM nb_carts WHERE user_id=?').get(userId);
  }
  return row;
}

function cartLines(userId) {
  return db.prepare(`SELECT ci.qty, p.*, s.name AS shop_name, s.slug AS shop_slug, s.emoji AS shop_emoji, s.tone AS shop_tone,
      s.is_open AS shop_open, s.delivery_enabled, s.pickup_enabled, s.delivery_fee_paise, s.free_delivery_over_paise,
      s.pickup_fee_paise, s.min_order_paise, s.prep_minutes, s.service_pincodes, s.radius_km, s.lat AS shop_lat, s.lng AS shop_lng
    FROM nb_cart_items ci JOIN nb_products p ON p.id=ci.product_id JOIN nb_shops s ON s.id=p.shop_id
    WHERE ci.user_id=? ORDER BY s.name, ci.created_at`).all(userId);
}

function couponUsable(coupon, userId, cartRows, subtotal) {
  if (!coupon || !coupon.active) return { ok: false, message: 'This coupon is not valid.' };
  const at = Date.now();
  if (new Date(coupon.starts_at).getTime() > at) return { ok: false, message: 'This offer has not started yet.' };
  if (new Date(coupon.ends_at).getTime() < at) return { ok: false, message: 'This coupon has expired.' };
  if (coupon.usage_limit != null && coupon.used_count >= coupon.usage_limit) return { ok: false, message: 'This coupon has reached its usage limit.' };
  const mine = db.prepare('SELECT COUNT(*) AS n FROM nb_coupon_redemptions WHERE coupon_code=? AND user_id=?').get(coupon.code, userId);
  if (coupon.per_customer_limit && Number(mine?.n || 0) >= coupon.per_customer_limit) return { ok: false, message: 'You have already used this coupon.' };
  if (coupon.shop_id) {
    const has = cartRows.some((r) => r.shop_id === coupon.shop_id);
    if (!has) return { ok: false, message: 'This coupon only applies to items from a specific shop.' };
    const shopSub = cartRows.filter((r) => r.shop_id === coupon.shop_id).reduce((t, r) => t + r.price_paise * r.qty, 0);
    if (shopSub < coupon.min_order_paise) return { ok: false, message: `Add ₹${Math.ceil((coupon.min_order_paise - shopSub) / 100)} more from this shop to use ${coupon.code}.` };
  } else if (subtotal < coupon.min_order_paise) {
    return { ok: false, message: `Add ₹${Math.ceil((coupon.min_order_paise - subtotal) / 100)} more to use ${coupon.code}.` };
  }
  return { ok: true };
}

function priceCart(userId, opts = {}) {
  const rows = cartLines(userId);
  const cart = getCartRow(userId);
  const couponCode = opts.couponCode !== undefined ? opts.couponCode : cart?.coupon_code;
  const location = opts.location || null;
  const fulfillmentMap = opts.fulfillment || {};
  const coupon = couponCode ? db.prepare('SELECT * FROM nb_coupons WHERE code=?').get(couponCode) : null;
  const subtotal = rows.reduce((t, r) => t + r.price_paise * r.qty, 0);
  const couponCheck = coupon ? couponUsable(coupon, userId, rows, subtotal) : null;
  const usableCoupon = couponCheck?.ok ? coupon : null;

  const byShop = new Map();
  for (const r of rows) {
    if (!byShop.has(r.shop_id)) byShop.set(r.shop_id, []);
    byShop.get(r.shop_id).push(r);
  }

  const shopCoupon = usableCoupon?.shop_id || null;
  const platformDiscountTotal = usableCoupon && !shopCoupon && usableCoupon.type !== 'free_delivery'
    ? Math.min(usableCoupon.type === 'percent' ? Math.floor((subtotal * usableCoupon.value) / 100) : usableCoupon.value,
      usableCoupon.max_discount_paise || Infinity, subtotal)
    : 0;

  const groups = [];
  for (const [shopId, lines] of byShop) {
    const first = lines[0];
    const shopSubtotal = lines.reduce((t, r) => t + r.price_paise * r.qty, 0);
    const fulfillment = fulfillmentMap[shopId] === 'pickup' ? 'pickup' : 'delivery';
    let discount = 0;
    if (usableCoupon && shopCoupon === shopId && usableCoupon.type !== 'free_delivery') {
      discount = Math.min(usableCoupon.type === 'percent' ? Math.floor((shopSubtotal * usableCoupon.value) / 100) : usableCoupon.value,
        usableCoupon.max_discount_paise || Infinity, shopSubtotal);
    } else if (platformDiscountTotal > 0) {
      discount = subtotal > 0 ? Math.round((platformDiscountTotal * shopSubtotal) / subtotal) : 0;
    }
    const freeDelivery = usableCoupon?.type === 'free_delivery';
    let deliveryFee = 0;
    if (fulfillment === 'delivery') {
      deliveryFee = first.delivery_fee_paise;
      if (first.free_delivery_over_paise != null && shopSubtotal - discount >= first.free_delivery_over_paise) deliveryFee = 0;
      if (freeDelivery) deliveryFee = 0;
    } else {
      deliveryFee = first.pickup_fee_paise;
    }
    let tax = 0;
    for (const r of lines) {
      const line = r.price_paise * r.qty;
      const share = shopSubtotal > 0 ? line / shopSubtotal : 0;
      const taxable = Math.max(0, line - discount * share);
      tax += Math.round((taxable * r.tax_rate) / 100);
    }
    const available = lines.map((r) => Math.max(0, r.stock - r.reserved) >= r.qty).every(Boolean);
    const minOrderMet = shopSubtotal >= first.min_order_paise;
    groups.push({
      shop: {
        id: shopId, name: first.shop_name, slug: first.shop_slug, emoji: first.shop_emoji, tone: first.shop_tone,
        isOpen: Boolean(first.shop_open), deliveryEnabled: Boolean(first.delivery_enabled), pickupEnabled: Boolean(first.pickup_enabled),
        deliveryFee: first.delivery_fee_paise, freeDeliveryOver: first.free_delivery_over_paise,
        pickupFee: first.pickup_fee_paise, minOrder: first.min_order_paise, prepMinutes: first.prep_minutes
      },
      fulfillment,
      fulfillmentOptions: [
        ...(first.delivery_enabled ? ['delivery'] : []),
        ...(first.pickup_enabled ? ['pickup'] : [])
      ],
      subtotal: shopSubtotal, discount, deliveryFee, tax,
      total: Math.max(0, shopSubtotal - discount + deliveryFee + tax),
      minOrderMet, minOrder: first.min_order_paise,
      available,
      etaMinutes: first.prep_minutes + (fulfillment === 'delivery' ? 18 : 0),
      items: lines.map((r) => ({
        productId: r.id, name: r.name, brand: r.brand, emoji: r.emoji, imageUrl: r.image_url,
        unit: r.unit, price: r.price_paise, mrp: r.mrp_paise, qty: r.qty, moveToWishlist: false,
        stock: Math.max(0, r.stock - r.reserved), available: Math.max(0, r.stock - r.reserved) >= r.qty,
        lineTotal: r.price_paise * r.qty, taxRate: r.tax_rate, categorySlug: r.category_slug
      }))
    });
  }

  const discountTotal = groups.reduce((t, g) => t + g.discount, 0);
  const deliveryTotal = groups.reduce((t, g) => t + g.deliveryFee, 0);
  const taxTotal = groups.reduce((t, g) => t + g.tax, 0);
  const total = groups.reduce((t, g) => t + g.total, 0);
  const itemCount = rows.reduce((t, r) => t + r.qty, 0);
  const issues = [];
  for (const g of groups) {
    if (!g.fulfillmentOptions.includes(g.fulfillment)) issues.push(`${g.shop.name} does not offer ${g.fulfillment}.`);
    if (!g.minOrderMet) issues.push(`${g.shop.name} has a minimum order of ₹${Math.round(g.minOrder / 100)}. Add ₹${Math.ceil((g.minOrder - g.subtotal) / 100)} more.`);
    if (!g.available) issues.push(`Some items from ${g.shop.name} are no longer available in the quantity requested.`);
  }
  if (coupon && !usableCoupon) issues.push(couponCheck.message);

  return {
    items: rows.length, itemCount, subtotal, discount: discountTotal, deliveryFee: deliveryTotal,
    tax: taxTotal, total, groups, issues,
    coupon: usableCoupon ? {
      code: usableCoupon.code, title: usableCoupon.title, type: usableCoupon.type,
      value: usableCoupon.value, shopId: usableCoupon.shop_id,
      description: usableCoupon.description, endsAt: usableCoupon.ends_at
    } : null,
    rejectedCoupon: coupon && !usableCoupon ? { code: coupon.code, message: couponCheck.message } : null,
    freeDelivery: usableCoupon?.type === 'free_delivery'
  };
}

/* ------------------------------------------------------------------ */
/* Notifications, events, OTP                                          */
/* ------------------------------------------------------------------ */

function notify(userId, title, body, type = 'order', link = '#/orders') {
  if (!userId) return;
  db.prepare('INSERT INTO nb_notifications(user_id,title,body,type,link,is_read,created_at) VALUES(?,?,?,?,?,0,?)')
    .run(userId, title, body, type, link, now());
}

function addEvent(orderId, sellerOrderId, status, label, detail, actor = 'system') {
  db.prepare('INSERT INTO nb_order_events(order_id,seller_order_id,status,label,detail,actor,created_at) VALUES(?,?,?,?,?,?,?)')
    .run(orderId, sellerOrderId, status, label, detail || null, actor, now());
  db.prepare('UPDATE nb_orders SET updated_at=? WHERE id=?').run(now(), orderId);
}

function orderEvents(orderId) {
  return db.prepare('SELECT * FROM nb_order_events WHERE order_id=? ORDER BY id ASC').all(orderId).map((e) => ({
    status: e.status, label: e.label, detail: e.detail, actor: e.actor, at: e.created_at, sellerOrderId: e.seller_order_id
  }));
}



/* ------------------------------------------------------------------ */
/* Orders                                                              */
/* ------------------------------------------------------------------ */

const PARENT_ORDER = {
  placed: 'Order placed', accepted: 'Seller accepted', preparing: 'Preparing order',
  ready: 'Ready', runner_requested: 'Finding a delivery partner', runner_assigned: 'Delivery partner assigned',
  picked_up: 'Picked up', out_for_delivery: 'Out for delivery', delivered: 'Delivered',
  completed: 'Completed', delivered: 'Delivered', in_progress: 'Partially delivered',
  cancelled: 'Cancelled', partially_cancelled: 'Partially cancelled'
};

function deriveStatus(sellerOrders) {
  if (!sellerOrders.length) return 'placed';
  const active = sellerOrders.filter((o) => !['cancelled', 'rejected'].includes(o.status));
  if (!active.length) return 'cancelled';
  const dead = sellerOrders.filter((o) => ['cancelled', 'rejected'].includes(o.status));
  if (active.every((o) => ['completed', 'delivered'].includes(o.status))) {
    return active.every((o) => o.status === 'completed') ? 'completed' : 'delivered';
  }
  if (active.some((o) => ['delivered', 'completed'].includes(o.status))) return 'in_progress';
  if (active.some((o) => ['out_for_delivery', 'picked_up', 'arriving_soon'].includes(o.status))) return 'out_for_delivery';
  if (active.some((o) => o.status === 'runner_assigned')) return 'runner_assigned';
  if (active.some((o) => o.status === 'runner_requested')) return 'runner_requested';
  if (active.some((o) => o.status === 'ready')) return 'ready';
  if (active.some((o) => o.status === 'preparing')) return 'preparing';
  if (active.some((o) => o.status === 'accepted')) return dead.length ? 'partially_cancelled' : 'accepted';
  return dead.length ? 'partially_cancelled' : 'placed';
}

function maskedPhone(phone) {
  if (!phone) return null;
  const digits = String(phone).replace(/[^\d]/g, '');
  return digits.length >= 10 ? `••••••${digits.slice(-4)}` : null;
}

function fulfillmentLabel(sellerOrder) {
  return sellerOrder.fulfillment === 'pickup' ? 'Store pickup' : 'Home delivery';
}

function sellerOrderDetail(so, opts = {}) {
  const order = db.prepare('SELECT * FROM nb_orders WHERE id=?').get(so.order_id);
  const shop = db.prepare('SELECT * FROM nb_shops WHERE id=?').get(so.shop_id);
  const items = db.prepare('SELECT * FROM nb_order_items WHERE seller_order_id=? ORDER BY id').all(so.id).map((i) => ({
    id: i.id, productId: i.product_id, name: i.name, brand: i.brand, unit: i.unit, qty: i.qty,
    price: i.price_paise, mrp: i.mrp_paise, lineTotal: i.line_total_paise, emoji: i.emoji,
    imageUrl: i.image_url, taxRate: i.tax_rate, compareKey: i.compare_key
  }));
  const events = db.prepare(`SELECT * FROM nb_order_events WHERE (seller_order_id=? OR (order_id=? AND seller_order_id IS NULL)) ORDER BY id`).all(so.id, order.id)
    .map((e) => ({ status: e.status, label: e.label, detail: e.detail, at: e.created_at, actor: e.actor }));
  const runner = so.runner_id ? db.prepare(`SELECT u.name, u.phone, u.avatar, r.vehicle, r.rating, r.lat, r.lng
    FROM nb_users u LEFT JOIN nb_runners r ON r.user_id=u.id WHERE u.id=?`).get(so.runner_id) : null;
  const lastTracking = db.prepare('SELECT * FROM nb_delivery_tracking WHERE seller_order_id=? ORDER BY id DESC LIMIT 1').get(so.id);
  const canCancel = ['placed', 'accepted'].includes(so.status);
  const deliveredAt = so.delivered_at || so.completed_at;
  const alreadyReturned = new Set(db.prepare("SELECT item_id FROM nb_returns WHERE seller_order_id=? AND status NOT IN ('rejected','cancelled')").all(so.id).map((r) => r.item_id));
  const returnableItems = items.filter((i) => {
    if (alreadyReturned.has(i.id)) return false;
    const product = db.prepare('SELECT return_days FROM nb_products WHERE id=?').get(i.productId);
    const days = product ? product.return_days : 0;
    if (!days || !deliveredAt) return false;
    return Date.now() - new Date(deliveredAt).getTime() <= days * 864e5;
  });
  const canReturn = returnableItems.length > 0;
  let deliveryOtp = null;
  let pickupCode = null;
  if (opts.includeCodes) {
    if (so.fulfillment === 'delivery' && ['runner_assigned', 'picked_up', 'out_for_delivery', 'arriving_soon'].includes(so.status)) {
      deliveryOtp = deriveCode('delivery', so.id, 6);
    }
    if (so.fulfillment === 'pickup' && ['ready', 'ready_dispatch'].includes(so.status)) {
      pickupCode = deriveCode('pickup', so.id, 6);
    }
  }
  return {
    id: so.id, code: so.code, parentCode: order.code, shop: shopCard(shop, null),
    status: so.status,
    statusLabel: so.status === 'ready' ? (so.fulfillment === 'delivery' ? 'Ready for dispatch' : 'Ready for pickup') : STATUS_LABELS[so.status] || so.status,
    fulfillment: so.fulfillment, fulfillmentLabel: fulfillmentLabel(so),
    subtotal: so.subtotal_paise, discount: so.discount_paise, deliveryFee: so.delivery_fee_paise,
    tax: so.tax_paise, total: so.total_paise, prepMinutes: so.prep_minutes,
    readyAt: so.ready_at, acceptedAt: so.accepted_at, rejectedReason: so.rejected_reason,
    cancelledAt: so.cancelled_at, deliveredAt, createdAt: so.created_at, updatedAt: so.updated_at,
    items, events, canCancel, canReturn, returnableItemIds: returnableItems.map((i) => i.id),
    runner: runner ? {
      name: runner.name, avatar: runner.avatar || '🛵', phoneMasked: maskedPhone(runner.phone),
      vehicle: runner.vehicle, rating: runner.rating,
      lastLocation: lastTracking && lastTracking.lat != null ? { lat: lastTracking.lat, lng: lastTracking.lng, at: lastTracking.created_at } : null
    } : null,
    deliveryOtp, pickupCode,
    estimatedOver: so.fulfillment === 'delivery' ? 18 : 0
  };
}

function orderSummary(order, opts = {}) {
  const sellerOrders = db.prepare('SELECT * FROM nb_seller_orders WHERE order_id=? ORDER BY created_at').all(order.id);
  const status = deriveStatus(sellerOrders);
  const shops = sellerOrders.map((so) => {
    const shop = db.prepare('SELECT * FROM nb_shops WHERE id=?').get(so.shop_id);
    return {
      id: so.id, code: so.code, shop: shop ? { id: shop.id, slug: shop.slug, name: shop.name, emoji: shop.emoji } : null,
      status: so.status, statusLabel: STATUS_LABELS[so.status] || so.status, fulfillment: so.fulfillment,
      total: so.total_paise, items: db.prepare('SELECT * FROM nb_order_items WHERE seller_order_id=?').all(so.id).map((i) => ({
        name: i.name, qty: i.qty, emoji: i.emoji, imageUrl: i.image_url, price: i.price_paise
      }))
    };
  });
  const itemCount = db.prepare('SELECT SUM(qty) AS n FROM nb_order_items WHERE order_id=?').get(order.id);
  return {
    id: order.id, code: order.code, status, statusLabel: PARENT_ORDER[status] || status,
    createdAt: order.created_at, updatedAt: order.updated_at,
    paymentMethod: order.payment_method, paymentStatus: order.payment_status,
    subtotal: order.subtotal_paise, discount: order.discount_paise, deliveryFee: order.delivery_fee_paise,
    tax: order.tax_paise, total: order.total_paise, couponCode: order.coupon_code,
    isDemo: Boolean(order.is_demo), itemCount: Number(itemCount?.n || 0), shops,
    canCancelAny: sellerOrders.some((s) => ['placed', 'accepted'].includes(s.status)),
    canReturnAny: sellerOrders.some((s) => ['delivered', 'completed'].includes(s.status)),
    hasReviewPrompt: sellerOrders.some((s) => ['delivered', 'completed'].includes(s.status))
  };
}

function orderDetail(order, opts = {}) {
  const summary = orderSummary(order);
  const address = JSON.parse(order.address_json);
  const sellerOrders = db.prepare('SELECT * FROM nb_seller_orders WHERE order_id=? ORDER BY created_at').all(order.id);
  const payments = db.prepare('SELECT * FROM nb_payment_records WHERE order_id=? ORDER BY created_at').all(order.id).map((p) => ({
    provider: p.provider, method: p.method, amount: p.amount_paise, status: p.status, reference: p.reference, at: p.created_at
  }));
  return {
    ...summary, address, note: order.note, events: orderEvents(order.id),
    sellerOrders: sellerOrders.map((so) => sellerOrderDetail(so, opts)),
    payments,
    receiptUrl: `/api/customer/orders/${encodeURIComponent(order.code)}/receipt`
  };
}

function orderByCode(code, userId) {
  const order = db.prepare('SELECT * FROM nb_orders WHERE code=?').get(code);
  if (!order) fail(404, 'Order not found');
  if (userId && order.customer_id !== userId) fail(403, 'This order belongs to another account');
  return order;
}

function addressDetail(row) {
  if (!row) return null;
  return {
    id: row.id, label: row.label, receiver: row.receiver, phone: row.phone, line1: row.line1, line2: row.line2,
    locality: row.locality, city: row.city, pincode: row.pincode, landmark: row.landmark,
    instructions: row.instructions, lat: row.lat, lng: row.lng, isDefault: Boolean(row.is_default)
  };
}

function addressList(userId) {
  return db.prepare('SELECT * FROM nb_addresses WHERE user_id=? ORDER BY is_default DESC, created_at DESC').all(userId).map(addressDetail);
}

function selectAddress(userId, addressId) {
  const address = db.prepare('SELECT * FROM nb_addresses WHERE id=? AND user_id=?').get(String(addressId || ''), userId);
  if (!address) fail(400, 'Choose a delivery address saved to your account');
  return address;
}

function quoteFor(userId, payload) {
  const address = selectAddress(userId, payload.addressId);
  const fulfillment = payload.fulfillment && typeof payload.fulfillment === 'object' ? payload.fulfillment : {};
  const priced = priceCart(userId, { fulfillment, couponCode: payload.couponCode, location: { pincode: address.pincode, lat: address.lat, lng: address.lng } });
  if (!priced.groups.length) fail(409, 'Your cart is empty');
  const serviceIssues = [];
  for (const g of priced.groups) {
    const shop = db.prepare('SELECT * FROM nb_shops WHERE id=?').get(g.shop.id);
    if (!shop.is_open) serviceIssues.push(`${shop.name} is currently closed.`);
    if (g.fulfillment === 'delivery') {
      const distance = haversineKm(address.lat, address.lng, shop.lat, shop.lng);
      const pins = String(shop.service_pincodes || '').split(',').map((s) => s.trim());
      const inArea = pins.includes(address.pincode);
      const inRadius = distance == null || distance <= shop.radius_km + 0.75;
      if (!inArea || !inRadius) {
        serviceIssues.push(`${shop.name} does not deliver to ${address.pincode}${distance != null ? ` (${distance} km away)` : ''}. Choose store pickup or another shop.`);
      }
    }
  }
  const paymentOptions = [
    { id: 'cod', label: 'Cash on delivery', enabled: true, note: 'Pay the seller or runner in cash when your order arrives.' },
    { id: 'pay_at_store', label: 'Pay at store', enabled: priced.groups.every((g) => g.fulfillment === 'pickup'), note: priced.groups.every((g) => g.fulfillment === 'pickup') ? 'Pay at the counter when you collect.' : 'Only available when every shop in this order is set to store pickup.' },
    { id: 'online', label: 'UPI, cards, net banking & wallets', enabled: GATEWAY.configured, note: GATEWAY.configured ? 'Secured by Razorpay. Payment is confirmed by the gateway webhook.' : 'Online payment is not configured for this deployment. Add RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET on the server to enable it.' }
  ];
  return {
    address: addressDetail(address), groups: priced.groups, subtotal: priced.subtotal, discount: priced.discount,
    deliveryFee: priced.deliveryFee, tax: priced.tax, total: priced.total, coupon: priced.coupon,
    rejectedCoupon: priced.rejectedCoupon, issues: [...priced.issues, ...serviceIssues],
    serviceIssues, paymentOptions, itemCount: priced.itemCount
  };
}

function newOrderCode() {
  const d = new Date();
  const stamp = `${String(d.getFullYear()).slice(2)}${String(d.getMonth() + 1).padStart(2, '0')}${String(d.getDate()).padStart(2, '0')}`;
  for (let i = 0; i < 8; i++) {
    const code = `NB-${stamp}-${String(Math.floor(Math.random() * 9000) + 1000)}`;
    if (!db.prepare('SELECT 1 FROM nb_orders WHERE code=?').get(code)) return code;
  }
  return `NB-${stamp}-${Date.now().toString().slice(-4)}`;
}
function newSellerCode() {
  for (let i = 0; i < 8; i++) {
    const code = `ORD-${String(Math.floor(Math.random() * 900000) + 100000)}`;
    if (!db.prepare('SELECT 1 FROM nb_seller_orders WHERE code=?').get(code)) return code;
  }
  return `ORD-${Date.now().toString().slice(-6)}`;
}

function releaseStockForSellerOrder(so) {
  const items = db.prepare('SELECT product_id, qty FROM nb_order_items WHERE seller_order_id=?').all(so.id);
  for (const item of items) {
    if (['accepted', 'preparing', 'ready', 'runner_requested', 'runner_assigned', 'picked_up', 'out_for_delivery'].includes(so.status)) {
      db.prepare('UPDATE nb_products SET stock=stock+? WHERE id=?').run(item.qty, item.product_id);
    } else {
      db.prepare('UPDATE nb_products SET reserved=MAX(0,reserved-?) WHERE id=?').run(item.qty, item.product_id);
    }
  }
}

function cancelSellerOrder(so, reason, actor = 'customer') {
  const order = db.prepare('SELECT * FROM nb_orders WHERE id=?').get(so.order_id);
  releaseStockForSellerOrder(so);
  db.prepare('UPDATE nb_seller_orders SET status=?,cancelled_at=?,updated_at=? WHERE id=?').run('cancelled', now(), now(), so.id);
  db.prepare('UPDATE nb_orders SET updated_at=? WHERE id=?').run(now(), so.order_id);
  addEvent(so.order_id, so.id, 'cancelled', 'Order cancelled', `${reason || 'Cancelled'}${actor === 'customer' ? ' (requested by customer)' : ''}`, actor);
  const shop = db.prepare('SELECT name FROM nb_shops WHERE id=?').get(so.shop_id);
  notify(order.customer_id, `Your ${shop.name} order was cancelled`, `${so.code}: ${reason || 'Cancelled'}`, 'order', `#/orders/${order.code}`);
  if (order.payment_status === 'paid') {
    db.prepare('INSERT INTO nb_refunds(id,return_id,order_id,amount_paise,status,reference,created_at,updated_at) VALUES(?,NULL,?,?,?,NULL,?,?)')
      .run(uid(), order.id, so.total_paise, 'processing', now(), now());
    notify(order.customer_id, 'Refund initiated', `₹${Math.round(so.total_paise / 100)} for ${so.code} is being returned to the original payment method.`, 'refund', '#/orders');
  }
  const siblings = db.prepare('SELECT * FROM nb_seller_orders WHERE order_id=?').all(order.id);
  if (siblings.every((s) => ['cancelled', 'rejected'].includes(s.status))) {
    db.prepare('UPDATE nb_orders SET status=?,updated_at=? WHERE id=?').run('cancelled', now(), order.id);
  }
}

/* ------------------------------------------------------------------ */
/* Printable receipt                                                   */
/* ------------------------------------------------------------------ */

const esc = (v) => String(v == null ? '' : v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const inr = (paise) => '₹' + (Number(paise || 0) / 100).toLocaleString('en-IN', { maximumFractionDigits: 2 });

function receiptHtml(order, sellerOrder, shop, customer, audience = 'customer') {
  const items = db.prepare('SELECT * FROM nb_order_items WHERE seller_order_id=?').all(sellerOrder.id);
  const address = JSON.parse(order.address_json);
  const rows = items.map((i) => `<tr><td>${esc(i.name)}<br><span class="muted">${esc(i.unit || '')}</span></td><td class="r">${i.qty}</td><td class="r">${inr(i.price_paise)}</td><td class="r">${inr(i.line_total_paise)}</td></tr>`).join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Receipt ${esc(sellerOrder.code)} · NearBuy</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 28px; background: #eff7ff; color: #142d4b; font: 14px/1.55 ui-sans-serif, system-ui, -apple-system, 'Segoe UI', sans-serif; }
  .sheet { max-width: 760px; margin: 0 auto; background: #fff; border: 1px solid #dce8f5; border-radius: 18px; padding: 30px 32px; box-shadow: 0 18px 48px rgba(6,59,120,.10); }
  .top { display: flex; justify-content: space-between; gap: 20px; border-bottom: 2px solid #0866d9; padding-bottom: 16px; }
  .brand { font-weight: 800; font-size: 24px; color: #063b78; letter-spacing: -.02em; }
  .brand span { color: #0866d9; }
  .muted { color: #6b7f98; font-size: 12px; }
  h1 { font-size: 17px; margin: 22px 0 4px; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; margin: 18px 0; }
  .card { background: #f7fbff; border: 1px solid #e2eefb; border-radius: 12px; padding: 12px 14px; }
  .card b { display: block; font-size: 11px; letter-spacing: .09em; text-transform: uppercase; color: #5a7694; margin-bottom: 4px; }
  table { width: 100%; border-collapse: collapse; margin: 10px 0 4px; }
  th { text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: #5a7694; border-bottom: 1px solid #dce8f5; padding: 8px 6px; }
  td { padding: 9px 6px; border-bottom: 1px solid #eef5fc; vertical-align: top; }
  .r { text-align: right; }
  .totals { margin-left: auto; width: 300px; margin-top: 12px; }
  .totals div { display: flex; justify-content: space-between; padding: 5px 0; }
  .totals .grand { border-top: 2px solid #0866d9; margin-top: 6px; padding-top: 10px; font-weight: 800; font-size: 17px; color: #063b78; }
  .pill { display: inline-block; padding: 3px 9px; border-radius: 999px; background: #e7f2ff; color: #0866d9; font-size: 11px; font-weight: 700; }
  .demo { background: #fff8e6; border: 1px solid #f5d58b; color: #8a5b00; border-radius: 10px; padding: 8px 12px; font-size: 12px; margin-top: 16px; }
  .actions { max-width: 760px; margin: 16px auto 0; display: flex; gap: 10px; justify-content: flex-end; }
  .actions button, .actions a { border: 0; border-radius: 10px; padding: 10px 18px; background: #0866d9; color: #fff; font: 600 13px system-ui; cursor: pointer; text-decoration: none; }
  .actions a { background: #e7f2ff; color: #063b78; }
  @media print { body { background: #fff; padding: 0; } .sheet { border: 0; box-shadow: none; border-radius: 0; } .actions { display: none; } }
</style></head><body>
<div class="actions"><a href="javascript:history.back()">Back</a><button onclick="window.print()">Print / save as PDF</button></div>
<div class="sheet">
  <div class="top">
    <div><div class="brand">Near<span>Buy</span></div><div class="muted">Shop Local. Live Better.</div></div>
    <div style="text-align:right"><span class="pill">${esc(audience === 'seller' ? 'Seller copy' : 'Customer receipt')}</span>
      <div class="muted" style="margin-top:6px">Receipt ${esc(sellerOrder.code)}<br>${new Date(sellerOrder.created_at).toLocaleString('en-IN')}</div></div>
  </div>
  <h1>${esc(shop.name)}</h1>
  <div class="muted">${esc(shop.address)}, ${esc(shop.locality)}, ${esc(shop.city)} — ${esc(shop.pincode)}${shop.phone ? ' · ' + esc(shop.phone) : ''}</div>
  <div class="grid">
    <div class="card"><b>Customer</b>${esc(customer.name)}<br>${esc(customer.email)}${audience === 'seller' ? '<br>' + esc(customer.phone || '') : ''}</div>
    <div class="card"><b>${sellerOrder.fulfillment === 'pickup' ? 'Pickup at' : 'Deliver to'}</b>${sellerOrder.fulfillment === 'pickup' ? esc(shop.address + ', ' + shop.locality + ', ' + shop.pincode) : esc([address.line1, address.line2, address.locality, address.city, address.pincode].filter(Boolean).join(', '))}<br><span class="muted">${esc(address.receiver || customer.name)} · ${esc(address.phone || customer.phone || '')}</span></div>
  </div>
  <table><thead><tr><th>Item</th><th class="r">Qty</th><th class="r">Rate</th><th class="r">Amount</th></tr></thead><tbody>${rows}</tbody></table>
  <div class="totals">
    <div><span>Subtotal</span><span>${inr(sellerOrder.subtotal_paise)}</span></div>
    ${sellerOrder.discount_paise ? `<div><span>Discount${order.coupon_code ? ' (' + esc(order.coupon_code) + ')' : ''}</span><span>−${inr(sellerOrder.discount_paise)}</span></div>` : ''}
    <div><span>${sellerOrder.fulfillment === 'pickup' ? 'Pickup charge' : 'Delivery fee'}</span><span>${sellerOrder.delivery_fee_paise ? inr(sellerOrder.delivery_fee_paise) : 'Free'}</span></div>
    <div><span>Tax</span><span>${inr(sellerOrder.tax_paise)}</span></div>
    <div class="grand"><span>Total</span><span>${inr(sellerOrder.total_paise)}</span></div>
  </div>
  <p class="muted">Payment: ${esc(order.payment_method === 'cod' ? 'Cash on delivery' : order.payment_method === 'pay_at_store' ? 'Pay at store' : 'Online')} · Status: ${esc(order.payment_status)}<br>
  Order ${esc(order.code)} · ${esc(sellerOrder.code)} · ${esc(fulfillmentLabel(sellerOrder))}</p>
  ${order.is_demo ? '<div class="demo"><b>Demo data.</b> This receipt belongs to the sample storefront. It is not a tax invoice and no payment provider processed money for it.</div>' : ''}
</div>
</body></html>`;
}

/* ------------------------------------------------------------------ */
/* Router                                                              */
/* ------------------------------------------------------------------ */

async function handle(req, res) {
  const url = new URL(req.url, 'http://nearbuy.local');
  const path = url.pathname;
  const method = req.method;
  if (!/^\/api\/(customer|partner|admin)\//.test(path)) return false;
  const q = url.searchParams;

  try {
    /* Gateway webhook: signature-verified raw body, no session. */
    if (method === 'POST' && path === '/api/customer/payments/webhook') {
      await paymentWebhook(req, res);
      return true;
    }

    let payload = {};
    if (!['GET', 'HEAD'].includes(method)) payload = await readBody(req, 320000);
    const session = sessionFor(req);
    const partnerSession = sessionFor(req, PARTNER_COOKIE);
    const adminSession = sessionFor(req, ADMIN_COOKIE);
    const authPath = /\/auth\/(login|register|forgot|reset)$/.test(path) || path === '/api/partner/login' || path === '/api/admin/login';
    if (!['GET', 'HEAD'].includes(method)) checkMutation(req, authPath ? null : (session || partnerSession || adminSession));
    const base = path.startsWith('/api/customer') ? '/api/customer' : path.startsWith('/api/partner') ? '/api/partner' : '/api/admin';
    const route = path.slice(base.length) || '/';
    /* Customer routes only match /api/customer/*, so an admin or partner path with
     * the same tail (for example /api/admin/orders) can never fall into a customer
     * handler that expects a customer session. */
    const custRoute = base === '/api/customer' ? route : '\u0000';

    const page = clampInt(q.get('page') || 1, 1, 1000);
    const limit = clampInt(q.get('limit') || 12, 1, 48);

    /* ---------------------------- auth ----------------------------- */
    if (method === 'POST' && custRoute === '/auth/register') {
      rateLimit(`register:${clientIp(req)}`, 12, 3600e3);
      const name = String(payload.name || '').trim();
      const email = String(payload.email || '').trim().toLowerCase();
      const phone = normalPhone(payload.phone);
      if (!str(name, 2, 80)) fail(400, 'Please enter your full name (2–80 characters).');
      if (!emailOk(email)) fail(400, 'Please enter a valid email address.');
      if (!phoneOk(phone)) fail(400, 'Please enter a valid 10-digit Indian mobile number.');
      if (typeof payload.password !== 'string' || payload.password.length < 8 || payload.password.length > 128) {
        fail(400, 'Your password must be 8–128 characters long.');
      }
      if (!/[A-Za-z]/.test(payload.password) || !/\d/.test(payload.password)) {
        fail(400, 'Please use at least one letter and one number in your password.');
      }
      if (payload.confirmPassword !== undefined && payload.confirmPassword !== payload.password) {
        fail(400, 'The two passwords do not match.');
      }
      if (payload.terms !== true) fail(400, 'Please accept the Terms of Use and Privacy Policy.');
      if (db.prepare('SELECT 1 FROM nb_users WHERE email=?').get(email)) fail(409, 'An account with this email already exists. Try signing in instead.', { field: 'email' });
      if (db.prepare('SELECT 1 FROM nb_users WHERE phone=?').get(phone)) fail(409, 'An account with this mobile number already exists.', { field: 'phone' });
      const id = uid();
      const created = now();
      transaction(() => {
        db.prepare(`INSERT INTO nb_users(id,role,name,email,phone,password_hash,email_verified,phone_verified,avatar,status,is_demo,created_at)
          VALUES(?, 'customer', ?, ?, ?, ?, 0, 0, '👤', 'active', ?, ?)`).run(id, name, email, phone, makePassword(payload.password), DEMO ? 1 : 0, created);
        db.prepare('INSERT INTO nb_customer_profiles(user_id,marketing_opt_in,order_updates,created_at) VALUES(?,?,1,?)').run(id, payload.marketing ? 1 : 0, created);
      });
      notify(id, 'Welcome to NearBuy', 'Shop local, compare prices and support neighbourhood businesses. Add your address to see shops that deliver to you.', 'account', '#/account/addresses');
      audit('customer', id, 'register', 'user', id, 'Customer account created');
      const user = { id, role: 'customer', name, email, phone, avatar: '👤' };
      const sess = startSession(req, user);
      send(res, 201, { user: { ...userPayload({ ...user, user_id: id, csrf: sess.csrf }), csrf: sess.csrf }, message: 'Welcome to NearBuy!' }, { 'Set-Cookie': sess.cookie });
      return true;
    }

    if (method === 'POST' && custRoute === '/auth/login') {
      rateLimit(`login:${clientIp(req)}`, 30, 900e3);
      const identifier = String(payload.identifier || payload.email || payload.phone || '').trim();
      rateLimit(`login-id:${sha(identifier.toLowerCase()).slice(0, 16)}`, 8, 900e3);
      if (!identifier || typeof payload.password !== 'string') fail(400, 'Enter your email or mobile number and password.');
      const digits = normalPhone(identifier);
      const user = emailOk(identifier)
        ? db.prepare('SELECT * FROM nb_users WHERE email=?').get(identifier.toLowerCase())
        : phoneOk(digits) ? db.prepare('SELECT * FROM nb_users WHERE phone=?').get(digits) : null;
      const ok = user ? checkPassword(payload.password, user.password_hash) : checkPassword(payload.password, makePassword('not-a-real-password'));
      if (!user || !ok) fail(401, 'Those details do not match an account. Check your email/mobile and password.');
      if (user.role !== 'customer') fail(403, 'This is a customer sign-in. Sellers and delivery partners should use their partner console.');
      if (user.status !== 'active') fail(403, 'This account is not active. Contact support.');
      const sess = startSession(req, user, SESSION_COOKIE, payload.remember === false ? 24 : SESSION_HOURS);
      audit('customer', user.id, 'login', 'user', user.id, 'Customer signed in');
      send(res, 200, { user: userPayload({ user_id: user.id, role: user.role, name: user.name, email: user.email, phone: user.phone, avatar: user.avatar, csrf: sess.csrf }), message: `Welcome back, ${user.name.split(' ')[0]}.` }, { 'Set-Cookie': sess.cookie });
      return true;
    }

    if (method === 'POST' && custRoute === '/auth/logout') {
      if (session) db.prepare('DELETE FROM nb_sessions WHERE token_hash=?').run(sha(session.token));
      send(res, 200, { ok: true }, { 'Set-Cookie': `${SESSION_COOKIE}=; ${cookieAttrs(req)}; Max-Age=0` });
      return true;
    }

    if (method === 'GET' && custRoute === '/auth/me') {
      if (!session || session.role !== 'customer') {
        send(res, 200, { user: null, config: publicConfig() });
        return true;
      }
      send(res, 200, { user: userPayload(session), config: publicConfig() });
      return true;
    }

    if (method === 'POST' && custRoute === '/auth/verify/request') {
      const s = requireCustomer(req);
      rateLimit(`verify:${s.user_id}`, 6, 600e3);
      const channel = payload.channel === 'phone' ? 'phone' : 'email';
      const user = db.prepare('SELECT * FROM nb_users WHERE id=?').get(s.user_id);
      const code = String(Math.floor(100000 + Math.random() * 900000));
      db.prepare('INSERT INTO nb_otp_codes(id,user_id,channel,purpose,target,code_hash,expires_at,attempts,created_at) VALUES(?,?,?,?,?,?,?,0,?)')
        .run(uid(), s.user_id, channel, 'verify_account', channel === 'phone' ? user.phone : user.email, sha(code), new Date(Date.now() + 10 * 60000).toISOString(), now());
      send(res, 200, {
        channel, sent: false, providerConfigured: false,
        message: `No ${channel === 'phone' ? 'SMS' : 'email'} provider is configured for this deployment, so nothing was sent.${DEV_CODES ? ' In development the code is shown here.' : ''}`,
        ...(DEV_CODES ? { devCode: code } : {})
      });
      return true;
    }

    if (method === 'POST' && custRoute === '/auth/verify/confirm') {
      const s = requireCustomer(req);
      const channel = payload.channel === 'phone' ? 'phone' : 'email';
      const code = String(payload.code || '');
      const row = db.prepare("SELECT * FROM nb_otp_codes WHERE user_id=? AND channel=? AND purpose='verify_account' AND consumed_at IS NULL ORDER BY created_at DESC LIMIT 1").get(s.user_id, channel);
      if (!row) fail(400, 'Request a new verification code first.');
      if (new Date(row.expires_at).getTime() < Date.now()) fail(400, 'That code has expired. Request a new one.');
      if (row.attempts >= 5) fail(429, 'Too many incorrect codes. Request a new one.');
      if (!safeEqual(sha(code), row.code_hash)) {
        db.prepare('UPDATE nb_otp_codes SET attempts=attempts+1 WHERE id=?').run(row.id);
        fail(400, 'That code is not correct.');
      }
      db.prepare('UPDATE nb_otp_codes SET consumed_at=? WHERE id=?').run(now(), row.id);
      db.prepare(`UPDATE nb_users SET ${channel === 'phone' ? 'phone_verified' : 'email_verified'}=1 WHERE id=?`).run(s.user_id);
      send(res, 200, { message: `${channel === 'phone' ? 'Mobile number' : 'Email address'} verified.`, user: userPayload(sessionFor(req)) });
      return true;
    }

    if (method === 'POST' && custRoute === '/auth/forgot') {
      rateLimit(`forgot:${clientIp(req)}`, 8, 3600e3);
      const email = String(payload.email || '').trim().toLowerCase();
      const generic = { message: 'If an account exists for that email, a password reset link has been created. Check your inbox.' };
      if (!emailOk(email)) fail(400, 'Enter the email address on your account.');
      const user = db.prepare("SELECT * FROM nb_users WHERE email=? AND role='customer'").get(email);
      if (user) {
        const token = randomBytes(24).toString('hex');
        db.prepare('INSERT INTO nb_password_resets(token_hash,user_id,expires_at,used_at) VALUES(?,?,?,NULL)')
          .run(sha(token), user.id, new Date(Date.now() + 3600e3).toISOString());
        audit('customer', user.id, 'password_reset_requested', 'user', user.id, 'Reset link created');
        if (DEV_CODES) {
          generic.devResetToken = token;
          generic.message = 'Email delivery is not configured in this environment. Use the development reset link below.';
          generic.resetUrl = `#/reset?token=${token}`;
        }
      }
      send(res, 200, generic);
      return true;
    }

    if (method === 'POST' && custRoute === '/auth/reset') {
      rateLimit(`reset:${clientIp(req)}`, 10, 3600e3);
      const token = String(payload.token || '');
      if (!/^[a-f0-9]{48}$/.test(token)) fail(400, 'This reset link is not valid.');
      const row = db.prepare('SELECT * FROM nb_password_resets WHERE token_hash=?').get(sha(token));
      if (!row || row.used_at || new Date(row.expires_at).getTime() < Date.now()) fail(400, 'This reset link has expired. Request a new one.');
      if (typeof payload.password !== 'string' || payload.password.length < 8 || !/[A-Za-z]/.test(payload.password) || !/\d/.test(payload.password)) {
        fail(400, 'Choose a password of at least 8 characters with a letter and a number.');
      }
      if (payload.confirmPassword !== undefined && payload.confirmPassword !== payload.password) fail(400, 'The two passwords do not match.');
      db.prepare('UPDATE nb_users SET password_hash=? WHERE id=?').run(makePassword(payload.password), row.user_id);
      db.prepare('UPDATE nb_password_resets SET used_at=? WHERE token_hash=?').run(now(), sha(token));
      db.prepare('DELETE FROM nb_sessions WHERE user_id=?').run(row.user_id);
      audit('customer', row.user_id, 'password_reset', 'user', row.user_id, 'Password changed through reset link');
      send(res, 200, { message: 'Your password has been changed. Sign in with the new password.' }, { 'Set-Cookie': `${SESSION_COOKIE}=; ${cookieAttrs(req)}; Max-Age=0` });
      return true;
    }

    /* -------------------------- bootstrap -------------------------- */
    if (method === 'GET' && custRoute === '/bootstrap') {
      const customer = session && session.role === 'customer' ? session : null;
      const cart = customer ? priceCart(customer.user_id) : { itemCount: 0, total: 0, items: 0 };
      const wishlist = customer ? db.prepare('SELECT COUNT(*) AS n FROM nb_wishlist WHERE user_id=?').get(customer.user_id) : { n: 0 };
      const unread = customer ? db.prepare('SELECT COUNT(*) AS n FROM nb_notifications WHERE user_id=? AND is_read=0').get(customer.user_id) : { n: 0 };
      send(res, 200, {
        user: customer ? userPayload(customer) : null,
        config: publicConfig(),
        categories: categoryList(),
        counts: { cart: cart.itemCount, wishlist: Number(wishlist?.n || 0), unread: Number(unread?.n || 0) },
        cartSummary: { subtotal: cart.subtotal || 0, total: cart.total || 0, itemCount: cart.itemCount || 0 },
        demoAccounts: DEMO ? {
          customer: { email: 'customer@nearbuy.demo', password: 'Customer123!' },
          seller: { email: 'owner@nearbuy.demo', password: 'Seller123!' },
          runner: { email: 'rohan@nearbuy.demo', password: 'Runner123!' }
        } : null
      });
      return true;
    }

    /* --------------------------- home ------------------------------ */
    if (method === 'GET' && custRoute === '/home') {
      const location = locationFromQuery(q);
      const banners = db.prepare('SELECT * FROM nb_banners WHERE active=1 ORDER BY sort, id').all().map((b) => ({
        id: b.id, title: b.title, subtitle: b.subtitle, eyebrow: b.eyebrow, ctaLabel: b.cta_label,
        ctaLink: b.cta_link, imageUrl: b.image_url, theme: b.theme
      }));
      const shopResult = queryShops({ location, limit: 8, sort: 'distance' });
      const productResult = queryProducts({ location, limit: 12, sort: 'relevance', available: '1' });
      const categorySet = categoryList();
      const stats = {
        shops: Number(db.prepare('SELECT COUNT(*) AS n FROM nb_shops').get().n),
        products: Number(db.prepare('SELECT COUNT(*) AS n FROM nb_products WHERE active=1').get().n),
        categories: categorySet.length,
        localities: Number(db.prepare('SELECT COUNT(DISTINCT locality) AS n FROM nb_service_areas').get().n)
      };
      const recentOrders = session && session.role === 'customer'
        ? db.prepare('SELECT * FROM nb_orders WHERE customer_id=? ORDER BY created_at DESC LIMIT 2').all(session.user_id).map((o) => orderSummary(o))
        : [];
      send(res, 200, {
        banners, categories: categorySet, shops: shopResult.shops, products: productResult.products,
        offers: activeOffers(location).slice(0, 4), stats, location, recentOrders,
        howItWorks: [
          { title: 'Find nearby shops', body: 'Share your locality or pincode and see the shops that actually deliver to you.' },
          { title: 'Discover products', body: 'Browse real catalogues, live stock and today’s prices from each seller.' },
          { title: 'Compare prices', body: 'Check the same product across nearby shops before you buy.' },
          { title: 'Cart & checkout', body: 'One basket across shops, delivery or pickup per shop, clear totals.' },
          { title: 'Track every step', body: 'Follow acceptance, preparation and delivery with a real status timeline.' },
          { title: 'Receive your order', body: 'Confirm handover with your delivery OTP and rate the shops you love.' }
        ]
      });
      return true;
    }

    if (method === 'GET' && custRoute === '/categories') {
      send(res, 200, { categories: categoryList() });
      return true;
    }

    if (method === 'GET' && custRoute === '/localities') {
      const search = String(q.get('q') || '').toLowerCase();
      const rows = db.prepare(`SELECT pincode, locality, city, lat, lng FROM nb_service_areas WHERE active=1
        ${search ? 'AND (LOWER(locality) LIKE ? OR pincode LIKE ?)' : ''} ORDER BY locality LIMIT 20`)
        .all(...(search ? [`%${search}%`, `%${search}%`] : []));
      send(res, 200, { localities: rows });
      return true;
    }

    if (method === 'GET' && custRoute === '/serviceability') {
      const pincode = String(q.get('pincode') || '');
      if (!pincodeOk(pincode)) fail(400, 'Enter a valid 6-digit pincode.');
      const area = pincodeArea(pincode);
      const location = area ? { pincode, locality: area.locality, city: area.city, lat: area.lat, lng: area.lng } : { pincode, lat: null, lng: null };
      const result = queryShops({ location, limit: 48 });
      const products = db.prepare('SELECT COUNT(*) AS n FROM nb_products p JOIN nb_shops s ON s.id=p.shop_id WHERE p.active=1').get();
      send(res, 200, {
        pincode, area: area ? { locality: area.locality, city: area.city, lat: area.lat, lng: area.lng } : null,
        serviceable: result.shops.length > 0, shops: result.shops, shopCount: result.total,
        productCount: Number(products?.n || 0),
        message: result.shops.length ? `${result.shops.length} shops deliver to ${area ? area.locality : pincode}.` : 'We are not live in this pincode yet. Try Hauz Khas (110016) or Saket (110017).'
      });
      return true;
    }

    /* --------------------------- shops ----------------------------- */
    if (method === 'GET' && custRoute === '/shops') {
      const location = locationFromQuery(q);
      const out = queryShops({
        location, category: q.get('category') || '', q: q.get('q') || '',
        sort: q.get('sort') || 'distance', open: q.get('open'), delivery: q.get('delivery'),
        pickup: q.get('pickup'), verified: q.get('verified'), minRating: q.get('minRating'),
        maxDistance: q.get('maxDistance'), includeUnserviceable: q.get('all') === '1', limit, page
      });
      send(res, 200, { ...out, location, categories: categoryList() });
      return true;
    }

    if (method === 'GET' && (custRoute.match(/^\/shops\/([a-z0-9-]+)$/))) {
      const slug = route.split('/')[2];
      const row = db.prepare('SELECT * FROM nb_shops WHERE slug=?').get(slug);
      if (!row) fail(404, 'Shop not found');
      const location = locationFromQuery(q);
      const card = shopCard(row, location);
      const products = db.prepare('SELECT * FROM nb_products WHERE shop_id=? AND active=1 ORDER BY category_slug, name').all(row.id)
        .map((p) => productCard(p, { location, shop: row }));
      const grouped = {};
      for (const p of products) {
        if (!grouped[p.categorySlug]) grouped[p.categorySlug] = { slug: p.categorySlug, name: p.category, products: [] };
        grouped[p.categorySlug].products.push(p);
      }
      const reviews = db.prepare(`SELECT r.*, u.name AS customer_name FROM nb_reviews r JOIN nb_users u ON u.id=r.customer_id
        WHERE r.shop_id=? AND r.status='published' ORDER BY r.created_at DESC LIMIT 12`).all(row.id).map((r) => ({
        id: r.id, rating: r.shop_rating, title: r.title, body: r.body, images: JSON.parse(r.images_json || '[]'),
        customerName: r.customer_name.split(' ')[0] + ' ' + (r.customer_name.split(' ')[1] || '').slice(0, 1) + '.',
        verified: Boolean(r.verified_purchase), at: r.created_at, productId: r.product_id
      }));
      const offers = activeOffers(location).filter((o) => !o.shop || o.shop.slug === slug);
      send(res, 200, {
        shop: card, categories: Object.values(grouped), products, reviews, offers, location,
        policies: {
          delivery: row.delivery_enabled ? `Home delivery within ${row.radius_km} km for ${inr(row.delivery_fee_paise)}${row.free_delivery_over_paise ? `, free over ${inr(row.free_delivery_over_paise)}` : ''}.` : 'Home delivery is not offered by this shop.',
          pickup: row.pickup_enabled ? (row.pickup_fee_paise ? `Store pickup for ${inr(row.pickup_fee_paise)}.` : 'Free store pickup.') : 'Store pickup is not offered by this shop.',
          returns: 'Return windows are shown per product. Perishables are only returnable if damaged on arrival.'
        }
      });
      return true;
    }

    /* -------------------------- products --------------------------- */
    if (method === 'GET' && custRoute === '/products') {
      const location = locationFromQuery(q);
      const out = queryProducts({
        location, q: q.get('q') || '', category: q.get('category') || '', shop: q.get('shop') || '',
        brand: q.get('brand') || '', minPrice: q.get('minPrice'), maxPrice: q.get('maxPrice'),
        rating: q.get('rating'), available: q.get('available'), delivery: q.get('delivery'),
        pickup: q.get('pickup'), sort: q.get('sort') || 'relevance', limit, page
      });
      const brands = db.prepare('SELECT DISTINCT brand FROM nb_products WHERE active=1 AND brand IS NOT NULL ORDER BY brand').all().map((b) => b.brand);
      const shops = db.prepare('SELECT id, slug, name, emoji FROM nb_shops ORDER BY name').all();
      const price = db.prepare('SELECT MIN(price_paise) AS min, MAX(price_paise) AS max FROM nb_products WHERE active=1').get();
      send(res, 200, { ...out, location, brands, shops, priceRange: { min: price.min, max: price.max }, categories: categoryList() });
      return true;
    }

    if (method === 'GET' && custRoute.match(/^\/products\/([a-zA-Z0-9_-]+)\/compare$/)) {
      const id = route.split('/')[2];
      const product = db.prepare('SELECT * FROM nb_products WHERE id=?').get(id);
      if (!product) fail(404, 'Product not found');
      const location = locationFromQuery(q);
      const rows = db.prepare(`SELECT p.*, s.name AS shop_name, s.slug AS shop_slug, s.is_open, s.delivery_enabled,
          s.pickup_enabled, s.lat AS shop_lat, s.lng AS shop_lng, s.service_pincodes, s.radius_km, s.rating AS shop_rating, s.verified
        FROM nb_products p JOIN nb_shops s ON s.id=p.shop_id WHERE p.compare_key=? AND p.active=1`).all(product.compare_key);
      const listings = rows.map((r) => {
        const shop = db.prepare('SELECT * FROM nb_shops WHERE id=?').get(r.shop_id);
        const card = productCard(r, { location, shop });
        return {
          ...card, shopVerified: Boolean(shop.verified), shopRating: shop.rating, shopOpen: Boolean(shop.is_open),
          serviceable: location ? shopCard(shop, location).serviceable : true,
          deliveryFee: shop.delivery_fee_paise, pickupFee: shop.pickup_fee_paise,
          freeDeliveryOver: shop.free_delivery_over_paise,
          deliveryTime: shop.prep_minutes + 18, pickupTime: shop.prep_minutes
        };
      }).sort((a, b) => (Number(b.available) - Number(a.available)) || a.price - b.price);
      const availableListings = listings.filter((l) => l.available);
      const lowest = availableListings.length ? Math.min(...availableListings.map((l) => l.price)) : null;
      send(res, 200, {
        product: productCard(product, { location }), listings,
        lowestPrice: lowest, savings: lowest != null && product.mrp_paise ? product.mrp_paise - lowest : 0,
        equivalentNote: 'Listings are matched on the same brand, product name, pack size and variant. Check the pack size before choosing a seller.',
        location
      });
      return true;
    }

    if (method === 'GET' && custRoute.match(/^\/products\/([a-zA-Z0-9_-]+)$/)) {
      const id = route.split('/')[2];
      const row = db.prepare('SELECT * FROM nb_products WHERE id=?').get(id);
      /* Admin moderation hides a listing from the storefront without deleting it. */
      if (!row || !row.active) fail(404, 'Product not found');
      const shop = db.prepare('SELECT * FROM nb_shops WHERE id=?').get(row.shop_id);
      if (!shop) fail(404, 'Product not found');
      const location = locationFromQuery(q);
      const images = db.prepare('SELECT url FROM nb_product_images WHERE product_id=? ORDER BY sort').all(id).map((i) => i.url);
      const reviews = db.prepare(`SELECT r.*, u.name AS customer_name FROM nb_reviews r JOIN nb_users u ON u.id=r.customer_id
        WHERE r.product_id=? AND r.status='published' ORDER BY r.created_at DESC LIMIT 10`).all(id).map((r) => ({
        id: r.id, rating: r.product_rating, title: r.title, body: r.body, images: JSON.parse(r.images_json || '[]'),
        customerName: r.customer_name.split(' ')[0] + ' ' + (r.customer_name.split(' ')[1] || '').slice(0, 1) + '.',
        verified: Boolean(r.verified_purchase), at: r.created_at
      }));
      const compareRows = db.prepare('SELECT p.* FROM nb_products p JOIN nb_shops s ON s.id=p.shop_id WHERE p.compare_key=? AND p.active=1').all(row.compare_key);
      const wishlisted = session && session.role === 'customer'
        ? Boolean(db.prepare('SELECT 1 FROM nb_wishlist WHERE user_id=? AND product_id=?').get(session.user_id, id)) : false;
      const related = db.prepare('SELECT * FROM nb_products WHERE category_slug=? AND id<>? AND active=1 ORDER BY RANDOM() LIMIT 6').all(row.category_slug, id)
        .map((p) => productCard(p, { location }));
      send(res, 200, {
        product: {
          ...productCard(row, { location, shop }),
          description: row.description,
          highlights: JSON.parse(row.highlights || '[]'),
          specs: JSON.parse(row.specs || '[]'),
          images: images.length ? images : row.image_url ? [row.image_url] : [],
          lowStockAt: row.low_stock
        },
        shop: shopCard(shop, location),
        reviews, related, wishlisted, location,
        compare: (() => {
          const availableRows = compareRows.filter((r) => r.stock - r.reserved > 0);
          return { count: compareRows.length, lowest: availableRows.length ? Math.min(...availableRows.map((r) => r.price_paise)) : null };
        })()
      });
      return true;
    }

    if (method === 'GET' && custRoute === '/search/suggest') {
      const term = String(q.get('q') || '').trim();
      if (term.length < 2) { send(res, 200, { products: [], shops: [], categories: [] }); return true; }
      const like = `%${term.toLowerCase()}%`;
      const location = locationFromQuery(q);
      const products = db.prepare(`SELECT p.* FROM nb_products p JOIN nb_shops s ON s.id=p.shop_id
        WHERE p.active=1 AND (LOWER(p.name) LIKE ? OR LOWER(p.brand) LIKE ? OR LOWER(p.category_slug) LIKE ?) LIMIT 6`)
        .all(like, like, like).map((p) => productCard(p, { location }));
      const shops = db.prepare(`SELECT * FROM nb_shops WHERE LOWER(name) LIKE ? OR LOWER(tagline) LIKE ? OR LOWER(category_slug) LIKE ? LIMIT 4`)
        .all(like, like, like).map((s) => shopCard(s, location));
      const categories = categoryList().filter((c) => c.name.toLowerCase().includes(term.toLowerCase())).slice(0, 4);
      send(res, 200, { products, shops, categories, query: term });
      return true;
    }

    if (method === 'GET' && custRoute === '/offers') {
      const location = locationFromQuery(q);
      const offers = activeOffers(location);
      const eligibleProducts = db.prepare('SELECT p.* FROM nb_products p JOIN nb_shops s ON s.id=p.shop_id WHERE p.active=1 AND p.mrp_paise>p.price_paise ORDER BY ((p.mrp_paise-p.price_paise)*100/p.mrp_paise) DESC LIMIT 8')
        .all().map((p) => productCard(p, { location }));
      send(res, 200, { offers, products: eligibleProducts, location });
      return true;
    }

    if (method === 'GET' && custRoute === '/faqs') {
      send(res, 200, { faqs: db.prepare('SELECT * FROM nb_faqs ORDER BY sort').all() });
      return true;
    }

    if (method === 'GET' && custRoute === '/reviews') {
      const productId = q.get('productId');
      const shopSlug = q.get('shop');
      let rows;
      if (productId) {
        rows = db.prepare(`SELECT r.*, u.name AS customer_name FROM nb_reviews r JOIN nb_users u ON u.id=r.customer_id
          WHERE r.product_id=? AND r.status='published' ORDER BY r.created_at DESC LIMIT 50`).all(productId);
      } else if (shopSlug) {
        const shop = db.prepare('SELECT id FROM nb_shops WHERE slug=?').get(shopSlug);
        rows = shop ? db.prepare(`SELECT r.*, u.name AS customer_name FROM nb_reviews r JOIN nb_users u ON u.id=r.customer_id
          WHERE r.shop_id=? AND r.status='published' ORDER BY r.created_at DESC LIMIT 50`).all(shop.id) : [];
      } else {
        rows = db.prepare(`SELECT r.*, u.name AS customer_name FROM nb_reviews r JOIN nb_users u ON u.id=r.customer_id
          WHERE r.status='published' ORDER BY r.created_at DESC LIMIT 50`).all();
      }
      send(res, 200, { reviews: rows.map((r) => ({
        id: r.id, rating: r.product_rating || r.shop_rating, shopRating: r.shop_rating, productRating: r.product_rating,
        title: r.title, body: r.body, images: JSON.parse(r.images_json || '[]'), verified: Boolean(r.verified_purchase),
        customerName: r.customer_name, at: r.created_at, productId: r.product_id, shopId: r.shop_id
      })) });
      return true;
    }

    if (method === 'POST' && custRoute === '/enquiry') {
      rateLimit(`enquiry:${clientIp(req)}`, 6, 3600e3);
      if (!str(payload.name, 2, 80)) fail(400, 'Please tell us your name.');
      if (!str(payload.contact, 5, 120)) fail(400, 'Add an email address or mobile number so we can reply.');
      if (!str(payload.topic, 2, 60)) fail(400, 'Choose a topic.');
      if (!str(payload.message, 10, 2000)) fail(400, 'Please add a message of at least 10 characters.');
      const code = 'ENQ-' + String(Math.floor(100000 + Math.random() * 900000));
      db.prepare('INSERT INTO nb_enquiries(id,code,name,contact,topic,message,status,created_at) VALUES(?,?,?,?,?,?,?,?)')
        .run(uid(), code, payload.name.trim(), payload.contact.trim(), payload.topic.trim(), payload.message.trim(), 'open', now());
      audit('guest', null, 'enquiry', 'enquiry', code, `Contact form: ${payload.topic}`);
      send(res, 201, { code, message: `Thanks — your enquiry is logged as ${code}. This demo records the message in NearBuy; no email provider is configured, so nothing is sent.` });
      return true;
    }

    /* -------------------------- addresses -------------------------- */
    if (method === 'GET' && custRoute === '/addresses') {
      const s = requireCustomer(req);
      send(res, 200, { addresses: addressList(s.user_id), areas: db.prepare('SELECT pincode, locality, city FROM nb_service_areas WHERE active=1 ORDER BY locality').all() });
      return true;
    }

    if (method === 'POST' && custRoute === '/addresses') {
      const s = requireCustomer(req);
      const count = db.prepare('SELECT COUNT(*) AS n FROM nb_addresses WHERE user_id=?').get(s.user_id);
      if (Number(count.n) >= 10) fail(409, 'You can save up to 10 addresses. Remove one first.');
      const label = ['Home', 'Work', 'Other'].includes(payload.label) ? payload.label : 'Home';
      const receiver = String(payload.receiver || '').trim();
      const phone = normalPhone(payload.phone);
      const line1 = String(payload.line1 || '').trim();
      const line2 = String(payload.line2 || '').trim().slice(0, 120);
      const locality = String(payload.locality || '').trim();
      const city = String(payload.city || 'New Delhi').trim().slice(0, 60);
      const pincode = String(payload.pincode || '').trim();
      const landmark = String(payload.landmark || '').trim().slice(0, 120);
      const instructions = String(payload.instructions || '').trim().slice(0, 240);
      if (!str(receiver, 2, 80)) fail(400, 'Enter the name of the person receiving the order.');
      if (!phoneOk(phone)) fail(400, 'Enter a valid 10-digit contact number for this address.');
      if (!str(line1, 3, 120)) fail(400, 'Enter the house/flat and street address.');
      if (!str(locality, 2, 80)) fail(400, 'Enter your locality.');
      if (!pincodeOk(pincode)) fail(400, 'Enter a valid 6-digit pincode.');
      const area = pincodeArea(pincode);
      if (!area) fail(400, 'We do not recognise this pincode yet. Try 110016, 110017, 110024, 110048 or 110070.');
      const lat = Number.isFinite(Number(payload.lat)) ? Number(payload.lat) : area.lat;
      const lng = Number.isFinite(Number(payload.lng)) ? Number(payload.lng) : area.lng;
      const id = uid();
      const makeDefault = payload.isDefault === true || Number(count.n) === 0;
      transaction(() => {
        if (makeDefault) db.prepare('UPDATE nb_addresses SET is_default=0 WHERE user_id=?').run(s.user_id);
        db.prepare(`INSERT INTO nb_addresses(id,user_id,label,receiver,phone,line1,line2,locality,city,pincode,landmark,instructions,lat,lng,is_default,created_at)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(id, s.user_id, label, receiver, phone, line1, line2 || null, locality, city, pincode,
          landmark || null, instructions || null, lat, lng, makeDefault ? 1 : 0, now());
      });
      const address = db.prepare('SELECT * FROM nb_addresses WHERE id=?').get(id);
      send(res, 201, { address: addressDetail(address), message: `${label} address saved.` });
      return true;
    }

    if (method === 'PATCH' && custRoute.match(/^\/addresses\/[a-zA-Z0-9-]+$/)) {
      const s = requireCustomer(req);
      const id = route.split('/')[2];
      const existing = db.prepare('SELECT * FROM nb_addresses WHERE id=? AND user_id=?').get(id, s.user_id);
      if (!existing) fail(404, 'Address not found');
      const next = { ...existing };
      for (const key of ['receiver', 'line1', 'line2', 'locality', 'city', 'landmark', 'instructions']) {
        if (payload[key] !== undefined) next[key] = String(payload[key] || '').trim().slice(0, 240);
      }
      if (payload.label !== undefined) next.label = ['Home', 'Work', 'Other'].includes(payload.label) ? payload.label : next.label;
      if (payload.phone !== undefined) {
        if (!phoneOk(payload.phone)) fail(400, 'Enter a valid 10-digit contact number.');
        next.phone = normalPhone(payload.phone);
      }
      if (payload.pincode !== undefined) {
        if (!pincodeOk(payload.pincode) || !pincodeArea(payload.pincode)) fail(400, 'Enter a serviceable 6-digit pincode.');
        next.pincode = String(payload.pincode);
      }
      if (!next.receiver || !next.line1 || !next.locality) fail(400, 'Name, address and locality are required.');
      transaction(() => {
        db.prepare(`UPDATE nb_addresses SET label=?,receiver=?,phone=?,line1=?,line2=?,locality=?,city=?,pincode=?,landmark=?,instructions=? WHERE id=? AND user_id=?`)
          .run(next.label, next.receiver, next.phone, next.line1, next.line2 || null, next.locality, next.city, next.pincode,
            next.landmark || null, next.instructions || null, id, s.user_id);
        if (payload.isDefault === true) {
          db.prepare('UPDATE nb_addresses SET is_default=0 WHERE user_id=?').run(s.user_id);
          db.prepare('UPDATE nb_addresses SET is_default=1 WHERE id=?').run(id);
        }
      });
      send(res, 200, { address: addressDetail(db.prepare('SELECT * FROM nb_addresses WHERE id=?').get(id)), message: 'Address updated.' });
      return true;
    }

    if (method === 'DELETE' && custRoute.match(/^\/addresses\/[a-zA-Z0-9-]+$/)) {
      const s = requireCustomer(req);
      const id = route.split('/')[2];
      const existing = db.prepare('SELECT * FROM nb_addresses WHERE id=? AND user_id=?').get(id, s.user_id);
      if (!existing) fail(404, 'Address not found');
      const active = db.prepare("SELECT COUNT(*) AS n FROM nb_orders WHERE customer_id=? AND status NOT IN ('completed','cancelled','delivered')").get(s.user_id);
      if (Number(active.n) > 0 && existing.is_default) fail(409, 'This is your default address for an active order. Choose another default first.');
      db.prepare('DELETE FROM nb_addresses WHERE id=? AND user_id=?').run(id, s.user_id);
      if (existing.is_default) {
        const next = db.prepare('SELECT id FROM nb_addresses WHERE user_id=? ORDER BY created_at DESC LIMIT 1').get(s.user_id);
        if (next) db.prepare('UPDATE nb_addresses SET is_default=1 WHERE id=?').run(next.id);
      }
      send(res, 200, { message: 'Address removed.' });
      return true;
    }

    if (method === 'POST' && custRoute.match(/^\/addresses\/[a-zA-Z0-9-]+\/default$/)) {
      const s = requireCustomer(req);
      const id = route.split('/')[2];
      if (!db.prepare('SELECT 1 FROM nb_addresses WHERE id=? AND user_id=?').get(id, s.user_id)) fail(404, 'Address not found');
      transaction(() => {
        db.prepare('UPDATE nb_addresses SET is_default=0 WHERE user_id=?').run(s.user_id);
        db.prepare('UPDATE nb_addresses SET is_default=1 WHERE id=?').run(id);
      });
      send(res, 200, { message: 'Default address updated.' });
      return true;
    }

    /* ----------------------------- cart ---------------------------- */
    if (method === 'GET' && custRoute === '/cart') {
      const s = requireCustomer(req);
      send(res, 200, { cart: priceCart(s.user_id), addresses: addressList(s.user_id) });
      return true;
    }

    if (method === 'POST' && custRoute === '/cart/items') {
      const s = requireCustomer(req);
      const productId = String(payload.productId || '');
      const addQty = clampInt(payload.qty || 1, 1, 20);
      const product = db.prepare('SELECT * FROM nb_products WHERE id=? AND active=1').get(productId);
      if (!product) fail(404, 'This product is no longer listed.');
      const shop = db.prepare('SELECT * FROM nb_shops WHERE id=?').get(product.shop_id);
      if (!shop.is_open) fail(409, `${shop.name} is currently closed. You can keep browsing, but this item cannot be added until the shop opens.`);
      const lineCount = db.prepare('SELECT COUNT(*) AS n FROM nb_cart_items WHERE user_id=?').get(s.user_id);
      const existing = db.prepare('SELECT * FROM nb_cart_items WHERE user_id=? AND product_id=?').get(s.user_id, productId);
      if (!existing && Number(lineCount.n) >= 40) fail(409, 'Your basket has the maximum number of different items. Remove something first.');
      const nextQty = (existing ? existing.qty : 0) + addQty;
      const available = Math.max(0, product.stock - product.reserved);
      if (available <= 0) fail(409, `${product.name} is out of stock at ${shop.name}.`);
      if (nextQty > available) fail(409, `Only ${available} ${available === 1 ? 'unit is' : 'units are'} available at ${shop.name}.`);
      if (nextQty > 20) fail(409, 'You can buy up to 20 units of one item per order.');
      getCartRow(s.user_id, true);
      if (existing) {
        db.prepare('UPDATE nb_cart_items SET qty=? WHERE user_id=? AND product_id=?').run(nextQty, s.user_id, productId);
      } else {
        db.prepare('INSERT INTO nb_cart_items(user_id,product_id,qty,created_at) VALUES(?,?,?,?)').run(s.user_id, productId, addQty, now());
      }
      db.prepare('UPDATE nb_carts SET updated_at=? WHERE user_id=?').run(now(), s.user_id);
      const cart = priceCart(s.user_id);
      send(res, 200, { cart, message: `${product.name} added to your basket.` });
      return true;
    }

    if (method === 'PATCH' && custRoute.match(/^\/cart\/items\/[a-zA-Z0-9_-]+$/)) {
      const s = requireCustomer(req);
      const productId = route.split('/')[3];
      const item = db.prepare('SELECT ci.*, p.name, p.stock, p.reserved FROM nb_cart_items ci JOIN nb_products p ON p.id=ci.product_id WHERE ci.user_id=? AND ci.product_id=?').get(s.user_id, productId);
      if (!item) fail(404, 'That item is not in your basket.');
      const qty = clampInt(payload.qty, 0, 20);
      if (qty === 0) {
        db.prepare('DELETE FROM nb_cart_items WHERE user_id=? AND product_id=?').run(s.user_id, productId);
      } else {
        const available = Math.max(0, item.stock - item.reserved);
        if (qty > available) fail(409, `Only ${available} available at this shop.`);
        db.prepare('UPDATE nb_cart_items SET qty=? WHERE user_id=? AND product_id=?').run(qty, s.user_id, productId);
      }
      db.prepare('UPDATE nb_carts SET updated_at=? WHERE user_id=?').run(now(), s.user_id);
      send(res, 200, { cart: priceCart(s.user_id) });
      return true;
    }

    if (method === 'DELETE' && custRoute === '/cart/items') {
      const s = requireCustomer(req);
      db.prepare('DELETE FROM nb_cart_items WHERE user_id=?').run(s.user_id);
      db.prepare('UPDATE nb_carts SET coupon_code=NULL,updated_at=? WHERE user_id=?').run(now(), s.user_id);
      send(res, 200, { cart: priceCart(s.user_id), message: 'Basket emptied.' });
      return true;
    }

    if (method === 'DELETE' && custRoute.match(/^\/cart\/items\/[a-zA-Z0-9_-]+$/)) {
      const s = requireCustomer(req);
      const productId = route.split('/')[3];
      db.prepare('DELETE FROM nb_cart_items WHERE user_id=? AND product_id=?').run(s.user_id, productId);
      send(res, 200, { cart: priceCart(s.user_id), message: 'Item removed.' });
      return true;
    }

    if (method === 'POST' && custRoute === '/cart/merge') {
      const s = requireCustomer(req);
      const items = Array.isArray(payload.items) ? payload.items.slice(0, 40) : [];
      let added = 0;
      for (const it of items) {
        const productId = typeof it?.productId === 'string' ? it.productId : '';
        const product = db.prepare('SELECT * FROM nb_products WHERE id=? AND active=1').get(productId);
        if (!product) continue;
        const available = Math.max(0, product.stock - product.reserved);
        if (available <= 0) continue;
        const qty = clampInt(it.qty || 1, 1, Math.min(20, available));
        const existing = db.prepare('SELECT * FROM nb_cart_items WHERE user_id=? AND product_id=?').get(s.user_id, productId);
        if (existing) {
          const next = Math.min(available, 20, existing.qty + qty);
          db.prepare('UPDATE nb_cart_items SET qty=? WHERE user_id=? AND product_id=?').run(next, s.user_id, productId);
        } else {
          db.prepare('INSERT INTO nb_cart_items(user_id,product_id,qty,created_at) VALUES(?,?,?,?)').run(s.user_id, productId, qty, now());
        }
        added += 1;
      }
      send(res, 200, { cart: priceCart(s.user_id), merged: added, message: added ? `${added} item${added === 1 ? '' : 's'} moved into your basket.` : 'Your basket is up to date.' });
      return true;
    }

    if (method === 'POST' && custRoute === '/cart/coupon') {
      const s = requireCustomer(req);
      const code = String(payload.code || '').trim().toUpperCase();
      if (!/^[A-Z0-9-]{3,24}$/.test(code)) fail(400, 'Enter a valid coupon code.');
      const rows = cartLines(s.user_id);
      if (!rows.length) fail(409, 'Add something to your basket before applying a coupon.');
      const coupon = db.prepare('SELECT * FROM nb_coupons WHERE code=?').get(code);
      const check = couponUsable(coupon, s.user_id, rows, rows.reduce((t, r) => t + r.price_paise * r.qty, 0));
      if (!check.ok) fail(400, check.message);
      db.prepare('UPDATE nb_carts SET coupon_code=?,updated_at=? WHERE user_id=?').run(code, now(), s.user_id);
      send(res, 200, { cart: priceCart(s.user_id), message: `${code} applied.` });
      return true;
    }

    if (method === 'DELETE' && custRoute === '/cart/coupon') {
      const s = requireCustomer(req);
      getCartRow(s.user_id, true);
      db.prepare('UPDATE nb_carts SET coupon_code=NULL,updated_at=? WHERE user_id=?').run(now(), s.user_id);
      send(res, 200, { cart: priceCart(s.user_id), message: 'Coupon removed.' });
      return true;
    }

    if (method === 'POST' && custRoute === '/checkout/quote') {
      const s = requireCustomer(req);
      const quote = quoteFor(s.user_id, payload);
      send(res, 200, { quote });
      return true;
    }

    /* ---------------------------- orders --------------------------- */
    if (method === 'POST' && custRoute === '/orders') {
      const s = requireCustomer(req);
      rateLimit(`checkout:${s.user_id}`, 12, 300e3);
      const idempotencyKey = typeof payload.idempotencyKey === 'string' && payload.idempotencyKey.length >= 8 && payload.idempotencyKey.length <= 80
        ? payload.idempotencyKey : uid();
      const prior = db.prepare('SELECT * FROM nb_orders WHERE customer_id=? AND idempotency_key=?').get(s.user_id, idempotencyKey);
      if (prior) {
        send(res, 200, { order: orderDetail(prior, { includeCodes: true }), duplicate: true });
        return true;
      }
      const paymentMethod = ['cod', 'pay_at_store', 'online'].includes(payload.paymentMethod) ? payload.paymentMethod : 'cod';
      const quote = quoteFor(s.user_id, payload);
      if (quote.rejectedCoupon) fail(400, quote.rejectedCoupon.message);
      if (quote.issues.length) fail(409, quote.issues[0], { issues: quote.issues });
      if (paymentMethod === 'pay_at_store' && !quote.groups.every((g) => g.fulfillment === 'pickup')) {
        fail(400, 'Pay at store is only available when every shop in this order is set to store pickup.');
      }
      if (paymentMethod === 'online' && !GATEWAY.configured) {
        fail(503, 'Online payment is not configured on this server. Choose cash on delivery or pay at store, or ask the operator to add the gateway keys.');
      }
      const user = db.prepare('SELECT * FROM nb_users WHERE id=?').get(s.user_id);
      const address = quote.address;
      const orderId = uid();
      const orderCode = newOrderCode();
      const created = now();
      const couponRow = quote.coupon ? db.prepare('SELECT * FROM nb_coupons WHERE code=?').get(quote.coupon.code) : null;
      let result;
      transaction(() => {
        const lines = cartLines(s.user_id);
        if (!lines.length) fail(409, 'Your basket is empty.');
        // Conditional reservation prevents overselling under concurrency.
        for (const line of lines) {
          const upd = db.prepare('UPDATE nb_products SET reserved=reserved+? WHERE id=? AND active=1 AND stock-reserved>=?')
            .run(line.qty, line.id, line.qty);
          if (Number(upd.changes) !== 1) fail(409, `${line.name} just went out of stock at ${line.shop_name}. Remove it and try again.`);
        }
        db.prepare(`INSERT INTO nb_orders
          (id,code,customer_id,status,payment_method,payment_status,address_json,subtotal_paise,discount_paise,delivery_fee_paise,tax_paise,total_paise,coupon_code,note,idempotency_key,is_demo,created_at,updated_at)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
          orderId, orderCode, s.user_id, 'placed', paymentMethod, 'pending', JSON.stringify(address),
          quote.subtotal, quote.discount, quote.deliveryFee, quote.tax, quote.total,
          quote.coupon?.code || null, String(payload.note || '').trim().slice(0, 300) || null,
          idempotencyKey, user.is_demo ? 1 : 0, created, created
        );
        addEvent(orderId, null, 'placed', 'Order placed', `${quote.groups.length} shop${quote.groups.length === 1 ? '' : 's'} · ${paymentMethod === 'cod' ? 'Cash on delivery' : paymentMethod === 'pay_at_store' ? 'Pay at store' : 'Online payment pending'}`, 'customer');
        for (const group of quote.groups) {
          const sellerOrderId = uid();
          const sellerCode = newSellerCode();
          db.prepare(`INSERT INTO nb_seller_orders
            (id,code,order_id,shop_id,status,fulfillment,subtotal_paise,discount_paise,delivery_fee_paise,tax_paise,total_paise,prep_minutes,ready_at,accepted_at,rejected_reason,cancelled_at,delivered_at,completed_at,runner_id,delivery_otp_expires,delivery_attempts,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,NULL,NULL,NULL,NULL,NULL,NULL,NULL,?,0,?,?)`).run(
            sellerOrderId, sellerCode, orderId, group.shop.id, 'placed', group.fulfillment,
            group.subtotal, group.discount, group.deliveryFee, group.tax, group.total, group.shop.prepMinutes,
            new Date(Date.now() + 72 * 3600e3).toISOString(), created, created
          );
          for (const item of group.items) {
            const product = db.prepare('SELECT * FROM nb_products WHERE id=?').get(item.productId);
            db.prepare(`INSERT INTO nb_order_items
              (id,order_id,seller_order_id,product_id,shop_id,name,brand,unit,qty,price_paise,mrp_paise,tax_rate,line_total_paise,image_url,emoji,compare_key)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
              uid(), orderId, sellerOrderId, item.productId, group.shop.id, product.name, product.brand, product.unit,
              item.qty, item.price, item.mrp, product.tax_rate, item.lineTotal, product.image_url, product.emoji, product.compare_key
            );
          }
          addEvent(orderId, sellerOrderId, 'placed', 'Seller notified', `${group.shop.name} received this part of the order.`, 'system');
          const owner = db.prepare('SELECT owner_user_id FROM nb_shops WHERE id=?').get(group.shop.id)?.owner_user_id;
          if (owner) notify(owner, 'New order received', `${sellerCode} · ${group.items.reduce((t, i) => t + i.qty, 0)} item(s) · ₹${Math.round(group.total / 100)}. Accept or reject it in your Seller Hub.`, 'seller', '#/orders');
        }
        db.prepare(`INSERT INTO nb_payment_records(id,order_id,seller_order_id,provider,method,amount_paise,status,reference,created_at,updated_at)
          VALUES(?,?,NULL,?,?,?,?,?,?,?)`).run(
          uid(), orderId, paymentMethod === 'cod' ? 'cash' : paymentMethod === 'pay_at_store' ? 'store' : 'razorpay',
          paymentMethod, quote.total, 'pending', null, created, created
        );
        if (couponRow) {
          db.prepare('INSERT INTO nb_coupon_redemptions(id,coupon_code,user_id,order_id,amount_paise,created_at) VALUES(?,?,?,?,?,?)')
            .run(uid(), couponRow.code, s.user_id, orderId, quote.discount, created);
          db.prepare('UPDATE nb_coupons SET used_count=used_count+1 WHERE code=?').run(couponRow.code);
        }
        db.prepare('DELETE FROM nb_cart_items WHERE user_id=?').run(s.user_id);
        db.prepare('UPDATE nb_carts SET coupon_code=NULL,updated_at=? WHERE user_id=?').run(now(), s.user_id);
        notify(s.user_id, 'Order placed', `${orderCode} · ₹${Math.round(quote.total / 100)}. We have notified ${quote.groups.length === 1 ? quote.groups[0].shop.name : quote.groups.length + ' shops'}.`, 'order', `#/orders/${orderCode}`);
        audit('customer', s.user_id, 'order_created', 'order', orderId, `${orderCode} · ${paymentMethod} · ${quote.total}`);
        result = orderDetail(db.prepare('SELECT * FROM nb_orders WHERE id=?').get(orderId), { includeCodes: true });
      });
      send(res, 201, { order: result, message: 'Order placed. The seller has been notified.' });
      return true;
    }

    if (method === 'GET' && custRoute === '/orders') {
      const s = requireCustomer(req);
      const filter = String(q.get('filter') || 'all');
      const search = String(q.get('q') || '').toLowerCase();
      let rows = db.prepare('SELECT * FROM nb_orders WHERE customer_id=? ORDER BY created_at DESC').all(s.user_id);
      let summaries = rows.map((o) => orderSummary(o));
      if (filter === 'in_progress') summaries = summaries.filter((o) => ['placed', 'accepted', 'preparing', 'ready', 'runner_requested', 'runner_assigned', 'out_for_delivery', 'partially_cancelled'].includes(o.status));
      else if (filter === 'delivered') summaries = summaries.filter((o) => ['delivered', 'completed'].includes(o.status));
      else if (filter === 'cancelled') summaries = summaries.filter((o) => o.status === 'cancelled');
      else if (filter === 'returned' || filter === 'refunded') {
        const codes = new Set(db.prepare("SELECT o.code FROM nb_orders o JOIN nb_returns r ON r.order_id=o.id WHERE r.customer_id=? AND r.status IN ('requested','under_review','approved','processing','completed')").all(s.user_id).map((r) => r.code));
        summaries = summaries.filter((o) => codes.has(o.code));
      }
      if (search) summaries = summaries.filter((o) => o.code.toLowerCase().includes(search) || o.shops.some((s2) => s2.shop?.name.toLowerCase().includes(search)));
      const total = summaries.length;
      const start = (page - 1) * limit;
      send(res, 200, {
        orders: summaries.slice(start, start + limit), total, page, pages: Math.max(1, Math.ceil(total / limit)),
        counts: {
          all: rows.length,
          in_progress: rows.map((o) => orderSummary(o)).filter((o) => ['placed', 'accepted', 'preparing', 'ready', 'runner_requested', 'runner_assigned', 'out_for_delivery', 'partially_cancelled'].includes(o.status)).length,
          delivered: rows.map((o) => orderSummary(o)).filter((o) => ['delivered', 'completed'].includes(o.status)).length,
          cancelled: rows.map((o) => orderSummary(o)).filter((o) => o.status === 'cancelled').length
        }
      });
      return true;
    }

    if (method === 'GET' && custRoute.match(/^\/orders\/[A-Za-z0-9-]+\/receipt$/)) {
      const s = requireCustomer(req);
      const code = decodeURIComponent(route.split('/')[2]);
      const order = orderByCode(code, s.user_id);
      const sellerCode = q.get('sellerOrder');
      const so = sellerCode
        ? db.prepare('SELECT * FROM nb_seller_orders WHERE order_id=? AND code=?').get(order.id, sellerCode)
        : db.prepare('SELECT * FROM nb_seller_orders WHERE order_id=? ORDER BY created_at LIMIT 1').get(order.id);
      if (!so) fail(404, 'Receipt not found');
      const shop = db.prepare('SELECT * FROM nb_shops WHERE id=?').get(so.shop_id);
      const customer = db.prepare('SELECT * FROM nb_users WHERE id=?').get(order.customer_id);
      sendHtml(res, 200, receiptHtml(order, so, shop, customer, 'customer'));
      return true;
    }

    if (method === 'GET' && custRoute.match(/^\/orders\/[A-Za-z0-9-]+$/)) {
      const s = requireCustomer(req);
      const code = decodeURIComponent(route.split('/')[2]);
      const order = orderByCode(code, s.user_id);
      send(res, 200, { order: orderDetail(order, { includeCodes: true }) });
      return true;
    }

    if (method === 'POST' && custRoute.match(/^\/orders\/[A-Za-z0-9-]+\/cancel$/)) {
      const s = requireCustomer(req);
      const code = decodeURIComponent(route.split('/')[2]);
      const order = orderByCode(code, s.user_id);
      const reason = String(payload.reason || '').trim();
      if (!str(reason, 3, 200)) fail(400, 'Tell us why you want to cancel (at least 3 characters).');
      const target = payload.sellerOrderId
        ? [db.prepare('SELECT * FROM nb_seller_orders WHERE order_id=? AND code=?').get(order.id, String(payload.sellerOrderId))]
        : db.prepare('SELECT * FROM nb_seller_orders WHERE order_id=?').all(order.id);
      if (!target[0]) fail(404, 'Shop order not found');
      for (const so of target) {
        if (!['placed', 'accepted'].includes(so.status)) {
          fail(409, `${so.code} can no longer be cancelled online because the shop has already started preparing it. Contact support for help.`);
        }
      }
      transaction(() => {
        for (const so of target) cancelSellerOrder(so, reason, 'customer');
        audit('customer', s.user_id, 'order_cancelled', 'order', order.id, reason);
      });
      send(res, 200, { order: orderDetail(db.prepare('SELECT * FROM nb_orders WHERE id=?').get(order.id), { includeCodes: true }), message: 'Order cancelled. Any reserved stock has been released.' });
      return true;
    }

    /* ---------------------------- returns -------------------------- */
    const validImages = (images) => {
      if (!Array.isArray(images)) return [];
      return images.slice(0, 3).filter((v) => typeof v === 'string' && /^data:image\/(png|jpe?g|webp);base64,[A-Za-z0-9+/=]+$/.test(v) && v.length < 180000);
    };

    if (method === 'POST' && custRoute.match(/^\/orders\/[A-Za-z0-9-]+\/returns$/)) {
      const s = requireCustomer(req);
      const code = decodeURIComponent(route.split('/')[2]);
      const order = orderByCode(code, s.user_id);
      const so = db.prepare('SELECT * FROM nb_seller_orders WHERE order_id=? AND id=?').get(order.id, String(payload.sellerOrderId || ''));
      if (!so) fail(404, 'Shop order not found.');
      if (!['delivered', 'completed'].includes(so.status)) fail(409, 'You can request a return only after the order is delivered.');
      const item = db.prepare('SELECT * FROM nb_order_items WHERE id=? AND seller_order_id=?').get(String(payload.itemId || ''), so.id);
      if (!item) fail(400, 'Choose an item from this order.');
      const product = db.prepare('SELECT * FROM nb_products WHERE id=?').get(item.product_id);
      const days = product?.return_days || 0;
      if (!days) fail(409, `${item.name} is not returnable. Perishable items can only be reported as damaged through support.`);
      const deliveredAt = so.delivered_at || so.completed_at || so.updated_at;
      if (Date.now() - new Date(deliveredAt).getTime() > days * 864e5) fail(409, `The ${days}-day return window for this item has closed.`);
      const reason = String(payload.reason || '').trim();
      if (!str(reason, 3, 160)) fail(400, 'Choose a return reason.');
      const images = validImages(payload.images);
      const duplicate = db.prepare("SELECT 1 FROM nb_returns WHERE item_id=? AND status NOT IN ('rejected','cancelled','completed')").get(item.id);
      if (duplicate) fail(409, 'A return request for this item is already open.');
      const returnId = uid();
      let returnCode;
      for (let i = 0; i < 6; i++) {
        returnCode = 'RTN-' + String(Math.floor(100000 + Math.random() * 900000));
        if (!db.prepare('SELECT 1 FROM nb_returns WHERE code=?').get(returnCode)) break;
      }
      transaction(() => {
        db.prepare(`INSERT INTO nb_returns(id,code,customer_id,order_id,seller_order_id,item_id,reason,comment,images_json,status,refund_amount_paise,decision_note,created_at,updated_at)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,NULL,?,?)`).run(returnId, returnCode, s.user_id, order.id, so.id, item.id, reason,
          String(payload.comment || '').trim().slice(0, 800) || null, JSON.stringify(images), 'requested', item.line_total_paise, now(), now());
        db.prepare('INSERT INTO nb_refunds(id,return_id,order_id,amount_paise,status,reference,created_at,updated_at) VALUES(?,?,?,?,?,NULL,?,?)')
          .run(uid(), returnId, order.id, item.line_total_paise, 'requested', now(), now());
        addEvent(order.id, so.id, 'return_requested', 'Return requested', `${item.name} · ${reason}`, 'customer');
        notify(s.user_id, 'Return request received', `${returnCode} for ${item.name}. The shop will review it and you can follow the refund status in My Account.`, 'return', '#/account/returns');
      });
      audit('customer', s.user_id, 'return_requested', 'return', returnId, `${returnCode} · ${item.name}`);
      send(res, 201, { return: { code: returnCode, status: 'requested' }, message: `Return ${returnCode} submitted. The shop will review it.` });
      return true;
    }

    if (method === 'GET' && custRoute === '/returns') {
      const s = requireCustomer(req);
      const rows = db.prepare(`SELECT r.*, o.code AS order_code, so.code AS seller_order_code, s.name AS shop_name, s.slug AS shop_slug,
          i.name AS item_name, i.emoji AS item_emoji, i.qty AS item_qty
        FROM nb_returns r JOIN nb_orders o ON o.id=r.order_id JOIN nb_seller_orders so ON so.id=r.seller_order_id
        LEFT JOIN nb_shops s ON s.id=so.shop_id LEFT JOIN nb_order_items i ON i.id=r.item_id
        WHERE r.customer_id=? ORDER BY r.created_at DESC`).all(s.user_id);
      const refunds = db.prepare('SELECT * FROM nb_refunds WHERE order_id IN (SELECT id FROM nb_orders WHERE customer_id=?) ORDER BY created_at DESC').all(s.user_id);
      send(res, 200, {
        returns: rows.map((r) => ({
          code: r.code, status: r.status, reason: r.reason, comment: r.comment, images: JSON.parse(r.images_json || '[]'),
          amount: r.refund_amount_paise, createdAt: r.created_at, updatedAt: r.updated_at, decisionNote: r.decision_note,
          orderCode: r.order_code, sellerOrderCode: r.seller_order_code, shop: { name: r.shop_name, slug: r.shop_slug },
          item: { name: r.item_name, emoji: r.item_emoji, qty: r.item_qty }
        })),
        refunds: refunds.map((r) => ({ amount: r.amount_paise, status: r.status, reference: r.reference, at: r.created_at, updatedAt: r.updated_at }))
      });
      return true;
    }

    /* ---------------------------- reviews -------------------------- */
    if (method === 'POST' && custRoute === '/reviews') {
      const s = requireCustomer(req);
      const order = orderByCode(String(payload.orderCode || ''), s.user_id);
      const so = db.prepare('SELECT * FROM nb_seller_orders WHERE order_id=? AND id=?').get(order.id, String(payload.sellerOrderId || ''));
      if (!so) fail(404, 'Order not found.');
      if (!['delivered', 'completed'].includes(so.status)) fail(409, 'You can review this order after it is delivered.');
      const productId = String(payload.productId || '');
      if (productId && !db.prepare('SELECT 1 FROM nb_order_items WHERE seller_order_id=? AND product_id=?').get(so.id, productId)) {
        fail(403, 'Only a product you actually bought can be reviewed.');
      }
      const shopRating = clampInt(payload.shopRating || payload.rating, 1, 5);
      const productRating = productId ? clampInt(payload.productRating || payload.rating, 1, 5) : null;
      const body = String(payload.body || '').trim();
      if (!str(body, 10, 1200)) fail(400, 'Please write at least 10 characters about your experience.');
      const images = validImages(payload.images);
      if (db.prepare('SELECT 1 FROM nb_reviews WHERE customer_id=? AND seller_order_id=? AND IFNULL(product_id,\'\')=?').get(s.user_id, so.id, productId)) {
        fail(409, 'You have already reviewed this item for this order.');
      }
      const id = uid();
      transaction(() => {
        db.prepare(`INSERT INTO nb_reviews(id,customer_id,shop_id,product_id,seller_order_id,order_id,shop_rating,product_rating,title,body,images_json,verified_purchase,status,created_at)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,1,'published',?)`).run(id, s.user_id, so.shop_id, productId || null, so.id, order.id,
          shopRating, productRating, String(payload.title || '').trim().slice(0, 90) || null, body, JSON.stringify(images), now());
        const shopAgg = db.prepare("SELECT AVG(shop_rating) AS avg, COUNT(*) AS n FROM nb_reviews WHERE shop_id=? AND status='published'").get(so.shop_id);
        db.prepare('UPDATE nb_shops SET rating=?,review_count=? WHERE id=?').run(round2(shopAgg.avg || 0), Number(shopAgg.n || 0), so.shop_id);
        if (productId) {
          const pAgg = db.prepare("SELECT AVG(product_rating) AS avg, COUNT(*) AS n FROM nb_reviews WHERE product_id=? AND status='published'").get(productId);
          db.prepare('UPDATE nb_products SET rating=?,review_count=? WHERE id=?').run(round2(pAgg.avg || 0), Number(pAgg.n || 0), productId);
        }
      });
      notify(s.user_id, 'Thanks for your review', 'Your verified review is now published. It helps neighbours choose local shops with confidence.', 'review', '#/account/reviews');
      send(res, 201, { message: 'Review published. Thank you for supporting local shops.' });
      return true;
    }

    if (method === 'GET' && custRoute === '/reviews/mine') {
      const s = requireCustomer(req);
      const rows = db.prepare(`SELECT r.*, s.name AS shop_name, s.slug AS shop_slug, p.name AS product_name, p.emoji AS product_emoji
        FROM nb_reviews r LEFT JOIN nb_shops s ON s.id=r.shop_id LEFT JOIN nb_products p ON p.id=r.product_id
        WHERE r.customer_id=? ORDER BY r.created_at DESC`).all(s.user_id);
      send(res, 200, { reviews: rows.map((r) => ({
        id: r.id, shop: { name: r.shop_name, slug: r.shop_slug }, product: r.product_name ? { name: r.product_name, emoji: r.product_emoji } : null,
        shopRating: r.shop_rating, productRating: r.product_rating, rating: r.product_rating || r.shop_rating,
        title: r.title, body: r.body, images: JSON.parse(r.images_json || '[]'), status: r.status,
        verified: Boolean(r.verified_purchase), at: r.created_at
      })) });
      return true;
    }

    if (method === 'POST' && custRoute.match(/^\/reviews\/[a-zA-Z0-9-]+\/report$/)) {
      const s = requireCustomer(req);
      const id = route.split('/')[2];
      const review = db.prepare('SELECT * FROM nb_reviews WHERE id=?').get(id);
      if (!review) fail(404, 'Review not found');
      if (review.customer_id === s.user_id) fail(400, 'You cannot report your own review.');
      const reason = String(payload.reason || '').trim().slice(0, 300);
      audit('customer', s.user_id, 'review_reported', 'review', id, reason || 'Reported from the storefront');
      send(res, 200, { message: 'Thanks — the review has been sent to moderation. It stays visible until a moderator decides.' });
      return true;
    }

    /* ---------------------------- wishlist ------------------------- */
    if (method === 'GET' && custRoute === '/wishlist') {
      const s = requireCustomer(req);
      const location = locationFromQuery(q);
      const rows = db.prepare(`SELECT p.* FROM nb_wishlist w JOIN nb_products p ON p.id=w.product_id
        JOIN nb_shops sh ON sh.id=p.shop_id WHERE w.user_id=? AND p.active=1 ORDER BY w.created_at DESC`).all(s.user_id);
      send(res, 200, { products: rows.map((p) => productCard(p, { location })), count: rows.length });
      return true;
    }

    if (method === 'POST' && custRoute.match(/^\/wishlist\/[a-zA-Z0-9_-]+$/)) {
      const s = requireCustomer(req);
      const productId = route.split('/')[2];
      if (!db.prepare('SELECT 1 FROM nb_products WHERE id=? AND active=1').get(productId)) fail(404, 'Product not found');
      db.prepare('INSERT OR IGNORE INTO nb_wishlist(user_id,product_id,created_at) VALUES(?,?,?)').run(s.user_id, productId, now());
      send(res, 200, { saved: true, message: 'Saved to your wishlist.' });
      return true;
    }

    if (method === 'DELETE' && custRoute.match(/^\/wishlist\/[a-zA-Z0-9_-]+$/)) {
      const s = requireCustomer(req);
      const productId = route.split('/')[2];
      db.prepare('DELETE FROM nb_wishlist WHERE user_id=? AND product_id=?').run(s.user_id, productId);
      send(res, 200, { saved: false, message: 'Removed from your wishlist.' });
      return true;
    }

    /* --------------------------- account --------------------------- */
    if (method === 'GET' && custRoute === '/account') {
      const s = requireCustomer(req);
      const userId = s.user_id;
      const orders = db.prepare('SELECT * FROM nb_orders WHERE customer_id=? ORDER BY created_at DESC').all(userId).map((o) => orderSummary(o));
      const counts = {
        orders: orders.length,
        pending: orders.filter((o) => ['placed', 'accepted', 'preparing', 'ready', 'runner_requested', 'runner_assigned', 'out_for_delivery'].includes(o.status)).length,
        completed: orders.filter((o) => ['delivered', 'completed'].includes(o.status)).length,
        cancelled: orders.filter((o) => o.status === 'cancelled').length,
        addresses: Number(db.prepare('SELECT COUNT(*) AS n FROM nb_addresses WHERE user_id=?').get(userId).n),
        wishlist: Number(db.prepare('SELECT COUNT(*) AS n FROM nb_wishlist WHERE user_id=?').get(userId).n),
        reviews: Number(db.prepare('SELECT COUNT(*) AS n FROM nb_reviews WHERE customer_id=?').get(userId).n),
        returns: Number(db.prepare('SELECT COUNT(*) AS n FROM nb_returns WHERE customer_id=?').get(userId).n),
        tickets: Number(db.prepare("SELECT COUNT(*) AS n FROM nb_tickets WHERE customer_id=? AND status NOT IN ('resolved','closed')").get(userId).n),
        unread: Number(db.prepare('SELECT COUNT(*) AS n FROM nb_notifications WHERE user_id=? AND is_read=0').get(userId).n)
      };
      send(res, 200, {
        user: userPayload(s), addresses: addressList(userId), counts,
        recentOrders: orders.slice(0, 3),
        addressesPreview: addressList(userId).slice(0, 2)
      });
      return true;
    }

    if (method === 'PATCH' && custRoute === '/account') {
      const s = requireCustomer(req);
      const user = db.prepare('SELECT * FROM nb_users WHERE id=?').get(s.user_id);
      const name = payload.name !== undefined ? String(payload.name).trim() : user.name;
      if (!str(name, 2, 80)) fail(400, 'Name must be 2–80 characters.');
      const avatar = payload.avatar !== undefined ? String(payload.avatar).slice(0, 8) : user.avatar;
      db.prepare('UPDATE nb_users SET name=?,avatar=? WHERE id=?').run(name, avatar || '👤', s.user_id);
      if (payload.marketingOptIn !== undefined || payload.orderUpdates !== undefined) {
        db.prepare('UPDATE nb_customer_profiles SET marketing_opt_in=?,order_updates=? WHERE user_id=?')
          .run(payload.marketingOptIn === false ? 0 : 1, payload.orderUpdates === false ? 0 : 1, s.user_id);
      }
      send(res, 200, { user: userPayload(sessionFor(req)), message: 'Profile updated.' });
      return true;
    }

    if (method === 'POST' && custRoute === '/account/password') {
      const s = requireCustomer(req);
      const user = db.prepare('SELECT * FROM nb_users WHERE id=?').get(s.user_id);
      if (!checkPassword(payload.current || '', user.password_hash)) fail(400, 'Your current password is not correct.');
      if (typeof payload.password !== 'string' || payload.password.length < 8 || !/[A-Za-z]/.test(payload.password) || !/\d/.test(payload.password)) {
        fail(400, 'Choose a new password of at least 8 characters with a letter and a number.');
      }
      if (payload.confirm !== undefined && payload.confirm !== payload.password) fail(400, 'The new passwords do not match.');
      db.prepare('UPDATE nb_users SET password_hash=? WHERE id=?').run(makePassword(payload.password), s.user_id);
      db.prepare('DELETE FROM nb_sessions WHERE user_id=? AND token_hash<>?').run(s.user_id, sha(s.token));
      audit('customer', s.user_id, 'password_changed', 'user', s.user_id, 'Password changed from account settings');
      send(res, 200, { message: 'Password changed. Other devices have been signed out.' });
      return true;
    }

    if (method === 'POST' && (custRoute === '/account/email/request' || custRoute === '/account/phone/request')) {
      const s = requireCustomer(req);
      rateLimit(`contact-change:${s.user_id}`, 6, 600e3);
      const isEmail = route.includes('/email/');
      const target = isEmail ? String(payload.email || '').trim().toLowerCase() : normalPhone(payload.phone);
      if (isEmail && !emailOk(target)) fail(400, 'Enter a valid email address.');
      if (!isEmail && !phoneOk(target)) fail(400, 'Enter a valid 10-digit mobile number.');
      if (db.prepare(`SELECT 1 FROM nb_users WHERE ${isEmail ? 'email' : 'phone'}=? AND id<>?`).get(target, s.user_id)) fail(409, 'That contact detail is already used by another account.');
      rateLimit(`contact-code:${s.user_id}`, 6, 600e3);
      const code = String(Math.floor(100000 + Math.random() * 900000));
      db.prepare('INSERT INTO nb_otp_codes(id,user_id,channel,purpose,target,code_hash,expires_at,attempts,created_at) VALUES(?,?,?,?,?,?,?,0,?)')
        .run(uid(), s.user_id, isEmail ? 'email' : 'phone', 'change_contact', target, sha(code), new Date(Date.now() + 10 * 60000).toISOString(), now());
      send(res, 200, {
        target, sent: false, providerConfigured: false,
        message: `No ${isEmail ? 'email' : 'SMS'} provider is configured, so the code is shown here in development.`,
        ...(DEV_CODES ? { devCode: code } : {})
      });
      return true;
    }

    if (method === 'POST' && (custRoute === '/account/email/confirm' || custRoute === '/account/phone/confirm')) {
      const s = requireCustomer(req);
      const isEmail = route.includes('/email/');
      const channel = isEmail ? 'email' : 'phone';
      const row = db.prepare("SELECT * FROM nb_otp_codes WHERE user_id=? AND channel=? AND purpose='change_contact' AND consumed_at IS NULL ORDER BY created_at DESC LIMIT 1").get(s.user_id, channel);
      if (!row) fail(400, 'Request a new verification code first.');
      if (new Date(row.expires_at).getTime() < Date.now()) fail(400, 'That code has expired.');
      if (row.attempts >= 5) fail(429, 'Too many incorrect codes. Request a new one.');
      if (!safeEqual(sha(String(payload.code || '')), row.code_hash)) {
        db.prepare('UPDATE nb_otp_codes SET attempts=attempts+1 WHERE id=?').run(row.id);
        fail(400, 'That code is not correct.');
      }
      db.prepare('UPDATE nb_otp_codes SET consumed_at=? WHERE id=?').run(now(), row.id);
      db.prepare(`UPDATE nb_users SET ${channel}=?, ${channel}_verified=1 WHERE id=?`).run(row.target, s.user_id);
      audit('customer', s.user_id, 'contact_changed', 'user', s.user_id, `${channel} updated`);
      send(res, 200, { message: `${isEmail ? 'Email' : 'Mobile number'} updated and verified.`, user: userPayload(sessionFor(req)) });
      return true;
    }

    if (method === 'GET' && custRoute === '/account/sessions') {
      const s = requireCustomer(req);
      const rows = db.prepare('SELECT token_hash,created_at,expires_at,user_agent FROM nb_sessions WHERE user_id=? ORDER BY created_at DESC').all(s.user_id);
      send(res, 200, { sessions: rows.map((r) => ({
        id: r.token_hash.slice(0, 16), createdAt: r.created_at, expiresAt: r.expires_at,
        device: r.user_agent || 'Unknown device', current: r.token_hash === sha(s.token)
      })) });
      return true;
    }

    if (method === 'POST' && custRoute === '/account/sessions/revoke') {
      const s = requireCustomer(req);
      if (payload.all === true) {
        db.prepare('DELETE FROM nb_sessions WHERE user_id=?').run(s.user_id);
      } else if (payload.id) {
        const row = db.prepare('SELECT token_hash FROM nb_sessions WHERE user_id=? AND token_hash LIKE ?').get(s.user_id, `${String(payload.id)}%`);
        if (!row) fail(404, 'Session not found');
        if (row.token_hash === sha(s.token)) fail(400, 'Use Sign out to end this session.');
        db.prepare('DELETE FROM nb_sessions WHERE token_hash=?').run(row.token_hash);
      } else fail(400, 'Choose a session to revoke.');
      send(res, 200, { message: 'Session ended.' });
      return true;
    }

    /* ------------------------- notifications ----------------------- */
    if (method === 'GET' && custRoute === '/notifications') {
      const s = requireCustomer(req);
      const rows = db.prepare('SELECT * FROM nb_notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 100').all(s.user_id);
      send(res, 200, {
        notifications: rows.map((n) => ({ id: n.id, title: n.title, body: n.body, type: n.type, link: n.link, read: Boolean(n.is_read), at: n.created_at })),
        unread: rows.filter((n) => !n.is_read).length
      });
      return true;
    }

    if (method === 'POST' && custRoute === '/notifications/read') {
      const s = requireCustomer(req);
      if (payload.all === true) db.prepare('UPDATE nb_notifications SET is_read=1 WHERE user_id=?').run(s.user_id);
      else if (Array.isArray(payload.ids)) {
        const ids = payload.ids.map((n) => Number(n)).filter(Number.isSafeInteger).slice(0, 100);
        const stmt = db.prepare('UPDATE nb_notifications SET is_read=1 WHERE id=? AND user_id=?');
        for (const id of ids) stmt.run(id, s.user_id);
      } else fail(400, 'Choose notifications to mark as read.');
      send(res, 200, { ok: true });
      return true;
    }

    /* --------------------------- support --------------------------- */
    const TICKET_CATEGORIES = ['order', 'payment', 'delivery', 'missing', 'damaged', 'wrong', 'return', 'shop', 'account', 'other'];

    if (method === 'GET' && custRoute === '/tickets') {
      const s = requireCustomer(req);
      const rows = db.prepare('SELECT * FROM nb_tickets WHERE customer_id=? ORDER BY created_at DESC').all(s.user_id);
      send(res, 200, { tickets: rows.map((t) => ({
        code: t.code, category: t.category, subject: t.subject, status: t.status, priority: t.priority,
        createdAt: t.created_at, updatedAt: t.updated_at
      })) });
      return true;
    }

    if (method === 'POST' && custRoute === '/tickets') {
      const s = requireCustomer(req);
      rateLimit(`ticket:${s.user_id}`, 8, 3600e3);
      const category = TICKET_CATEGORIES.includes(payload.category) ? payload.category : null;
      if (!category) fail(400, 'Choose a complaint category.');
      if (!str(payload.subject, 5, 120)) fail(400, 'Add a subject of 5–120 characters.');
      if (!str(payload.description, 20, 2000)) fail(400, 'Describe the issue in at least 20 characters.');
      let orderId = null;
      if (payload.orderCode) {
        const order = orderByCode(String(payload.orderCode).trim().toUpperCase(), s.user_id);
        orderId = order.id;
      }
      const code = 'TKT-' + String(Math.floor(100000 + Math.random() * 900000));
      const id = uid();
      const attachment = typeof payload.attachment === 'string' && /^data:image\/(png|jpe?g|webp);base64,/.test(payload.attachment) && payload.attachment.length < 180000 ? payload.attachment : null;
      transaction(() => {
        db.prepare(`INSERT INTO nb_tickets(id,code,customer_id,order_id,category,subject,description,attachment,status,priority,created_at,updated_at)
          VALUES(?,?,?,?,?,?,?,?, 'open','normal',?,?)`).run(id, code, s.user_id, orderId, category, payload.subject.trim(), payload.description.trim(), attachment, now(), now());
        db.prepare('INSERT INTO nb_ticket_messages(id,ticket_id,author_role,author_name,body,created_at) VALUES(?,?,?,?,?,?)')
          .run(uid(), id, 'customer', db.prepare('SELECT name FROM nb_users WHERE id=?').get(s.user_id).name, payload.description.trim(), now());
      });
      notify(s.user_id, 'Support ticket created', `${code}: ${payload.subject.trim()}. You can follow replies in Help → My tickets.`, 'support', `#/help/tickets/${code}`);
      send(res, 201, { ticket: { code, status: 'open' }, message: `Ticket ${code} created. A support agent will review it.` });
      return true;
    }

    if (method === 'GET' && custRoute.match(/^\/tickets\/[A-Za-z0-9-]+$/)) {
      const s = requireCustomer(req);
      const code = decodeURIComponent(route.split('/')[2]);
      const ticket = db.prepare('SELECT * FROM nb_tickets WHERE code=? AND customer_id=?').get(code, s.user_id);
      if (!ticket) fail(404, 'Ticket not found');
      const messages = db.prepare('SELECT * FROM nb_ticket_messages WHERE ticket_id=? ORDER BY created_at').all(ticket.id);
      const order = ticket.order_id ? db.prepare('SELECT code FROM nb_orders WHERE id=?').get(ticket.order_id) : null;
      send(res, 200, { ticket: {
        code: ticket.code, category: ticket.category, subject: ticket.subject, description: ticket.description,
        status: ticket.status, priority: ticket.priority, createdAt: ticket.created_at, updatedAt: ticket.updated_at,
        orderCode: order?.code || null, attachment: ticket.attachment,
        messages: messages.map((m) => ({ authorRole: m.author_role, authorName: m.author_name, body: m.body, at: m.created_at }))
      } });
      return true;
    }

    if (method === 'POST' && custRoute.match(/^\/tickets\/[A-Za-z0-9-]+\/messages$/)) {
      const s = requireCustomer(req);
      const code = decodeURIComponent(route.split('/')[2]);
      const ticket = db.prepare('SELECT * FROM nb_tickets WHERE code=? AND customer_id=?').get(code, s.user_id);
      if (!ticket) fail(404, 'Ticket not found');
      if (['closed'].includes(ticket.status)) fail(409, 'This ticket is closed. Create a new ticket if you still need help.');
      if (!str(payload.body, 2, 2000)) fail(400, 'Write a message of at least 2 characters.');
      const name = db.prepare('SELECT name FROM nb_users WHERE id=?').get(s.user_id).name;
      transaction(() => {
        db.prepare('INSERT INTO nb_ticket_messages(id,ticket_id,author_role,author_name,body,created_at) VALUES(?,?,?,?,?,?)')
          .run(uid(), ticket.id, 'customer', name, payload.body.trim(), now());
        db.prepare("UPDATE nb_tickets SET status=?,updated_at=? WHERE id=?").run(ticket.status === 'awaiting_customer' ? 'in_progress' : ticket.status, now(), ticket.id);
      });
      send(res, 200, { message: 'Reply added.' });
      return true;
    }

    if (method === 'POST' && custRoute.match(/^\/tickets\/[A-Za-z0-9-]+\/close$/)) {
      const s = requireCustomer(req);
      const code = decodeURIComponent(route.split('/')[2]);
      const ticket = db.prepare('SELECT * FROM nb_tickets WHERE code=? AND customer_id=?').get(code, s.user_id);
      if (!ticket) fail(404, 'Ticket not found');
      db.prepare("UPDATE nb_tickets SET status='closed',updated_at=? WHERE id=?").run(now(), ticket.id);
      send(res, 200, { message: 'Ticket closed.' });
      return true;
    }

    /* ================================================================== */
    /* Partner console — Seller Hub workflow (same database, same orders)  */
    /* ================================================================== */

    if (method === 'POST' && route === '/login' && base === '/api/partner') {
      rateLimit(`partner-login:${clientIp(req)}`, 20, 900e3);
      const email = String(payload.email || '').trim().toLowerCase();
      if (!emailOk(email) || typeof payload.password !== 'string') fail(400, 'Enter your partner email and password.');
      const user = db.prepare("SELECT * FROM nb_users WHERE email=? AND role IN ('seller','runner')").get(email);
      const ok = user ? checkPassword(payload.password, user.password_hash) : checkPassword(payload.password, makePassword('invalid-password'));
      if (!user || !ok) fail(401, 'Those partner details do not match an account.');
      if (user.status !== 'active') fail(403, 'This partner account is not active.');
      const sess = startSession(req, user, PARTNER_COOKIE);
      const shop = user.role === 'seller' ? db.prepare('SELECT * FROM nb_shops WHERE owner_user_id=?').get(user.id) : null;
      const runner = user.role === 'runner' ? db.prepare('SELECT * FROM nb_runners WHERE user_id=?').get(user.id) : null;
      audit(user.role, user.id, 'partner_login', 'user', user.id, `${user.role} signed in`);
      send(res, 200, {
        user: { id: user.id, name: user.name, email: user.email, role: user.role, phone: user.phone, avatar: user.avatar, csrf: sess.csrf },
        shop: shop ? { id: shop.id, slug: shop.slug, name: shop.name, emoji: shop.emoji, locality: shop.locality, isOpen: Boolean(shop.is_open), openAt: shop.opens_at, closeAt: shop.closes_at } : null,
        runner: runner ? { vehicle: runner.vehicle, status: runner.status, rating: runner.rating, completed: runner.completed } : null
      }, { 'Set-Cookie': sess.cookie });
      return true;
    }

    if (base === '/api/partner' && route === '/me' && method === 'GET') {
      const s = sessionFor(req, PARTNER_COOKIE);
      if (!s || !['seller', 'runner'].includes(s.role)) { send(res, 200, { user: null }); return true; }
      const shop = s.role === 'seller' ? db.prepare('SELECT * FROM nb_shops WHERE owner_user_id=?').get(s.user_id) : null;
      const runner = s.role === 'runner' ? db.prepare('SELECT * FROM nb_runners WHERE user_id=?').get(s.user_id) : null;
      send(res, 200, {
        user: { id: s.user_id, name: s.name, email: s.email, phone: s.phone, avatar: s.avatar, role: s.role, csrf: s.csrf },
        shop: shop ? { id: shop.id, slug: shop.slug, name: shop.name, emoji: shop.emoji, locality: shop.locality, isOpen: Boolean(shop.is_open), openAt: shop.opens_at, closeAt: shop.closes_at } : null,
        runner: runner ? { vehicle: runner.vehicle, status: runner.status, rating: runner.rating, completed: runner.completed } : null
      });
      return true;
    }

    if (base === '/api/partner' && route === '/logout' && method === 'POST') {
      const s = sessionFor(req, PARTNER_COOKIE);
      if (s) db.prepare('DELETE FROM nb_sessions WHERE token_hash=?').run(sha(s.token));
      send(res, 200, { ok: true }, { 'Set-Cookie': `${PARTNER_COOKIE}=; ${cookieAttrs(req)}; Max-Age=0` });
      return true;
    }

    function requirePartner(roles) {
      const s = sessionFor(req, PARTNER_COOKIE);
      if (!s) fail(401, 'Partner sign-in required');
      if (!roles.includes(s.role)) fail(403, 'This partner area is not available for your role');
      return s;
    }
    function sellerShopContext(s) {
      const shop = db.prepare('SELECT * FROM nb_shops WHERE owner_user_id=?').get(s.user_id);
      if (!shop) fail(403, 'No shop is linked to this seller account. Ask operations to link it.');
      return shop;
    }
    function sellerOrderOwned(code, shop) {
      const so = db.prepare('SELECT * FROM nb_seller_orders WHERE code=? AND shop_id=?').get(String(code), shop.id);
      if (!so) fail(404, 'Order not found for your shop');
      return so;
    }
    function syncParentPayment(orderId) {
      const order = db.prepare('SELECT * FROM nb_orders WHERE id=?').get(orderId);
      const siblings = db.prepare('SELECT * FROM nb_seller_orders WHERE order_id=?').all(orderId);
      const allPaid = siblings.every((s) => ['delivered', 'completed'].includes(s.status));
      const payment = { paid: 'paid', pending: 'pending' }[allPaid ? 'paid' : 'pending'];
      if (payment === 'paid' && order.payment_status !== 'paid') {
        db.prepare("UPDATE nb_orders SET payment_status='paid',updated_at=? WHERE id=?").run(now(), orderId);
        db.prepare("UPDATE nb_payment_records SET status='paid',updated_at=? WHERE order_id=?").run(now(), orderId);
        notify(order.customer_id, 'Payment recorded', `₹${Math.round(order.total_paise / 100)} was collected for ${order.code}.`, 'payment', `#/orders/${order.code}`);
      }
      if (siblings.every((s) => ['delivered', 'completed', 'cancelled', 'rejected'].includes(s.status))) {
        db.prepare('UPDATE nb_orders SET status=? WHERE id=?').run(siblings.every((s) => ['delivered', 'completed'].includes(s.status)) ? 'completed' : 'cancelled', orderId);
      }
    }

    if (base === '/api/partner' && route === '/seller/overview' && method === 'GET') {
      const s = requirePartner(['seller']);
      const shop = sellerShopContext(s);
      const orders = db.prepare('SELECT * FROM nb_seller_orders WHERE shop_id=? ORDER BY created_at DESC').all(shop.id);
      const counts = {
        new: orders.filter((o) => o.status === 'placed').length,
        preparing: orders.filter((o) => ['accepted', 'preparing'].includes(o.status)).length,
        ready: orders.filter((o) => ['ready', 'runner_requested'].includes(o.status)).length,
        onTheWay: orders.filter((o) => ['runner_assigned', 'picked_up', 'out_for_delivery'].includes(o.status)).length,
        completed: orders.filter((o) => ['delivered', 'completed'].includes(o.status)).length
      };
      const revenue = orders.filter((o) => ['delivered', 'completed'].includes(o.status)).reduce((t, o) => t + o.total_paise, 0);
      const lowStock = db.prepare('SELECT id,name,stock,low_stock,emoji FROM nb_products WHERE shop_id=? AND active=1 AND stock<=low_stock ORDER BY stock LIMIT 6').all(shop.id);
      const recent = orders.slice(0, 5).map((so) => {
        const order = db.prepare('SELECT * FROM nb_orders WHERE id=?').get(so.order_id);
        const customer = db.prepare('SELECT name FROM nb_users WHERE id=?').get(order.customer_id);
        return { code: so.code, parentCode: order.code, customer: customer?.name, status: so.status, total: so.total_paise, fulfillment: so.fulfillment, createdAt: so.created_at };
      });
      send(res, 200, {
        shop: { id: shop.id, name: shop.name, emoji: shop.emoji, slug: shop.slug, isOpen: Boolean(shop.is_open), opensAt: shop.opens_at, closesAt: shop.closes_at, verified: Boolean(shop.verified), rating: shop.rating },
        counts, revenue, orders: orders.length, lowStock: lowStock.map((p) => ({ id: p.id, name: p.name, stock: p.stock, lowAt: p.low_stock, emoji: p.emoji })),
        recent,
        runnerOffers: db.prepare(`SELECT a.*, so.code, u.name FROM nb_delivery_assignments a
          JOIN nb_seller_orders so ON so.id=a.seller_order_id JOIN nb_users u ON u.id=a.runner_id
          WHERE a.shop_id=? AND a.status='offered' AND a.expires_at>? ORDER BY a.created_at DESC`).all(shop.id, now()).map((a) => ({
          id: a.id, orderCode: a.code, runner: a.name, expiresAt: a.expires_at
        }))
      });
      return true;
    }

    if (base === '/api/partner' && route === '/seller/orders' && method === 'GET') {
      const s = requirePartner(['seller']);
      const shop = sellerShopContext(s);
      const filter = String(q.get('status') || 'all');
      let orders = db.prepare('SELECT * FROM nb_seller_orders WHERE shop_id=? ORDER BY created_at DESC LIMIT 100').all(shop.id);
      if (filter !== 'all') {
        const sets = {
          new: ['placed'], active: ['accepted', 'preparing', 'ready', 'runner_requested', 'runner_assigned', 'picked_up', 'out_for_delivery'],
          completed: ['delivered', 'completed'], cancelled: ['cancelled', 'rejected']
        };
        orders = orders.filter((o) => (sets[filter] || []).includes(o.status));
      }
      const payloadOrders = orders.map((so) => {
        const order = db.prepare('SELECT * FROM nb_orders WHERE id=?').get(so.order_id);
        const customer = db.prepare('SELECT name,phone FROM nb_users WHERE id=?').get(order.customer_id);
        const items = db.prepare('SELECT * FROM nb_order_items WHERE seller_order_id=?').all(so.id);
        const address = JSON.parse(order.address_json);
        return {
          id: so.id, code: so.code, parentCode: order.code, status: so.status, statusLabel: STATUS_LABELS[so.status] || so.status,
          fulfillment: so.fulfillment, total: so.total_paise, subtotal: so.subtotal_paise, discount: so.discount_paise,
          deliveryFee: so.delivery_fee_paise, tax: so.tax_paise, createdAt: so.created_at, acceptedAt: so.accepted_at,
          readyAt: so.ready_at, deliveredAt: so.delivered_at, paymentMethod: order.payment_method, paymentStatus: order.payment_status,
          customer: { name: customer?.name || 'Customer', phone: customer?.phone || null, maskedPhone: maskedPhone(customer?.phone) },
          address: so.fulfillment === 'delivery' ? address : null,
          items: items.map((i) => ({ name: i.name, qty: i.qty, price: i.price_paise, emoji: i.emoji, unit: i.unit })),
          itemCount: items.reduce((t, i) => t + i.qty, 0),
          handoverPin: ['ready', 'runner_requested', 'runner_assigned'].includes(so.status) ? deriveCode('handover', so.id, 4) : null,
          pickupCodeHint: so.fulfillment === 'pickup' ? 'Ask the customer for their 6-digit collection code.' : null,
          runner: so.runner_id ? db.prepare('SELECT name,phone FROM nb_users WHERE id=?').get(so.runner_id) : null,
          receiptUrl: `/api/partner/seller/receipt/${so.code}`
        };
      });
      send(res, 200, { orders: payloadOrders, shop: { name: shop.name, emoji: shop.emoji } });
      return true;
    }

    if (base === '/api/partner' && route.match(/^\/seller\/orders\/[A-Za-z0-9-]+\/action$/) && method === 'POST') {
      const s = requirePartner(['seller']);
      const shop = sellerShopContext(s);
      const code = decodeURIComponent(route.split('/')[3]);
      const so = sellerOrderOwned(code, shop);
      const order = db.prepare('SELECT * FROM nb_orders WHERE id=?').get(so.order_id);
      const action = String(payload.action || '');
      const reason = String(payload.reason || '').trim();
      let message = '';
      transaction(() => {
        if (action === 'accept') {
          if (so.status !== 'placed') fail(409, 'This order is no longer waiting for acceptance.');
          for (const item of db.prepare('SELECT * FROM nb_order_items WHERE seller_order_id=?').all(so.id)) {
            const upd = db.prepare('UPDATE nb_products SET stock=stock-?,reserved=MAX(0,reserved-?) WHERE id=? AND stock>=?').run(item.qty, item.qty, item.product_id, item.qty);
            if (Number(upd.changes) !== 1) fail(409, `Stock for ${item.name} changed. Reject the order or ask support to adjust it.`);
          }
          db.prepare('UPDATE nb_seller_orders SET status=?,accepted_at=?,updated_at=? WHERE id=?').run('accepted', now(), now(), so.id);
          addEvent(so.order_id, so.id, 'accepted', 'Seller accepted', `${shop.name} accepted your order.`, 'seller');
          notify(order.customer_id, `${shop.name} accepted your order`, `${so.code} is being prepared. You can still cancel until preparation starts.`, 'order', `#/orders/${order.code}`);
          message = 'Order accepted. Stock has been deducted from your inventory.';
        } else if (action === 'reject') {
          if (!['placed', 'accepted'].includes(so.status)) fail(409, 'Only a new or accepted order can be rejected.');
          if (!str(reason, 3, 200)) fail(400, 'Give the customer a reason for rejecting this order.');
          releaseStockForSellerOrder(so);
          db.prepare('UPDATE nb_seller_orders SET status=?,rejected_reason=?,updated_at=? WHERE id=?').run('rejected', reason, now(), so.id);
          addEvent(so.order_id, so.id, 'rejected', 'Seller rejected the order', reason, 'seller');
          notify(order.customer_id, `${shop.name} could not accept your order`, `${so.code}: ${reason}. Any payment will be refunded separately.`, 'order', `#/orders/${order.code}`);
          if (order.payment_status === 'paid') {
            db.prepare('INSERT INTO nb_refunds(id,return_id,order_id,amount_paise,status,reference,created_at,updated_at) VALUES(?,NULL,?,?,?,NULL,?,?)')
              .run(uid(), order.id, so.total_paise, 'processing', now(), now());
          }
          message = 'Order rejected and reserved stock released.';
        } else if (action === 'prepare') {
          if (so.status !== 'accepted') fail(409, 'Accept the order before marking it as preparing.');
          db.prepare('UPDATE nb_seller_orders SET status=?,updated_at=? WHERE id=?').run('preparing', now(), so.id);
          addEvent(so.order_id, so.id, 'preparing', 'Preparing order', `${shop.name} started packing your items.`, 'seller');
          notify(order.customer_id, 'Your order is being prepared', `${so.code}: ${shop.name} started packing. Online cancellation is no longer available; use support if something is wrong.`, 'order', `#/orders/${order.code}`);
          message = 'Order moved to preparing.';
        } else if (action === 'ready') {
          if (so.status !== 'preparing') fail(409, 'Mark the order as preparing first.');
          db.prepare('UPDATE nb_seller_orders SET status=?,ready_at=?,updated_at=? WHERE id=?').run('ready', now(), now(), so.id);
          addEvent(so.order_id, so.id, 'ready', so.fulfillment === 'pickup' ? 'Ready for pickup' : 'Ready for dispatch', so.fulfillment === 'pickup' ? 'Show your collection code at the counter.' : 'Choose delivery by your own rider or request a NearBuy runner.', 'seller');
          notify(order.customer_id, so.fulfillment === 'pickup' ? 'Ready for pickup' : 'Your order is packed', so.fulfillment === 'pickup' ? `${so.code} is ready at ${shop.name}. Your collection code is on the order page.` : `${so.code} is packed and waiting for dispatch.`, 'order', `#/orders/${order.code}`);
          message = 'Order marked ready.';
        } else if (action === 'request_runner') {
          if (so.status !== 'ready') fail(409, 'The order must be packed and ready first.');
          if (so.fulfillment !== 'delivery') fail(409, 'This order is set to store pickup.');
          const address = JSON.parse(order.address_json);
          const runnerRows = db.prepare(`SELECT r.*, u.name FROM nb_runners r JOIN nb_users u ON u.id=r.user_id
            WHERE r.status='online' AND r.active=1 AND r.lat IS NOT NULL AND r.lng IS NOT NULL`).all();
          const busy = new Set(db.prepare(`SELECT a.runner_id FROM nb_delivery_assignments a JOIN nb_seller_orders x ON x.id=a.seller_order_id
            WHERE a.status='accepted' AND x.status NOT IN ('delivered','completed','cancelled','rejected')`).all().map((r) => r.runner_id));
          const declined = new Set(db.prepare("SELECT runner_id FROM nb_delivery_assignments WHERE seller_order_id=? AND status='declined'").all(so.id).map((r) => r.runner_id));
          const eligible = runnerRows.filter((r) => !busy.has(r.user_id) && !declined.has(r.user_id))
            .map((r) => ({ ...r, distance: haversineKm(shop.lat, shop.lng, r.lat, r.lng) || 0 }))
            .filter((r) => r.distance <= 10)
            .sort((a, b) => a.distance - b.distance);
          if (!eligible.length) {
            fail(409, 'No NearBuy runner is free right now. You can deliver this order with your own rider, or try again in a few minutes.', {
              alternatives: ['Use my own rider (deliver myself)', 'Try requesting a runner again later']
            });
          }
          const offerSeconds = Number(process.env.DELIVERY_OFFER_SECONDS || 180);
          for (const runner of eligible.slice(0, 3)) {
            const payout = Math.max(3500, Math.min(15000, 3000 + Math.round(runner.distance * 900)));
            db.prepare(`INSERT INTO nb_delivery_assignments(id,seller_order_id,shop_id,runner_id,status,payout_paise,distance_km,created_at,expires_at,responded_at,picked_up_at,delivered_at)
              VALUES(?,?,?,?, 'offered', ?,?,?,?,NULL,NULL,NULL)`).run(uid(), so.id, shop.id, runner.user_id, payout,
              Math.round(runner.distance * 100) / 100, now(), new Date(Date.now() + offerSeconds * 1000).toISOString());
            notify(runner.user_id, 'New delivery offer', `${so.code} · ${shop.name} · ₹${Math.round(payout / 100)} payout. Open the delivery console to accept.`, 'runner', '#/delivery');
          }
          db.prepare('UPDATE nb_seller_orders SET status=?,updated_at=? WHERE id=?').run('runner_requested', now(), so.id);
          addEvent(so.order_id, so.id, 'runner_requested', 'Finding a delivery partner', `${eligible.length} nearby runner(s) offered this delivery.`, 'seller');
          notify(order.customer_id, 'Finding a delivery partner', `${so.code}: ${shop.name} has requested a NearBuy runner.`, 'order', `#/orders/${order.code}`);
          message = `Runner request sent to ${Math.min(3, eligible.length)} nearby partner(s). Offers expire in ${Math.round(offerSeconds / 60)} minute(s).`;
        } else if (action === 'self_deliver') {
          if (so.status !== 'ready' || so.fulfillment !== 'delivery') fail(409, 'Only a ready delivery order can be dispatched.');
          db.prepare('UPDATE nb_seller_orders SET status=?,updated_at=? WHERE id=?').run('out_for_delivery', now(), so.id);
          addEvent(so.order_id, so.id, 'out_for_delivery', 'Out for delivery', `${shop.name} is delivering this order with its own rider.`, 'seller');
          notify(order.customer_id, 'Out for delivery', `${so.code} left ${shop.name} with the shop’s own rider. Share your delivery OTP only after you receive the items.`, 'order', `#/orders/${order.code}`);
          message = 'Order dispatched with your own rider. Ask the customer for their delivery OTP on arrival.';
        } else if (action === 'deliver') {
          if (so.fulfillment !== 'delivery') fail(409, 'Use complete_pickup for a store pickup order.');
          if (so.status !== 'out_for_delivery') fail(409, 'The order must be out for delivery before handover.');
          if (so.runner_id) fail(409, 'A NearBuy runner is assigned; only that partner can complete this delivery.');
          if (!safeEqual(deriveCode('delivery', so.id, 6), String(payload.otp || ''))) {
            db.prepare('UPDATE nb_seller_orders SET delivery_attempts=delivery_attempts+1 WHERE id=?').run(so.id);
            fail(400, 'That delivery OTP is not correct. Ask the customer to read it from their order page.');
          }
          db.prepare('UPDATE nb_seller_orders SET status=?,delivered_at=?,updated_at=? WHERE id=?').run('delivered', now(), now(), so.id);
          addEvent(so.order_id, so.id, 'delivered', 'Delivered', 'Delivery OTP verified at the doorstep.', 'seller');
          notify(order.customer_id, 'Order delivered', `${so.code} was handed over after OTP verification. Rate your experience in Orders.`, 'order', `#/orders/${order.code}`);
          syncParentPayment(order.id);
          message = 'Delivery completed after OTP verification.';
        } else if (action === 'complete_pickup') {
          if (so.fulfillment !== 'pickup' || so.status !== 'ready') fail(409, 'This order is not ready for collection.');
          if (!safeEqual(deriveCode('pickup', so.id, 6), String(payload.otp || ''))) {
            fail(400, 'That collection code is not correct. Ask the customer to read it from their order page.');
          }
          db.prepare('UPDATE nb_seller_orders SET status=?,delivered_at=?,completed_at=?,updated_at=? WHERE id=?').run('completed', now(), now(), now(), so.id);
          addEvent(so.order_id, so.id, 'completed', 'Collected from store', 'Collection code verified at the counter.', 'seller');
          notify(order.customer_id, 'Order collected', `${so.code} was collected from ${shop.name}. Thanks for shopping local!`, 'order', `#/orders/${order.code}`);
          syncParentPayment(order.id);
          message = 'Pickup completed after collection-code verification.';
        } else if (action === 'mark_paid') {
          if (!['delivered', 'completed'].includes(so.status)) fail(409, 'Payment can only be recorded after handover.');
          db.prepare("UPDATE nb_payment_records SET status='paid',updated_at=? WHERE order_id=?").run(now(), order.id);
          db.prepare("UPDATE nb_orders SET payment_status='paid',updated_at=? WHERE id=?").run(now(), order.id);
          notify(order.customer_id, 'Payment recorded', `Cash payment for ${order.code} has been recorded by ${shop.name}.`, 'payment', `#/orders/${order.code}`);
          message = 'Cash payment recorded.';
        } else if (action === 'cancel') {
          if (!['placed', 'accepted'].includes(so.status)) fail(409, 'This order can no longer be cancelled by the seller.');
          if (!str(reason, 3, 200)) fail(400, 'Give a reason for cancelling.');
          cancelSellerOrder(so, reason, 'seller');
          message = 'Order cancelled.';
        } else {
          fail(400, 'Unknown seller action.');
        }
        audit('seller', s.user_id, `seller_${action}`, 'seller_order', so.id, `${so.code}${reason ? ' · ' + reason : ''}`);
      });
      const updated = db.prepare('SELECT * FROM nb_seller_orders WHERE id=?').get(so.id);
      send(res, 200, { message, status: updated.status, statusLabel: STATUS_LABELS[updated.status] || updated.status });
      return true;
    }

    if (base === '/api/partner' && route === '/seller/products' && method === 'GET') {
      const s = requirePartner(['seller']);
      const shop = sellerShopContext(s);
      const products = db.prepare('SELECT * FROM nb_products WHERE shop_id=? ORDER BY category_slug, name').all(shop.id).map((p) => ({
        id: p.id, name: p.name, brand: p.brand, category: p.category_slug, emoji: p.emoji, price: p.price_paise,
        mrp: p.mrp_paise, stock: p.stock, reserved: p.reserved, available: Math.max(0, p.stock - p.reserved),
        lowAt: p.low_stock, active: Boolean(p.active), unit: p.unit, rating: p.rating, reviewCount: p.review_count
      }));
      send(res, 200, { products, shop: { name: shop.name, emoji: shop.emoji } });
      return true;
    }

    if (base === '/api/partner' && route.match(/^\/seller\/products\/[a-zA-Z0-9_-]+$/) && method === 'PATCH') {
      const s = requirePartner(['seller']);
      const shop = sellerShopContext(s);
      const product = db.prepare('SELECT * FROM nb_products WHERE id=? AND shop_id=?').get(route.split('/')[3], shop.id);
      if (!product) fail(404, 'Product not found in your catalogue');
      const nextStock = payload.stock !== undefined ? clampInt(payload.stock, 0, 100000) : product.stock;
      const nextPrice = payload.price !== undefined ? Math.round(Number(payload.price)) : product.price_paise;
      if (payload.price !== undefined && (!Number.isFinite(nextPrice) || nextPrice < 100 || nextPrice > 1000000)) fail(400, 'Price must be between ₹1 and ₹10,000.');
      if (nextPrice > (payload.mrp !== undefined ? Math.round(Number(payload.mrp)) : product.mrp_paise || Infinity)) fail(400, 'Selling price cannot be above MRP.');
      const active = payload.active !== undefined ? (payload.active ? 1 : 0) : product.active;
      db.prepare('UPDATE nb_products SET stock=?,price_paise=?,mrp_paise=?,active=? WHERE id=? AND shop_id=?')
        .run(nextStock, nextPrice, payload.mrp !== undefined ? Math.round(Number(payload.mrp)) : product.mrp_paise, active, product.id, shop.id);
      audit('seller', s.user_id, 'product_updated', 'product', product.id, `${product.name}: stock ${product.stock}→${nextStock}, price ${product.price_paise}→${nextPrice}, active ${active}`);
      send(res, 200, { message: 'Catalogue updated. The customer storefront reads this immediately.' });
      return true;
    }

    if (base === '/api/partner' && route.match(/^\/seller\/receipt\/[A-Za-z0-9-]+$/) && method === 'GET') {
      const s = requirePartner(['seller']);
      const shop = sellerShopContext(s);
      const so = sellerOrderOwned(decodeURIComponent(route.split('/')[3]), shop);
      const order = db.prepare('SELECT * FROM nb_orders WHERE id=?').get(so.order_id);
      const customer = db.prepare('SELECT * FROM nb_users WHERE id=?').get(order.customer_id);
      sendHtml(res, 200, receiptHtml(order, so, shop, customer, 'seller'));
      return true;
    }

    if (base === '/api/partner' && route === '/seller/returns' && method === 'GET') {
      const s = requirePartner(['seller']);
      const shop = sellerShopContext(s);
      const rows = db.prepare(`SELECT r.*, o.code AS order_code, so.code AS seller_order_code, i.name AS item_name, i.emoji AS item_emoji, i.qty AS item_qty
        FROM nb_returns r JOIN nb_orders o ON o.id=r.order_id JOIN nb_seller_orders so ON so.id=r.seller_order_id
        JOIN nb_order_items i ON i.id=r.item_id WHERE so.shop_id=? ORDER BY r.created_at DESC`).all(shop.id);
      send(res, 200, { returns: rows.map((r) => ({
        code: r.code, status: r.status, reason: r.reason, comment: r.comment, amount: r.refund_amount_paise,
        images: JSON.parse(r.images_json || '[]'), createdAt: r.created_at, orderCode: r.order_code,
        sellerOrderCode: r.seller_order_code, item: { name: r.item_name, emoji: r.item_emoji, qty: r.item_qty }
      })) });
      return true;
    }

    if (base === '/api/partner' && route.match(/^\/seller\/returns\/[A-Za-z0-9-]+\/action$/) && method === 'POST') {
      const s = requirePartner(['seller']);
      const shop = sellerShopContext(s);
      const code = decodeURIComponent(route.split('/')[3]);
      const ret = db.prepare(`SELECT r.*, so.shop_id, i.product_id, i.qty FROM nb_returns r JOIN nb_seller_orders so ON so.id=r.seller_order_id
        JOIN nb_order_items i ON i.id=r.item_id WHERE r.code=? AND so.shop_id=?`).get(code, shop.id);
      if (!ret) fail(404, 'Return request not found for your shop');
      const action = String(payload.action || '');
      const note = String(payload.note || '').trim().slice(0, 300);
      const map = { approve: 'approved', reject: 'rejected', complete: 'completed', review: 'under_review', process: 'processing' };
      if (!map[action]) fail(400, 'Unknown return action');
      if (['completed', 'rejected'].includes(ret.status)) fail(409, 'This return is already closed.');
      transaction(() => {
        db.prepare('UPDATE nb_returns SET status=?,decision_note=?,updated_at=? WHERE id=?').run(map[action], note || ret.decision_note, now(), ret.id);
        const refundStatus = action === 'approve' ? 'processing' : action === 'complete' ? 'completed' : action === 'reject' ? 'rejected' : action === 'review' ? 'under_review' : 'processing';
        db.prepare('UPDATE nb_refunds SET status=?,updated_at=? WHERE return_id=?').run(refundStatus, now(), ret.id);
        if (action === 'complete') {
          db.prepare('UPDATE nb_products SET stock=stock+? WHERE id=?').run(ret.qty, ret.product_id);
        }
        const order = db.prepare('SELECT * FROM nb_orders WHERE id=?').get(ret.order_id);
        addEvent(ret.order_id, ret.seller_order_id, `return_${map[action]}`, `Return ${map[action]}`, note || null, 'seller');
        notify(order.customer_id, `Return ${map[action]}`, `${ret.code}: ${shop.name} marked your return as ${map[action].replace('_', ' ')}.${note ? ' ' + note : ''}`, 'return', '#/account/returns');
      });
      audit('seller', s.user_id, `return_${action}`, 'return', ret.id, note);
      send(res, 200, { message: `Return ${map[action].replace('_', ' ')}.`, status: map[action] });
      return true;
    }

    /* ================================================================== */
    /* Runner console                                                     */
    /* ================================================================== */

    if (base === '/api/partner' && route === '/runner/overview' && method === 'GET') {
      const s = requirePartner(['runner']);
      const runner = db.prepare('SELECT * FROM nb_runners WHERE user_id=?').get(s.user_id);
      if (!runner) fail(403, 'No delivery profile is linked to this account.');
      const offers = db.prepare(`SELECT a.* FROM nb_delivery_assignments a JOIN nb_seller_orders so ON so.id=a.seller_order_id
        WHERE a.runner_id=? AND a.status='offered' AND a.expires_at>? AND so.status='runner_requested' ORDER BY a.created_at DESC`)
        .all(s.user_id, now()).map((a) => {
          const so = db.prepare('SELECT * FROM nb_seller_orders WHERE id=?').get(a.seller_order_id);
          const shop = db.prepare('SELECT * FROM nb_shops WHERE id=?').get(a.shop_id);
          const count = db.prepare('SELECT SUM(qty) AS n FROM nb_order_items WHERE seller_order_id=?').get(so.id);
          return {
            id: a.id, orderCode: so.code, shop: {	name: shop.name, emoji: shop.emoji, locality: shop.locality },
            payout: a.payout_paise, distanceKm: a.distance_km, expiresAt: a.expires_at, itemCount: Number(count?.n || 0),
            deliveryArea: 'Customer address is shared after you accept.'
          };
        });
      const jobs = db.prepare(`SELECT a.* FROM nb_delivery_assignments a JOIN nb_seller_orders so ON so.id=a.seller_order_id
        WHERE a.runner_id=? AND a.status IN ('accepted','picked_up','delivered') ORDER BY a.created_at DESC LIMIT 20`).all(s.user_id);
      const active = jobs.filter((j) => j.status === 'accepted' || (j.status === 'picked_up')).map((j) => {
        const so = db.prepare('SELECT * FROM nb_seller_orders WHERE id=?').get(j.seller_order_id);
        const order = db.prepare('SELECT * FROM nb_orders WHERE id=?').get(so.order_id);
        const shop = db.prepare('SELECT * FROM nb_shops WHERE id=?').get(j.shop_id);
        const customer = db.prepare('SELECT name, phone FROM nb_users WHERE id=?').get(order.customer_id);
        const address = JSON.parse(order.address_json);
        const items = db.prepare('SELECT name,qty FROM nb_order_items WHERE seller_order_id=?').all(so.id);
        return {
          assignmentId: j.id, orderCode: so.code, status: so.status, shop: { name: shop.name, emoji: shop.emoji, address: shop.address, locality: shop.locality, phone: shop.phone },
          payout: j.payout_paise, customer: { name: customer.name, phoneMasked: maskedPhone(customer.phone) },
          address, items: items.map((i) => ({ name: i.name, qty: i.qty })),
          canPickup: so.status === 'runner_assigned', canDeliver: so.status === 'picked_up'
        };
      });
      const delivered = jobs.filter((j) => j.status === 'delivered');
      const earnings = delivered.reduce((t, j) => t + j.payout_paise, 0);
      send(res, 200, {
        runner: { status: runner.status, vehicle: runner.vehicle, rating: runner.rating, completed: runner.completed, lat: runner.lat, lng: runner.lng },
        offers, active, history: delivered.slice(0, 6).map((j) => ({ payout: j.payout_paise, at: j.delivered_at, distanceKm: j.distance_km })),
        earnings, activeJobCount: active.length
      });
      return true;
    }

    if (base === '/api/partner' && route === '/runner/status' && method === 'POST') {
      const s = requirePartner(['runner']);
      const status = payload.status === 'online' ? 'online' : 'offline';
      const lat = Number.isFinite(Number(payload.lat)) ? Number(payload.lat) : null;
      const lng = Number.isFinite(Number(payload.lng)) ? Number(payload.lng) : null;
      db.prepare('UPDATE nb_runners SET status=?,lat=COALESCE(?,lat),lng=COALESCE(?,lng) WHERE user_id=?').run(status, lat, lng, s.user_id);
      send(res, 200, { message: `You are now ${status}.`, status });
      return true;
    }

    if (base === '/api/partner' && route.match(/^\/runner\/offers\/[a-zA-Z0-9-]+\/(accept|decline)$/) && method === 'POST') {
      const s = requirePartner(['runner']);
      const [, , , id, action] = route.split('/');
      const offer = db.prepare("SELECT * FROM nb_delivery_assignments WHERE id=? AND runner_id=? AND status='offered'").get(id, s.user_id);
      if (!offer) fail(404, 'This offer is no longer available.');
      if (new Date(offer.expires_at).getTime() < Date.now()) fail(409, 'This offer has expired. The seller can request a runner again.');
      const so = db.prepare('SELECT * FROM nb_seller_orders WHERE id=?').get(offer.seller_order_id);
      if (!so || so.status !== 'runner_requested') fail(409, 'This delivery is no longer waiting for a runner.');
      if (action === 'decline') {
        db.prepare("UPDATE nb_delivery_assignments SET status='declined',responded_at=? WHERE id=?").run(now(), offer.id);
        send(res, 200, { message: 'Offer declined. It stays open for other partners.' });
        return true;
      }
      const active = db.prepare(`SELECT 1 FROM nb_delivery_assignments a JOIN nb_seller_orders x ON x.id=a.seller_order_id
        WHERE a.runner_id=? AND a.status='accepted' AND x.status NOT IN ('delivered','completed','cancelled','rejected')`).get(s.user_id);
      if (active) fail(409, 'Finish your current delivery before accepting another one.');
      transaction(() => {
        db.prepare("UPDATE nb_delivery_assignments SET status='accepted',responded_at=? WHERE id=? AND status='offered'").run(now(), offer.id);
        db.prepare("UPDATE nb_delivery_assignments SET status='expired' WHERE seller_order_id=? AND id<>? AND status='offered'").run(offer.id, offer.id);
        db.prepare('UPDATE nb_seller_orders SET status=?,runner_id=?,updated_at=? WHERE id=?').run('runner_assigned', s.user_id, now(), so.id);
        addEvent(so.order_id, so.id, 'runner_assigned', 'Delivery partner assigned', `${s.name} will collect your order from the shop.`, 'runner');
        const order = db.prepare('SELECT * FROM nb_orders WHERE id=?').get(so.order_id);
        notify(order.customer_id, 'Delivery partner assigned', `${s.name} is collecting ${so.code} from the shop. Your delivery OTP is on the order page.`, 'order', `#/orders/${order.code}`);
      });
      send(res, 200, { message: 'Delivery accepted. Collect the order from the shop and use the seller’s handover PIN.' });
      return true;
    }

    if (base === '/api/partner' && route === '/runner/jobs' && method === 'GET') {
      const s = requirePartner(['runner']);
      const rows = db.prepare("SELECT * FROM nb_delivery_assignments WHERE runner_id=? AND status IN ('accepted','picked_up','delivered') ORDER BY created_at DESC LIMIT 30").all(s.user_id);
      send(res, 200, { jobs: rows.map((a) => ({ id: a.id, status: a.status, payout: a.payout_paise, distanceKm: a.distance_km, createdAt: a.created_at, deliveredAt: a.delivered_at })) });
      return true;
    }

    if (base === '/api/partner' && route.match(/^\/runner\/jobs\/[a-zA-Z0-9-]+\/action$/) && method === 'POST') {
      const s = requirePartner(['runner']);
      const id = route.split('/')[3];
      const assignment = db.prepare("SELECT * FROM nb_delivery_assignments WHERE id=? AND runner_id=? AND status IN ('accepted','picked_up')").get(id, s.user_id);
      if (!assignment) fail(404, 'Active delivery not found.');
      const so = db.prepare('SELECT * FROM nb_seller_orders WHERE id=?').get(assignment.seller_order_id);
      if (!so || !['runner_assigned', 'picked_up', 'out_for_delivery'].includes(so.status)) fail(409, 'This delivery is no longer active.');
      const order = db.prepare('SELECT * FROM nb_orders WHERE id=?').get(so.order_id);
      const action = String(payload.action || '');
      let message = '';
      transaction(() => {
        if (action === 'arrived') {
          addEvent(so.order_id, so.id, 'runner_arrived', 'Delivery partner at the shop', `${s.name} reached ${db.prepare('SELECT name FROM nb_shops WHERE id=?').get(so.shop_id)?.name}.`, 'runner');
          message = 'Shop arrival recorded.';
        } else if (action === 'picked_up') {
          if (so.status !== 'runner_assigned') fail(409, 'This order has already been picked up.');
          if (!safeEqual(deriveCode('handover', so.id, 4), String(payload.pickupPin || ''))) fail(400, 'The seller’s handover PIN is not correct.');
          db.prepare("UPDATE nb_delivery_assignments SET status='picked_up',picked_up_at=? WHERE id=?").run(now(), assignment.id);
          db.prepare('UPDATE nb_seller_orders SET status=?,updated_at=? WHERE id=?').run('picked_up', now(), so.id);
          db.prepare('INSERT INTO nb_delivery_tracking(seller_order_id,status,note,lat,lng,actor,created_at) VALUES(?,?,?,?,?,?,?)')
            .run(so.id, 'picked_up', 'Collected from shop after handover PIN verification', Number(payload.lat) || null, Number(payload.lng) || null, 'runner', now());
          addEvent(so.order_id, so.id, 'picked_up', 'Order picked up', 'Handover PIN verified at the shop.', 'runner');
          notify(order.customer_id, 'Order picked up', `${s.name} collected ${so.code} and is on the way to you.`, 'order', `#/orders/${order.code}`);
          message = 'Pickup confirmed with the seller’s handover PIN.';
        } else if (action === 'out_for_delivery') {
          if (so.status !== 'picked_up') fail(409, 'Pick up the order first.');
          db.prepare('UPDATE nb_seller_orders SET status=?,updated_at=? WHERE id=?').run('out_for_delivery', now(), so.id);
          addEvent(so.order_id, so.id, 'out_for_delivery', 'Out for delivery', `${s.name} is on the way with your order.`, 'runner');
          notify(order.customer_id, 'Out for delivery', `${s.name} is on the way with ${so.code}. Keep your delivery OTP ready.`, 'order', `#/orders/${order.code}`);
          message = 'Marked out for delivery.';
        } else if (action === 'delivered') {
          if (so.status !== 'out_for_delivery') fail(409, 'Mark the order out for delivery before completing it.');
          if (!safeEqual(deriveCode('delivery', so.id, 6), String(payload.otp || ''))) {
            db.prepare('UPDATE nb_seller_orders SET delivery_attempts=delivery_attempts+1 WHERE id=?').run(so.id);
            fail(400, 'That delivery OTP is not correct. Ask the customer to read it from their order page.');
          }
          db.prepare("UPDATE nb_delivery_assignments SET status='delivered',delivered_at=? WHERE id=?").run(now(), assignment.id);
          db.prepare("UPDATE nb_seller_orders SET status='delivered',delivered_at=?,updated_at=? WHERE id=?").run(now(), now(), so.id);
          db.prepare('UPDATE nb_runners SET completed=completed+1 WHERE user_id=?').run(s.user_id);
          addEvent(so.order_id, so.id, 'delivered', 'Delivered', 'Delivery OTP verified by the customer at the doorstep.', 'runner');
          notify(order.customer_id, 'Order delivered', `${so.code} was delivered by ${s.name}. Rate your experience in Orders.`, 'order', `#/orders/${order.code}`);
          syncParentPayment(order.id);
          message = 'Delivery completed after OTP verification.';
        } else {
          fail(400, 'Unknown delivery action.');
        }
        audit('runner', s.user_id, `runner_${action}`, 'delivery', assignment.id, so.code);
      });
      send(res, 200, { message });
      return true;
    }

    if (base === '/api/partner' && route.match(/^\/runner\/jobs\/[a-zA-Z0-9-]+\/location$/) && method === 'POST') {
      const s = requirePartner(['runner']);
      const id = route.split('/')[3];
      const assignment = db.prepare("SELECT * FROM nb_delivery_assignments WHERE id=? AND runner_id=? AND status IN ('accepted','picked_up')").get(id, s.user_id);
      if (!assignment) fail(404, 'Active delivery not found.');
      const lat = Number(payload.lat);
      const lng = Number(payload.lng);
      if (!Number.isFinite(lat) || !Number.isFinite(lng) || Math.abs(lat) > 90 || Math.abs(lng) > 180) fail(400, 'A valid location is required.');
      db.prepare('UPDATE nb_runners SET lat=?,lng=? WHERE user_id=?').run(lat, lng, s.user_id);
      db.prepare('INSERT INTO nb_delivery_tracking(seller_order_id,status,note,lat,lng,actor,created_at) VALUES(?,?,?,?,?,?,?)')
        .run(assignment.seller_order_id, 'location', 'Runner shared a location', lat, lng, 'runner', now());
      send(res, 200, { message: 'Location shared with the customer.' });
      return true;
    }

    /* ================================================================== */
    /* Payments                                                            */
    /* ================================================================== */

    if (method === 'POST' && custRoute === '/payments/intent') {
      const s = requireCustomer(req);
      if (!GATEWAY.configured) fail(503, 'Online payment is not configured. This deployment has no Razorpay keys, so no payment can be started.');
      const order = orderByCode(String(payload.orderCode || ''), s.user_id);
      if (order.payment_status === 'paid') fail(409, 'There is nothing left to pay for this order.');
      const auth = Buffer.from(`${GATEWAY.keyId}:${GATEWAY.keySecret}`).toString('base64');
      let gatewayOrder;
      try {
        const resGateway = await fetch('https://api.razorpay.com/v1/orders', {
          method: 'POST',
          headers: { authorization: `Basic ${auth}`, 'content-type': 'application/json' },
          body: JSON.stringify({ amount: order.total_paise, currency: 'INR', receipt: order.code, notes: { nearbuyOrder: order.id } }),
          signal: AbortSignal.timeout(12000)
        });
        gatewayOrder = await resGateway.json();
        if (!resGateway.ok || !gatewayOrder.id) throw new Error(gatewayOrder?.error?.description || 'Gateway refused the order');
      } catch (err) {
        fail(502, `The payment gateway could not be reached: ${err.message}`);
      }
      db.prepare("UPDATE nb_payment_records SET provider='razorpay',status='created',reference=?,updated_at=? WHERE order_id=?")
        .run(gatewayOrder.id, now(), order.id);
      db.prepare("UPDATE nb_orders SET payment_method='online',updated_at=? WHERE id=?").run(now(), order.id);
      send(res, 201, { gatewayOrderId: gatewayOrder.id, keyId: GATEWAY.keyId, amount: order.total_paise, orderCode: order.code, currency: 'INR' });
      return true;
    }

    /* ================================================================== */
    /* Admin console API                                                   */
    /* ================================================================== */

    if (base === '/api/admin' && route === '/login' && method === 'POST') {
      rateLimit(`admin-login:${clientIp(req)}`, 10, 900e3);
      const email = String(payload.email || '').trim().toLowerCase();
      const user = db.prepare("SELECT * FROM nb_users WHERE email=? AND role='admin'").get(email);
      const ok = user ? checkPassword(payload.password || '', user.password_hash) : checkPassword(payload.password || '', makePassword('invalid-password'));
      if (!user || !ok) fail(401, 'Those administrator details are not valid.');
      const sess = startSession(req, user, ADMIN_COOKIE);
      audit('admin', user.id, 'admin_login', 'user', user.id, 'Administrator signed in');
      send(res, 200, { user: { id: user.id, name: user.name, email: user.email, role: user.role, csrf: sess.csrf } }, { 'Set-Cookie': sess.cookie });
      return true;
    }

    if (base === '/api/admin' && route === '/logout' && method === 'POST') {
      const s = sessionFor(req, ADMIN_COOKIE);
      if (s) db.prepare('DELETE FROM nb_sessions WHERE token_hash=?').run(sha(s.token));
      send(res, 200, { ok: true }, { 'Set-Cookie': `${ADMIN_COOKIE}=; ${cookieAttrs(req)}; Max-Age=0` });
      return true;
    }

    const requireAdmin = () => requireUser(req, ['admin'], ADMIN_COOKIE);

    if (base === '/api/admin' && route === '/me' && method === 'GET') {
      const s = sessionFor(req, ADMIN_COOKIE);
      send(res, 200, { user: s && s.role === 'admin' ? { id: s.user_id, name: s.name, email: s.email, csrf: s.csrf, role: 'admin' } : null });
      return true;
    }

    if (base === '/api/admin' && route === '/overview' && method === 'GET') {
      requireAdmin();
      const count = (sql, ...p) => Number(db.prepare(sql).get(...p).n || 0);
      send(res, 200, {
        counts: {
          customers: count("SELECT COUNT(*) AS n FROM nb_users WHERE role='customer'"),
          shops: count('SELECT COUNT(*) AS n FROM nb_shops'),
          products: count('SELECT COUNT(*) AS n FROM nb_products'),
          orders: count('SELECT COUNT(*) AS n FROM nb_orders'),
          openTickets: count("SELECT COUNT(*) AS n FROM nb_tickets WHERE status NOT IN ('resolved','closed')"),
          pendingRefunds: count("SELECT COUNT(*) AS n FROM nb_refunds WHERE status NOT IN ('completed','rejected')"),
          pendingReturns: count("SELECT COUNT(*) AS n FROM nb_returns WHERE status NOT IN ('completed','rejected')"),
          reviews: count('SELECT COUNT(*) AS n FROM nb_reviews')
        },
        revenue: Number(db.prepare("SELECT COALESCE(SUM(total_paise),0) AS n FROM nb_orders WHERE payment_status='paid'").get().n),
        gmv: Number(db.prepare("SELECT COALESCE(SUM(total_paise),0) AS n FROM nb_orders WHERE status NOT IN ('cancelled')").get().n),
        recentOrders: db.prepare('SELECT * FROM nb_orders ORDER BY created_at DESC LIMIT 10').all().map((o) => orderSummary(o)),
        recentEnquiries: db.prepare('SELECT * FROM nb_enquiries ORDER BY created_at DESC LIMIT 10').all()
      });
      return true;
    }

    if (base === '/api/admin' && route === '/customers' && method === 'GET') {
      requireAdmin();
      const rows = db.prepare("SELECT u.id,u.name,u.email,u.phone,u.status,u.is_demo,u.created_at, (SELECT COUNT(*) FROM nb_orders o WHERE o.customer_id=u.id) AS orders FROM nb_users u WHERE u.role='customer' ORDER BY u.created_at DESC LIMIT 200").all();
      send(res, 200, { customers: rows });
      return true;
    }

    if (base === '/api/admin' && route === '/shops' && method === 'GET') {
      requireAdmin();
      const rows = db.prepare(`SELECT s.*, u.email AS owner_email,
        (SELECT COUNT(*) FROM nb_products p WHERE p.shop_id=s.id) AS products,
        (SELECT COUNT(*) FROM nb_seller_orders so WHERE so.shop_id=s.id) AS orders
        FROM nb_shops s LEFT JOIN nb_users u ON u.id=s.owner_user_id ORDER BY s.name`).all();
      send(res, 200, { shops: rows.map((s) => ({ ...shopCard(s, null), ownerEmail: s.owner_email, orders: Number(s.orders || 0) })) });
      return true;
    }

    if (base === '/api/admin' && route === '/orders' && method === 'GET') {
      requireAdmin();
      const rows = db.prepare('SELECT * FROM nb_orders ORDER BY created_at DESC LIMIT 100').all();
      send(res, 200, { orders: rows.map((o) => orderSummary(o)) });
      return true;
    }

    if (base === '/api/admin' && route === '/returns' && method === 'GET') {
      requireAdmin();
      const rows = db.prepare(`SELECT r.*, o.code AS order_code, s.name AS shop_name, i.name AS item_name
        FROM nb_returns r JOIN nb_orders o ON o.id=r.order_id JOIN nb_seller_orders so ON so.id=r.seller_order_id
        JOIN nb_shops s ON s.id=so.shop_id JOIN nb_order_items i ON i.id=r.item_id ORDER BY r.created_at DESC LIMIT 100`).all();
      const refunds = db.prepare('SELECT * FROM nb_refunds ORDER BY created_at DESC LIMIT 100').all();
      send(res, 200, { returns: rows, refunds });
      return true;
    }

    if (base === '/api/admin' && route.match(/^\/refunds\/[a-zA-Z0-9-]+\/status$/) && method === 'POST') {
      const admin = requireAdmin();
      const id = route.split('/')[2];
      const refund = db.prepare('SELECT * FROM nb_refunds WHERE id=?').get(id);
      if (!refund) fail(404, 'Refund not found');
      const allowed = ['requested', 'under_review', 'approved', 'processing', 'completed', 'rejected'];
      if (!allowed.includes(payload.status)) fail(400, 'Choose a valid refund status.');
      if (payload.status === 'completed' && refund.status !== 'processing' && refund.status !== 'approved') {
        fail(409, 'A refund can only be completed from approved or processing.');
      }
      db.prepare('UPDATE nb_refunds SET status=?,reference=?,updated_at=? WHERE id=?')
        .run(payload.status, payload.reference ? String(payload.reference).slice(0, 120) : refund.reference, now(), id);
      if (refund.return_id) db.prepare('UPDATE nb_returns SET status=?,updated_at=? WHERE id=?').run(payload.status === 'completed' ? 'completed' : payload.status === 'rejected' ? 'rejected' : 'processing', now(), refund.return_id);
      const order = db.prepare('SELECT * FROM nb_orders WHERE id=?').get(refund.order_id);
      if (order) notify(order.customer_id, `Refund ${payload.status.replace('_', ' ')}`, `₹${Math.round(refund.amount_paise / 100)} for ${order.code} is now ${payload.status.replace('_', ' ')}.`, 'refund', '#/account/returns');
      audit('admin', admin.user_id, 'refund_status', 'refund', id, `${refund.status} → ${payload.status}`);
      send(res, 200, { message: `Refund marked ${payload.status}.` });
      return true;
    }

    if (base === '/api/admin' && route === '/reviews' && method === 'GET') {
      requireAdmin();
      const rows = db.prepare(`SELECT r.*, u.name AS customer_name, s.name AS shop_name, p.name AS product_name
        FROM nb_reviews r JOIN nb_users u ON u.id=r.customer_id LEFT JOIN nb_shops s ON s.id=r.shop_id LEFT JOIN nb_products p ON p.id=r.product_id
        ORDER BY r.created_at DESC LIMIT 200`).all();
      send(res, 200, { reviews: rows.map((r) => ({ ...r, customer_name: r.customer_name, shop_name: r.shop_name, product_name: r.product_name })) });
      return true;
    }

    if (base === '/api/admin' && route.match(/^\/reviews\/[a-zA-Z0-9-]+\/status$/) && method === 'POST') {
      const admin = requireAdmin();
      const id = route.split('/')[2];
      const review = db.prepare('SELECT * FROM nb_reviews WHERE id=?').get(id);
      if (!review) fail(404, 'Review not found');
      if (!['published', 'hidden', 'reported'].includes(payload.status)) fail(400, 'Choose published, hidden or reported.');
      db.prepare('UPDATE nb_reviews SET status=? WHERE id=?').run(payload.status, id);
      audit('admin', admin.user_id, 'review_moderated', 'review', id, `${review.status} → ${payload.status}`);
      send(res, 200, { message: `Review marked ${payload.status}.` });
      return true;
    }

    if (base === '/api/admin' && route === '/tickets' && method === 'GET') {
      requireAdmin();
      const rows = db.prepare(`SELECT t.*, u.name AS customer_name, u.email AS customer_email FROM nb_tickets t
        JOIN nb_users u ON u.id=t.customer_id ORDER BY t.created_at DESC LIMIT 100`).all();
      send(res, 200, { tickets: rows });
      return true;
    }

    if (base === '/api/admin' && route.match(/^\/tickets\/[A-Za-z0-9-]+\/(reply|status)$/) && method === 'POST') {
      const admin = requireAdmin();
      const code = decodeURIComponent(route.split('/')[2]);
      const ticket = db.prepare('SELECT * FROM nb_tickets WHERE code=?').get(code);
      if (!ticket) fail(404, 'Ticket not found');
      if (route.endsWith('/reply')) {
        if (!str(payload.body, 2, 3000)) fail(400, 'Write a reply.');
        transaction(() => {
          db.prepare('INSERT INTO nb_ticket_messages(id,ticket_id,author_role,author_name,body,created_at) VALUES(?,?,?,?,?,?)')
            .run(uid(), ticket.id, 'agent', admin.name, payload.body.trim(), now());
          db.prepare("UPDATE nb_tickets SET status='awaiting_customer',updated_at=? WHERE id=?").run(now(), ticket.id);
          notify(ticket.customer_id, 'Support replied to your ticket', `${code}: ${admin.name} replied. Open Help → My tickets to read it.`, 'support', `#/help/tickets/${code}`);
        });
        send(res, 200, { message: 'Reply sent and the customer was notified.' });
      } else {
        if (!['open', 'assigned', 'in_progress', 'awaiting_customer', 'resolved', 'closed'].includes(payload.status)) fail(400, 'Invalid ticket status.');
        db.prepare('UPDATE nb_tickets SET status=?,updated_at=? WHERE id=?').run(payload.status, now(), ticket.id);
        send(res, 200, { message: `Ticket ${payload.status}.` });
      }
      return true;
    }

    if (base === '/api/admin' && route === '/coupons' && method === 'GET') {
      requireAdmin();
      send(res, 200, { coupons: db.prepare('SELECT * FROM nb_coupons ORDER BY ends_at DESC').all(), offers: activeOffers(null) });
      return true;
    }

    if (base === '/api/admin' && route === '/coupons' && method === 'POST') {
      const admin = requireAdmin();
      const code = String(payload.code || '').trim().toUpperCase();
      if (!/^[A-Z0-9-]{3,24}$/.test(code)) fail(400, 'Coupon code must be 3–24 letters, numbers or dashes.');
      if (db.prepare('SELECT 1 FROM nb_coupons WHERE code=?').get(code)) fail(409, 'That coupon code already exists.');
      const type = ['percent', 'fixed', 'free_delivery'].includes(payload.type) ? payload.type : 'percent';
      const value = type === 'fixed' ? Math.round(Number(payload.value || 0)) : clampInt(payload.value || 0, 0, 100);
      const minOrder = Math.round(Number(payload.minOrderPaise || 0));
      const endsAt = new Date(Date.now() + clampInt(payload.days || 30, 1, 365) * 864e5).toISOString();
      const shop = payload.shopSlug ? db.prepare('SELECT id FROM nb_shops WHERE slug=?').get(payload.shopSlug) : null;
      db.prepare(`INSERT INTO nb_coupons(code,title,description,type,value,min_order_paise,max_discount_paise,shop_id,starts_at,ends_at,usage_limit,used_count,per_customer_limit,active)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,0,1,1)`).run(code, String(payload.title || code).slice(0, 120), String(payload.description || '').slice(0, 300),
        type, value, minOrder, payload.maxDiscountPaise ? Math.round(Number(payload.maxDiscountPaise)) : null, shop?.id || null, now(), endsAt,
        payload.usageLimit ? clampInt(payload.usageLimit, 1, 100000) : null);
      audit('admin', admin.user_id, 'coupon_created', 'coupon', code, `${type} ${value}`);
      send(res, 201, { message: `Coupon ${code} created and live from now.` });
      return true;
    }

    if (base === '/api/admin' && route === '/banners' && method === 'GET') {
      requireAdmin();
      send(res, 200, { banners: db.prepare('SELECT * FROM nb_banners ORDER BY sort').all() });
      return true;
    }

    if (base === '/api/admin' && route === '/banners' && method === 'POST') {
      const admin = requireAdmin();
      if (!str(payload.title, 3, 120)) fail(400, 'A banner title is required.');
      db.prepare(`INSERT INTO nb_banners(id,title,subtitle,eyebrow,cta_label,cta_link,image_url,theme,active,sort)
        VALUES(?,?,?,?,?,?,?,?,?,?)`).run(uid(), payload.title.trim(), String(payload.subtitle || '').slice(0, 300),
        String(payload.eyebrow || '').slice(0, 80), String(payload.ctaLabel || 'Shop now').slice(0, 40),
        String(payload.ctaLink || '#/shops').slice(0, 200), String(payload.imageUrl || '').slice(0, 300) || null,
        ['blue', 'green', 'cyan', 'amber'].includes(payload.theme) ? payload.theme : 'blue', payload.active === false ? 0 : 1,
        clampInt(payload.sort || 10, 0, 100));
      audit('admin', admin.user_id, 'banner_created', 'banner', null, payload.title);
      send(res, 201, { message: 'Banner created.' });
      return true;
    }

    if (base === '/api/admin' && route === '/enquiries' && method === 'GET') {
      requireAdmin();
      send(res, 200, { enquiries: db.prepare('SELECT * FROM nb_enquiries ORDER BY created_at DESC LIMIT 100').all() });
      return true;
    }

    if (base === '/api/admin' && method === 'PATCH' && /^\/enquiries\/[A-Za-z0-9-]+$/.test(route)) {
      const admin = requireAdmin();
      const code = route.split('/')[2];
      const status = String(payload.status || '');
      if (!['open', 'in_review', 'closed'].includes(status)) fail(400, 'Unknown enquiry status.');
      const row = db.prepare('SELECT * FROM nb_enquiries WHERE code = ?').get(code);
      if (!row) fail(404, 'Enquiry not found.');
      db.prepare('UPDATE nb_enquiries SET status = ? WHERE code = ?').run(status, code);
      audit('admin', admin.user_id, 'enquiry_status', 'enquiry', code, `Enquiry ${code} → ${status}`);
      send(res, 200, { message: `Enquiry ${code} marked ${status.replace('_', ' ')}.` });
      return true;
    }

    if (base === '/api/admin' && route === '/audit' && method === 'GET') {
      requireAdmin();
      send(res, 200, { logs: db.prepare('SELECT * FROM nb_audit_logs ORDER BY id DESC LIMIT 200').all() });
      return true;
    }

    /* ================================================================== */
    /* Seller shop profile + catalogue management                          */
    /* ================================================================== */

    if (base === '/api/partner' && route === '/seller/shop' && method === 'GET') {
      const s = requirePartner(['seller']);
      const shop = sellerShopContext(s);
      send(res, 200, { shop: shopRow(shop) });
      return true;
    }

    if (base === '/api/partner' && route === '/seller/shop' && method === 'PATCH') {
      const s = requirePartner(['seller']);
      const shop = sellerShopContext(s);
      const next = {
        is_open: payload.isOpen === undefined ? shop.is_open : payload.isOpen ? 1 : 0,
        delivery_enabled: payload.deliveryEnabled === undefined ? shop.delivery_enabled : payload.deliveryEnabled ? 1 : 0,
        pickup_enabled: payload.pickupEnabled === undefined ? shop.pickup_enabled : payload.pickupEnabled ? 1 : 0,
        prep_minutes: payload.prepMinutes === undefined ? shop.prep_minutes : clampInt(payload.prepMinutes, 1, 240),
        delivery_fee_paise: payload.deliveryFee === undefined ? shop.delivery_fee_paise : clampInt(payload.deliveryFee, 0, 200000),
        pickup_fee_paise: payload.pickupFee === undefined ? shop.pickup_fee_paise : clampInt(payload.pickupFee, 0, 200000),
        min_order_paise: payload.minOrder === undefined ? shop.min_order_paise : clampInt(payload.minOrder, 0, 1000000),
        radius_km: payload.radiusKm === undefined ? shop.radius_km : round2(Math.min(50, Math.max(0.5, Number(payload.radiusKm) || shop.radius_km))),
        opens_at: str(payload.opensAt, 4, 5) ? payload.opensAt.trim() : shop.opens_at,
        closes_at: str(payload.closesAt, 4, 5) ? payload.closesAt.trim() : shop.closes_at,
        phone: str(payload.phone, 6, 20) ? normalPhone(payload.phone) : shop.phone
      };
      if (!next.delivery_enabled && !next.pickup_enabled) fail(400, 'Keep at least one fulfilment option enabled: home delivery or store pickup.');
      if (!/^\d{1,2}:\d{2}$/.test(next.opens_at) || !/^\d{1,2}:\d{2}$/.test(next.closes_at)) fail(400, 'Opening and closing times must look like 09:00.');
      db.prepare(`UPDATE nb_shops SET is_open=?,delivery_enabled=?,pickup_enabled=?,prep_minutes=?,delivery_fee_paise=?,
        pickup_fee_paise=?,min_order_paise=?,radius_km=?,opens_at=?,closes_at=?,phone=? WHERE id=?`).run(
        next.is_open, next.delivery_enabled, next.pickup_enabled, next.prep_minutes, next.delivery_fee_paise,
        next.pickup_fee_paise, next.min_order_paise, next.radius_km, next.opens_at, next.closes_at, next.phone, shop.id
      );
      audit('seller', s.user_id, 'shop_updated', 'shop', shop.id, JSON.stringify(next).slice(0, 300));
      const updated = db.prepare('SELECT * FROM nb_shops WHERE id=?').get(shop.id);
      send(res, 200, { message: 'Shop settings saved. Customers see the change immediately.', shop: shopRow(updated) });
      return true;
    }

    if (base === '/api/partner' && route === '/seller/products' && method === 'POST') {
      const s = requirePartner(['seller']);
      const shop = sellerShopContext(s);
      const name = String(payload.name || '').trim();
      if (!str(name, 2, 120)) fail(400, 'Give the product a name of 2–120 characters.');
      const categorySlug = String(payload.category || shop.category_slug);
      if (!db.prepare('SELECT 1 FROM nb_categories WHERE slug=?').get(categorySlug)) fail(400, 'Choose a valid category.');
      const price = Math.round(Number(payload.price));
      const mrp = payload.mrp === undefined || payload.mrp === null || payload.mrp === '' ? price : Math.round(Number(payload.mrp));
      if (!Number.isFinite(price) || price < 100 || price > 1000000) fail(400, 'Price must be between ₹1 and ₹10,000.');
      if (!Number.isFinite(mrp) || mrp < price) fail(400, 'MRP cannot be lower than the selling price.');
      const stock = clampInt(payload.stock, 0, 100000);
      const compareKey = payload.compareKey ? String(payload.compareKey).trim().slice(0, 60)
        : `${NB_SLUG(name)}-${String(payload.unit || '1 pc').toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;
      const id = `${shop.slug}-${NB_SLUG(name).slice(0, 32)}-${randomBytes(3).toString('hex')}`;
      db.prepare(`INSERT INTO nb_products(id,shop_id,category_slug,compare_key,name,brand,variant,description,highlights,specs,unit,pack_size,emoji,image_url,
        price_paise,mrp_paise,tax_rate,stock,reserved,low_stock,return_days,rating,review_count,active,is_demo,created_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,?,0,0,1,0,?)`).run(
        id, shop.id, categorySlug, compareKey, name, String(payload.brand || '').trim() || null,
        String(payload.variant || '').trim() || null, String(payload.description || '').slice(0, 2000) || null,
        '[]', '[]', String(payload.unit || '1 pc').slice(0, 40), String(payload.packSize || '').slice(0, 40) || null,
        String(payload.emoji || '🛍️').slice(0, 8), String(payload.imageUrl || '').slice(0, 300) || null,
        price, mrp, Math.min(28, Math.max(0, Number(payload.taxRate) || 0)), stock, clampInt(payload.lowStock ?? 5, 0, 1000),
        clampInt(payload.returnDays ?? 0, 0, 30), now()
      );
      audit('seller', s.user_id, 'product_created', 'product', id, `${name} · ${price}`);
      send(res, 201, { message: `${name} is live in your catalogue.`, productId: id });
      return true;
    }

    /* ================================================================== */
    /* Admin: catalogue, service areas, shops, deliveries, broadcast        */
    /* ================================================================== */

    if (base === '/api/admin' && route === '/categories' && method === 'GET') {
      requireAdmin();
      const rows = db.prepare(`SELECT c.*, (SELECT COUNT(*) FROM nb_shops s WHERE s.category_slug=c.slug) AS shops,
        (SELECT COUNT(*) FROM nb_products p WHERE p.category_slug=c.slug) AS products
        FROM nb_categories c ORDER BY c.parent_slug IS NOT NULL, c.sort, c.name`).all();
      send(res, 200, {
        categories: rows.map((c) => ({
          slug: c.slug, name: c.name, icon: c.icon, tone: c.tone, parentSlug: c.parent_slug,
          sort: c.sort, active: Boolean(c.active), shops: Number(c.shops || 0), products: Number(c.products || 0)
        }))
      });
      return true;
    }

    if (base === '/api/admin' && route === '/categories' && method === 'POST') {
      const admin = requireAdmin();
      const name = String(payload.name || '').trim();
      if (!str(name, 2, 60)) fail(400, 'Give the category a name of 2–60 characters.');
      const slug = String(payload.slug || NB_SLUG(name)).toLowerCase();
      if (!/^[a-z0-9-]{2,60}$/.test(slug)) fail(400, 'Slug may only contain letters, numbers and dashes.');
      const parentSlug = payload.parentSlug ? String(payload.parentSlug).trim() : null;
      if (parentSlug && !db.prepare('SELECT 1 FROM nb_categories WHERE slug=?').get(parentSlug)) fail(400, 'The parent category does not exist.');
      if (parentSlug === slug) fail(400, 'A category cannot be its own parent.');
      const existing = db.prepare('SELECT * FROM nb_categories WHERE slug=?').get(slug);
      if (existing) {
        db.prepare('UPDATE nb_categories SET name=?,icon=?,tone=?,parent_slug=?,sort=?,active=? WHERE slug=?').run(
          name, String(payload.icon || existing.icon || '🏷️').slice(0, 8), String(payload.tone || existing.tone || 'blue').slice(0, 12),
          parentSlug, clampInt(payload.sort ?? existing.sort, 0, 999), payload.active === undefined ? existing.active : payload.active ? 1 : 0, slug
        );
        audit('admin', admin.user_id, 'category_updated', 'category', slug, name);
        send(res, 200, { message: `Category ${name} updated.`, slug });
        return true;
      }
      db.prepare('INSERT INTO nb_categories(slug,name,icon,tone,parent_slug,sort,active) VALUES(?,?,?,?,?,?,?)').run(
        slug, name, String(payload.icon || '🏷️').slice(0, 8), String(payload.tone || 'blue').slice(0, 12),
        parentSlug, clampInt(payload.sort ?? 50, 0, 999), payload.active === false ? 0 : 1
      );
      audit('admin', admin.user_id, 'category_created', 'category', slug, name);
      send(res, 201, { message: `Category ${name} created.`, slug });
      return true;
    }

    if (base === '/api/admin' && route === '/service-areas' && method === 'GET') {
      requireAdmin();
      const rows = db.prepare('SELECT * FROM nb_service_areas ORDER BY pincode, locality').all();
      send(res, 200, {
        areas: rows.map((a) => ({ id: a.id, pincode: a.pincode, locality: a.locality, city: a.city, lat: a.lat, lng: a.lng, active: Boolean(a.active) }))
      });
      return true;
    }

    if (base === '/api/admin' && route === '/service-areas' && method === 'POST') {
      const admin = requireAdmin();
      if (!pincodeOk(payload.pincode)) fail(400, 'Enter a valid 6-digit PIN code.');
      if (!str(payload.locality, 2, 80)) fail(400, 'Enter the locality name.');
      const lat = Number(payload.lat);
      const lng = Number(payload.lng);
      if (!Number.isFinite(lat) || Math.abs(lat) > 90 || !Number.isFinite(lng) || Math.abs(lng) > 180) fail(400, 'Valid coordinates are required to place the area on the map.');
      const existing = db.prepare('SELECT * FROM nb_service_areas WHERE pincode=? AND locality=?').get(String(payload.pincode), payload.locality.trim());
      if (existing) {
        db.prepare('UPDATE nb_service_areas SET city=?,lat=?,lng=?,active=? WHERE id=?').run(
          String(payload.city || 'New Delhi').slice(0, 60), lat, lng, payload.active === false ? 0 : 1, existing.id
        );
        audit('admin', admin.user_id, 'service_area_updated', 'service_area', String(existing.id), payload.locality);
        send(res, 200, { message: 'Service area updated.' });
        return true;
      }
      db.prepare('INSERT INTO nb_service_areas(pincode,locality,city,lat,lng,active) VALUES(?,?,?,?,?,1)')
        .run(String(payload.pincode), payload.locality.trim(), String(payload.city || 'New Delhi').slice(0, 60), lat, lng);
      audit('admin', admin.user_id, 'service_area_created', 'service_area', null, `${payload.pincode} ${payload.locality}`);
      send(res, 201, { message: `${payload.locality} is now serviceable.` });
      return true;
    }

    if (base === '/api/admin' && route.match(/^\/shops\/[a-z0-9-]+$/) && method === 'PATCH') {
      const admin = requireAdmin();
      const shop = db.prepare('SELECT * FROM nb_shops WHERE slug=?').get(route.split('/')[2]);
      if (!shop) fail(404, 'Shop not found');
      const verified = payload.verified === undefined ? shop.verified : payload.verified ? 1 : 0;
      const openState = payload.isOpen === undefined ? shop.is_open : payload.isOpen ? 1 : 0;
      const radius = payload.radiusKm === undefined ? shop.radius_km : round2(Math.min(50, Math.max(0.5, Number(payload.radiusKm) || shop.radius_km)));
      const pincodes = payload.servicePincodes === undefined ? shop.service_pincodes
        : (Array.isArray(payload.servicePincodes) ? payload.servicePincodes : String(payload.servicePincodes).split(','))
          .map((p) => String(p).trim()).filter((p) => pincodeOk(p)).join(',');
      if (payload.servicePincodes !== undefined && shop.service_pincodes && !pincodes) {
        fail(400, 'Enter at least one valid 6-digit PIN code.');
      }
      db.prepare('UPDATE nb_shops SET verified=?,is_open=?,radius_km=?,service_pincodes=? WHERE id=?')
        .run(verified, openState, radius, pincodes, shop.id);
      audit('admin', admin.user_id, 'shop_updated', 'shop', shop.id, `verified ${shop.verified}→${verified}, open ${shop.is_open}→${openState}, radius ${shop.radius_km}→${radius}`);
      const updated = db.prepare('SELECT * FROM nb_shops WHERE id=?').get(shop.id);
      send(res, 200, { message: `${updated.name} updated.`, shop: shopCard(updated, null) });
      return true;
    }

    if (base === '/api/admin' && route.match(/^\/customers\/[a-zA-Z0-9-]+$/) && method === 'PATCH') {
      const admin = requireAdmin();
      const customer = db.prepare("SELECT * FROM nb_users WHERE id=? AND role='customer'").get(route.split('/')[2]);
      if (!customer) fail(404, 'Customer not found');
      if (!['active', 'suspended'].includes(payload.status)) fail(400, 'Choose active or suspended.');
      db.prepare('UPDATE nb_users SET status=? WHERE id=?').run(payload.status, customer.id);
      if (payload.status === 'suspended') {
        db.prepare('DELETE FROM nb_sessions WHERE user_id=?').run(customer.id);
        notify(customer.id, 'Account suspended', 'Your NearBuy account has been suspended. Contact support if you think this is a mistake.', 'account', '#/help');
      }
      audit('admin', admin.user_id, 'customer_status', 'user', customer.id, `${customer.status} → ${payload.status}`);
      send(res, 200, { message: `${customer.name} is now ${payload.status}.` });
      return true;
    }

    if (base === '/api/admin' && route === '/products' && method === 'GET') {
      requireAdmin();
      const rows = db.prepare(`SELECT p.id,p.name,p.brand,p.category_slug,p.price_paise,p.mrp_paise,p.stock,p.reserved,p.active,p.is_demo,
        s.name AS shop_name, s.slug AS shop_slug FROM nb_products p JOIN nb_shops s ON s.id=p.shop_id
        ORDER BY p.active, s.name, p.name LIMIT 400`).all();
      send(res, 200, {
        products: rows.map((p) => ({
          id: p.id, name: p.name, brand: p.brand, category: p.category_slug, price: p.price_paise, mrp: p.mrp_paise,
          stock: p.stock, reserved: p.reserved, available: Math.max(0, p.stock - p.reserved), active: Boolean(p.active),
          shop: { name: p.shop_name, slug: p.shop_slug }
        }))
      });
      return true;
    }

    if (base === '/api/admin' && route.match(/^\/products\/[a-zA-Z0-9_-]+$/) && method === 'PATCH') {
      const admin = requireAdmin();
      const product = db.prepare('SELECT * FROM nb_products WHERE id=?').get(route.split('/')[2]);
      if (!product) fail(404, 'Product not found');
      if (payload.active === undefined) fail(400, 'Send active: true or false to moderate a listing.');
      db.prepare('UPDATE nb_products SET active=? WHERE id=?').run(payload.active ? 1 : 0, product.id);
      audit('admin', admin.user_id, 'product_moderated', 'product', product.id, `${product.active} → ${payload.active ? 1 : 0}`);
      const shop = db.prepare('SELECT owner_user_id,name FROM nb_shops WHERE id=?').get(product.shop_id);
      if (shop?.owner_user_id) notify(shop.owner_user_id, `Listing ${payload.active ? 'restored' : 'hidden'}`, `${product.name} was ${payload.active ? 'restored to' : 'removed from'} the customer storefront by platform operations.`, 'seller', '#/catalogue');
      send(res, 200, { message: `${product.name} is now ${payload.active ? 'live' : 'hidden'}.` });
      return true;
    }

    if (base === '/api/admin' && route === '/deliveries' && method === 'GET') {
      requireAdmin();
      const rows = db.prepare(`SELECT a.*, so.code AS order_code, so.status AS order_status, s.name AS shop_name, u.name AS runner_name
        FROM nb_delivery_assignments a JOIN nb_seller_orders so ON so.id=a.seller_order_id
        JOIN nb_shops s ON s.id=a.shop_id LEFT JOIN nb_users u ON u.id=a.runner_id
        ORDER BY a.created_at DESC LIMIT 100`).all();
      send(res, 200, {
        deliveries: rows.map((a) => ({
          id: a.id, orderCode: a.order_code, orderStatus: a.order_status, shop: a.shop_name, runner: a.runner_name,
          status: a.status, payout: a.payout_paise, distanceKm: a.distance_km, createdAt: a.created_at,
          expiresAt: a.expires_at, pickedUpAt: a.picked_up_at, deliveredAt: a.delivered_at
        }))
      });
      return true;
    }

    if (base === '/api/admin' && route === '/notifications' && method === 'POST') {
      const admin = requireAdmin();
      if (!str(payload.title, 3, 120)) fail(400, 'A notification title is required.');
      if (!str(payload.body, 3, 400)) fail(400, 'Write the notification message.');
      const audience = payload.audience === 'shop_customers' ? 'shop_customers' : payload.audience === 'sellers' ? 'sellers' : 'customers';
      let users;
      if (audience === 'sellers') users = db.prepare("SELECT id FROM nb_users WHERE role='seller' AND status='active'").all();
      else if (audience === 'shop_customers' && payload.shopSlug) {
        users = db.prepare(`SELECT DISTINCT o.customer_id AS id FROM nb_orders o JOIN nb_seller_orders so ON so.order_id=o.id
          JOIN nb_shops s ON s.id=so.shop_id WHERE s.slug=?`).all(String(payload.shopSlug));
      } else users = db.prepare("SELECT id FROM nb_users WHERE role='customer' AND status='active'").all();
      transaction(() => {
        for (const u of users) notify(u.id, payload.title.trim(), payload.body.trim(), 'platform', String(payload.link || '#/notifications').slice(0, 200));
        audit('admin', admin.user_id, 'broadcast', 'notification', null, `${audience}: ${payload.title}`);
      });
      send(res, 201, {
        message: `Notification stored for ${users.length} ${audience.replace('_', ' ')}. In-app delivery is immediate; no SMS or email provider is configured.`,
        recipients: users.length
      });
      return true;
    }

    fail(404, 'API endpoint not found');
    return true;
  } catch (err) {
    if (!(err instanceof HttpError)) {
      console.error('[nearbuy] customer API error:', err);
    }
    if (!res.headersSent && !res.destroyed) {
      const status = err instanceof HttpError ? err.status : 500;
      send(res, status, {
        error: err instanceof HttpError ? err.message : 'Something went wrong on our side. Please try again.',
        ...(err instanceof HttpError && err.extra ? err.extra : {})
      });
    }
    return true;
  }
}

/* ------------------------------------------------------------------ */
/* Public config + payment webhook                                     */
/* ------------------------------------------------------------------ */

function publicConfig() {
  return {
    demo: DEMO,
    devCodes: DEV_CODES,
    payments: {
      gateway: GATEWAY.provider,
      onlineEnabled: GATEWAY.configured,
      cod: true,
      payAtStore: true,
      message: GATEWAY.configured
        ? 'Online payments are processed by Razorpay and confirmed by webhook.'
        : 'Online payments are not configured on this deployment. Cash on delivery and pay at store are available; add RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET and RAZORPAY_WEBHOOK_SECRET to enable UPI and cards.'
    },
    integrations: {
      maps: false,
      mapsMessage: 'No map-tile provider is configured. Distances are straight-line estimates × 1.35 from the shop and locality coordinates, and the map view is a schematic of those coordinates.',
      sms: false,
      email: false,
      notificationsMessage: 'In-app notifications are real database records. SMS, email and WhatsApp providers are not configured, so nothing is sent externally.'
    },
    delivery: { otpRequired: true, handoverPinRequired: true, offerSeconds: Number(process.env.DELIVERY_OFFER_SECONDS || 180) }
  };
}

async function paymentWebhook(req, res) {
  const secret = process.env.RAZORPAY_WEBHOOK_SECRET || '';
  if (!secret) { send(res, 503, { error: 'Webhook not configured (RAZORPAY_WEBHOOK_SECRET is missing).' }); return; }
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > 131072) { send(res, 413, { error: 'Payload too large' }); return; }
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks);
  const expected = createHmac('sha256', secret).update(raw).digest('hex');
  const provided = String(req.headers['x-razorpay-signature'] || '');
  if (!safeEqual(expected, provided)) { send(res, 401, { error: 'Invalid signature' }); return; }
  let event;
  try { event = JSON.parse(raw.toString('utf8')); } catch { send(res, 400, { error: 'Invalid JSON' }); return; }
  const payment = event?.payload?.payment?.entity;
  if (!payment || !payment.order_id) { send(res, 200, { ok: true, ignored: true }); return; }
  const record = db.prepare("SELECT * FROM nb_payment_records WHERE provider='razorpay' AND reference=?").get(payment.order_id);
  if (!record) { send(res, 200, { ok: true, ignored: true }); return; }
  const captured = event.event === 'payment.captured' || payment.status === 'captured';
  const failed = event.event === 'payment.failed' || payment.status === 'failed';
  transaction(() => {
    db.prepare('UPDATE nb_payment_records SET status=?,updated_at=? WHERE id=?').run(captured ? 'paid' : failed ? 'failed' : 'pending', now(), record.id);
    if (captured) {
      db.prepare("UPDATE nb_orders SET payment_status='paid',updated_at=? WHERE id=?").run(now(), record.order_id);
      const order = db.prepare('SELECT * FROM nb_orders WHERE id=?').get(record.order_id);
      notify(order.customer_id, 'Payment successful', `We received ₹${Math.round(record.amount_paise / 100)} for ${order.code}.`, 'payment', `#/orders/${order.code}`);
    } else if (failed) {
      const order = db.prepare('SELECT * FROM nb_orders WHERE id=?').get(record.order_id);
      notify(order.customer_id, 'Payment failed', `The gateway did not complete the payment for ${order.code}. No money was taken. You can try again.`, 'payment', `#/orders/${order.code}`);
    }
    audit('gateway', null, captured ? 'payment_captured' : failed ? 'payment_failed' : 'payment_updated', 'order', record.order_id, payment.id || '');
  });
  send(res, 200, { ok: true });
}

module.exports = { handle };
