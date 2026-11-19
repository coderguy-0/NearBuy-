'use strict';
/*
 * NearBuy Customer Portal — shared platform database.
 *
 * One Node process, one SQLite file (NEARBUY_DB), one set of customer, seller,
 * runner, catalogue, order and payment records. The legacy `server/orders.js`
 * foundation keeps its own legacy tables in the same file; every table created
 * here is prefixed `nb_` so the two can never overwrite each other.
 *
 * Zero npm dependencies: node:sqlite (Node 22.5+) and node:crypto only.
 */
const { DatabaseSync } = require('node:sqlite');
const { randomUUID, randomBytes, scryptSync, timingSafeEqual, createHash, createHmac } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const dbPath = process.env.NEARBUY_DB || path.join(__dirname, '..', '..', 'data', 'orders.sqlite');
const dataDir = path.dirname(dbPath);
fs.mkdirSync(dataDir, { recursive: true });
const db = new DatabaseSync(dbPath);

db.exec(`
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA busy_timeout=5000;

CREATE TABLE IF NOT EXISTS nb_users (
  id TEXT PRIMARY KEY,
  role TEXT NOT NULL CHECK (role IN ('customer','seller','runner','admin')),
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  phone TEXT UNIQUE,
  password_hash TEXT NOT NULL,
  email_verified INTEGER NOT NULL DEFAULT 0,
  phone_verified INTEGER NOT NULL DEFAULT 0,
  avatar TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  is_demo INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nb_customer_profiles (
  user_id TEXT PRIMARY KEY REFERENCES nb_users(id) ON DELETE CASCADE,
  marketing_opt_in INTEGER NOT NULL DEFAULT 1,
  order_updates INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nb_sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES nb_users(id) ON DELETE CASCADE,
  role TEXT NOT NULL,
  csrf TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  user_agent TEXT
);

CREATE TABLE IF NOT EXISTS nb_addresses (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES nb_users(id) ON DELETE CASCADE,
  label TEXT NOT NULL,
  receiver TEXT NOT NULL,
  phone TEXT NOT NULL,
  line1 TEXT NOT NULL,
  line2 TEXT,
  locality TEXT NOT NULL,
  city TEXT NOT NULL,
  pincode TEXT NOT NULL,
  landmark TEXT,
  instructions TEXT,
  lat REAL,
  lng REAL,
  is_default INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_addr_user ON nb_addresses(user_id);

CREATE TABLE IF NOT EXISTS nb_service_areas (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pincode TEXT NOT NULL,
  locality TEXT NOT NULL,
  city TEXT NOT NULL,
  lat REAL NOT NULL,
  lng REAL NOT NULL,
  active INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_area_pin ON nb_service_areas(pincode);

CREATE TABLE IF NOT EXISTS nb_categories (
  slug TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  icon TEXT NOT NULL,
  tone TEXT NOT NULL DEFAULT 'blue',
  parent_slug TEXT REFERENCES nb_categories(slug),
  sort INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS nb_shops (
  id TEXT PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  owner_user_id TEXT REFERENCES nb_users(id),
  name TEXT NOT NULL,
  category_slug TEXT NOT NULL REFERENCES nb_categories(slug),
  tagline TEXT,
  description TEXT,
  emoji TEXT,
  tone TEXT NOT NULL DEFAULT 'blue',
  phone TEXT,
  address TEXT NOT NULL,
  locality TEXT NOT NULL,
  city TEXT NOT NULL,
  pincode TEXT NOT NULL,
  lat REAL NOT NULL,
  lng REAL NOT NULL,
  rating REAL NOT NULL DEFAULT 0,
  review_count INTEGER NOT NULL DEFAULT 0,
  verified INTEGER NOT NULL DEFAULT 0,
  is_open INTEGER NOT NULL DEFAULT 1,
  opens_at TEXT NOT NULL DEFAULT '08:00',
  closes_at TEXT NOT NULL DEFAULT '22:00',
  prep_minutes INTEGER NOT NULL DEFAULT 15,
  delivery_enabled INTEGER NOT NULL DEFAULT 1,
  pickup_enabled INTEGER NOT NULL DEFAULT 1,
  delivery_fee_paise INTEGER NOT NULL DEFAULT 0,
  free_delivery_over_paise INTEGER,
  pickup_fee_paise INTEGER NOT NULL DEFAULT 0,
  min_order_paise INTEGER NOT NULL DEFAULT 0,
  radius_km REAL NOT NULL DEFAULT 5,
  service_pincodes TEXT NOT NULL DEFAULT '',
  badge TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_shop_cat ON nb_shops(category_slug);

CREATE TABLE IF NOT EXISTS nb_products (
  id TEXT PRIMARY KEY,
  shop_id TEXT NOT NULL REFERENCES nb_shops(id) ON DELETE CASCADE,
  category_slug TEXT NOT NULL REFERENCES nb_categories(slug),
  compare_key TEXT NOT NULL,
  name TEXT NOT NULL,
  brand TEXT,
  variant TEXT,
  description TEXT,
  highlights TEXT NOT NULL DEFAULT '[]',
  specs TEXT NOT NULL DEFAULT '[]',
  unit TEXT NOT NULL DEFAULT '1 pc',
  pack_size TEXT,
  emoji TEXT,
  image_url TEXT,
  price_paise INTEGER NOT NULL,
  mrp_paise INTEGER,
  tax_rate REAL NOT NULL DEFAULT 5,
  stock INTEGER NOT NULL DEFAULT 0,
  reserved INTEGER NOT NULL DEFAULT 0,
  low_stock INTEGER NOT NULL DEFAULT 5,
  return_days INTEGER NOT NULL DEFAULT 0,
  rating REAL NOT NULL DEFAULT 0,
  review_count INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1,
  is_demo INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_prod_shop ON nb_products(shop_id);
CREATE INDEX IF NOT EXISTS idx_prod_cat ON nb_products(category_slug);
CREATE INDEX IF NOT EXISTS idx_prod_compare ON nb_products(compare_key);
CREATE INDEX IF NOT EXISTS idx_prod_name ON nb_products(name);

CREATE TABLE IF NOT EXISTS nb_product_images (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  product_id TEXT NOT NULL REFERENCES nb_products(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  sort INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS nb_carts (
  user_id TEXT PRIMARY KEY REFERENCES nb_users(id) ON DELETE CASCADE,
  coupon_code TEXT,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nb_cart_items (
  user_id TEXT NOT NULL REFERENCES nb_users(id) ON DELETE CASCADE,
  product_id TEXT NOT NULL REFERENCES nb_products(id) ON DELETE CASCADE,
  qty INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (user_id, product_id)
);

CREATE TABLE IF NOT EXISTS nb_coupons (
  code TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  description TEXT,
  type TEXT NOT NULL CHECK (type IN ('percent','fixed','free_delivery')),
  value INTEGER NOT NULL DEFAULT 0,
  min_order_paise INTEGER NOT NULL DEFAULT 0,
  max_discount_paise INTEGER,
  shop_id TEXT REFERENCES nb_shops(id),
  starts_at TEXT NOT NULL,
  ends_at TEXT NOT NULL,
  usage_limit INTEGER,
  used_count INTEGER NOT NULL DEFAULT 0,
  per_customer_limit INTEGER NOT NULL DEFAULT 1,
  active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS nb_coupon_redemptions (
  id TEXT PRIMARY KEY,
  coupon_code TEXT NOT NULL REFERENCES nb_coupons(code),
  user_id TEXT NOT NULL REFERENCES nb_users(id),
  order_id TEXT NOT NULL,
  amount_paise INTEGER NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nb_orders (
  id TEXT PRIMARY KEY,
  code TEXT NOT NULL UNIQUE,
  customer_id TEXT NOT NULL REFERENCES nb_users(id),
  status TEXT NOT NULL,
  payment_method TEXT NOT NULL,
  payment_status TEXT NOT NULL,
  address_json TEXT NOT NULL,
  subtotal_paise INTEGER NOT NULL,
  discount_paise INTEGER NOT NULL DEFAULT 0,
  delivery_fee_paise INTEGER NOT NULL DEFAULT 0,
  tax_paise INTEGER NOT NULL DEFAULT 0,
  total_paise INTEGER NOT NULL,
  coupon_code TEXT,
  note TEXT,
  idempotency_key TEXT UNIQUE,
  is_demo INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_order_customer ON nb_orders(customer_id, created_at);

CREATE TABLE IF NOT EXISTS nb_seller_orders (
  id TEXT PRIMARY KEY,
  code TEXT NOT NULL UNIQUE,
  order_id TEXT NOT NULL REFERENCES nb_orders(id) ON DELETE CASCADE,
  shop_id TEXT NOT NULL REFERENCES nb_shops(id),
  status TEXT NOT NULL,
  fulfillment TEXT NOT NULL CHECK (fulfillment IN ('delivery','pickup')),
  subtotal_paise INTEGER NOT NULL,
  discount_paise INTEGER NOT NULL DEFAULT 0,
  delivery_fee_paise INTEGER NOT NULL DEFAULT 0,
  tax_paise INTEGER NOT NULL DEFAULT 0,
  total_paise INTEGER NOT NULL,
  prep_minutes INTEGER NOT NULL DEFAULT 15,
  ready_at TEXT,
  accepted_at TEXT,
  rejected_reason TEXT,
  cancelled_at TEXT,
  delivered_at TEXT,
  completed_at TEXT,
  runner_id TEXT REFERENCES nb_users(id),
  delivery_otp_expires TEXT,
  delivery_attempts INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_so_order ON nb_seller_orders(order_id);
CREATE INDEX IF NOT EXISTS idx_so_shop ON nb_seller_orders(shop_id, created_at);

CREATE TABLE IF NOT EXISTS nb_order_items (
  id TEXT PRIMARY KEY,
  order_id TEXT NOT NULL REFERENCES nb_orders(id) ON DELETE CASCADE,
  seller_order_id TEXT NOT NULL REFERENCES nb_seller_orders(id) ON DELETE CASCADE,
  product_id TEXT NOT NULL,
  shop_id TEXT NOT NULL,
  name TEXT NOT NULL,
  brand TEXT,
  unit TEXT,
  qty INTEGER NOT NULL,
  price_paise INTEGER NOT NULL,
  mrp_paise INTEGER,
  tax_rate REAL NOT NULL DEFAULT 0,
  line_total_paise INTEGER NOT NULL,
  image_url TEXT,
  emoji TEXT,
  compare_key TEXT
);
CREATE INDEX IF NOT EXISTS idx_item_order ON nb_order_items(order_id);

CREATE TABLE IF NOT EXISTS nb_order_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id TEXT NOT NULL,
  seller_order_id TEXT,
  status TEXT NOT NULL,
  label TEXT NOT NULL,
  detail TEXT,
  actor TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_order ON nb_order_events(order_id);

CREATE TABLE IF NOT EXISTS nb_payment_records (
  id TEXT PRIMARY KEY,
  order_id TEXT NOT NULL REFERENCES nb_orders(id) ON DELETE CASCADE,
  seller_order_id TEXT,
  provider TEXT NOT NULL,
  method TEXT NOT NULL,
  amount_paise INTEGER NOT NULL,
  status TEXT NOT NULL,
  reference TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nb_delivery_assignments (
  id TEXT PRIMARY KEY,
  seller_order_id TEXT NOT NULL REFERENCES nb_seller_orders(id) ON DELETE CASCADE,
  shop_id TEXT NOT NULL,
  runner_id TEXT NOT NULL REFERENCES nb_users(id),
  status TEXT NOT NULL,
  payout_paise INTEGER NOT NULL DEFAULT 0,
  distance_km REAL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  responded_at TEXT,
  picked_up_at TEXT,
  delivered_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_assign_runner ON nb_delivery_assignments(runner_id, status);

CREATE TABLE IF NOT EXISTS nb_delivery_tracking (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  seller_order_id TEXT NOT NULL,
  status TEXT NOT NULL,
  note TEXT,
  lat REAL,
  lng REAL,
  actor TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nb_returns (
  id TEXT PRIMARY KEY,
  code TEXT NOT NULL UNIQUE,
  customer_id TEXT NOT NULL,
  order_id TEXT NOT NULL,
  seller_order_id TEXT NOT NULL,
  item_id TEXT NOT NULL,
  reason TEXT NOT NULL,
  comment TEXT,
  images_json TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL,
  refund_amount_paise INTEGER NOT NULL DEFAULT 0,
  decision_note TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_returns_cust ON nb_returns(customer_id, created_at);

CREATE TABLE IF NOT EXISTS nb_refunds (
  id TEXT PRIMARY KEY,
  return_id TEXT,
  order_id TEXT NOT NULL,
  amount_paise INTEGER NOT NULL,
  status TEXT NOT NULL,
  reference TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nb_reviews (
  id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL,
  shop_id TEXT NOT NULL,
  product_id TEXT,
  seller_order_id TEXT,
  order_id TEXT,
  shop_rating INTEGER,
  product_rating INTEGER,
  title TEXT,
  body TEXT,
  images_json TEXT NOT NULL DEFAULT '[]',
  verified_purchase INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'published',
  created_at TEXT NOT NULL,
  UNIQUE (customer_id, product_id, seller_order_id)
);
CREATE INDEX IF NOT EXISTS idx_review_product ON nb_reviews(product_id);

CREATE TABLE IF NOT EXISTS nb_notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL REFERENCES nb_users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  type TEXT NOT NULL DEFAULT 'order',
  link TEXT,
  is_read INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notif_user ON nb_notifications(user_id, created_at);

CREATE TABLE IF NOT EXISTS nb_tickets (
  id TEXT PRIMARY KEY,
  code TEXT NOT NULL UNIQUE,
  customer_id TEXT NOT NULL,
  order_id TEXT,
  category TEXT NOT NULL,
  subject TEXT NOT NULL,
  description TEXT NOT NULL,
  attachment TEXT,
  status TEXT NOT NULL DEFAULT 'open',
  priority TEXT NOT NULL DEFAULT 'normal',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nb_ticket_messages (
  id TEXT PRIMARY KEY,
  ticket_id TEXT NOT NULL REFERENCES nb_tickets(id) ON DELETE CASCADE,
  author_role TEXT NOT NULL,
  author_name TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nb_wishlist (
  user_id TEXT NOT NULL REFERENCES nb_users(id) ON DELETE CASCADE,
  product_id TEXT NOT NULL REFERENCES nb_products(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  PRIMARY KEY (user_id, product_id)
);

CREATE TABLE IF NOT EXISTS nb_banners (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  subtitle TEXT,
  eyebrow TEXT,
  cta_label TEXT,
  cta_link TEXT,
  image_url TEXT,
  theme TEXT NOT NULL DEFAULT 'blue',
  active INTEGER NOT NULL DEFAULT 1,
  sort INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS nb_faqs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  category TEXT NOT NULL,
  question TEXT NOT NULL,
  answer TEXT NOT NULL,
  sort INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS nb_otp_codes (
  id TEXT PRIMARY KEY,
  user_id TEXT REFERENCES nb_users(id) ON DELETE CASCADE,
  channel TEXT NOT NULL,
  purpose TEXT NOT NULL,
  target TEXT,
  code_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  consumed_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nb_password_resets (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES nb_users(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL,
  used_at TEXT
);

CREATE TABLE IF NOT EXISTS nb_enquiries (
  id TEXT PRIMARY KEY,
  code TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  contact TEXT NOT NULL,
  topic TEXT NOT NULL,
  message TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nb_audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_type TEXT NOT NULL,
  actor_id TEXT,
  action TEXT NOT NULL,
  entity TEXT,
  entity_id TEXT,
  detail TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nb_runners (
  user_id TEXT PRIMARY KEY REFERENCES nb_users(id) ON DELETE CASCADE,
  vehicle TEXT NOT NULL DEFAULT 'scooter',
  status TEXT NOT NULL DEFAULT 'offline',
  lat REAL,
  lng REAL,
  rating REAL NOT NULL DEFAULT 4.8,
  completed INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1
);
`);

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

const now = () => new Date().toISOString();
const iso = (d) => new Date(d).toISOString();
const uid = () => randomUUID();
const sha = (s) => createHash('sha256').update(String(s)).digest('hex');

function makePassword(password) {
  const salt = randomBytes(16).toString('hex');
  return `${salt}:${scryptSync(String(password), salt, 64).toString('hex')}`;
}
function checkPassword(password, stored) {
  try {
    const [salt, digest] = String(stored || '').split(':');
    if (!salt || !digest) return false;
    const actual = scryptSync(String(password), salt, 64);
    const expected = Buffer.from(digest, 'hex');
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

/* A process-local key file keeps OTP derivation stable across restarts
 * without storing any code in plain text. The file is inside data/ (ignored). */
let secret = process.env.NEARBUY_OTP_SECRET || '';
if (!secret) {
  const keyFile = path.join(dataDir, '.nearbuy-otp-key');
  try {
    secret = fs.readFileSync(keyFile, 'utf8').trim();
  } catch {
    secret = randomBytes(32).toString('hex');
    fs.writeFileSync(keyFile, secret, { mode: 0o600 });
  }
}

/** Derive a code that is never stored: HMAC(secret, purpose:id:epoch). */
function deriveCode(purpose, id, digits = 6) {
  const digest = createHmac('sha256', secret).update(`${purpose}:${id}`).digest();
  const n = digest.readUInt32BE(0) % 10 ** digits;
  return String(n).padStart(digits, '0');
}
function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && timingSafeEqual(x, y);
}

function transaction(fn) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const out = fn();
    db.exec('COMMIT');
    return out;
  } catch (err) {
    try { db.exec('ROLLBACK'); } catch { /* already rolled back */ }
    throw err;
  }
}

function audit(actorType, actorId, action, entity, entityId, detail) {
  db.prepare(
    'INSERT INTO nb_audit_logs(actor_type,actor_id,action,entity,entity_id,detail,created_at) VALUES(?,?,?,?,?,?,?)'
  ).run(actorType, actorId || null, action, entity || null, entityId || null, detail ? String(detail).slice(0, 500) : null, now());
}

const money = (paise) => Math.round(Number(paise) || 0);
const rupees = (n) => Math.round(Number(n) * 100);

function pincodeArea(pincode) {
  return db.prepare('SELECT * FROM nb_service_areas WHERE pincode=? AND active=1 ORDER BY id LIMIT 1').get(String(pincode));
}

function haversineKm(aLat, aLng, bLat, bLng) {
  if ([aLat, aLng, bLat, bLng].some((v) => typeof v !== 'number' || Number.isNaN(v))) return null;
  const R = 6371;
  const toRad = (d) => (d * Math.PI) / 180;
  const dLat = toRad(bLat - aLat);
  const dLng = toRad(bLng - aLng);
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(aLat)) * Math.cos(toRad(bLat)) * Math.sin(dLng / 2) ** 2;
  return Math.round(2 * R * Math.asin(Math.sqrt(h)) * 100) / 100;
}

module.exports = {
  db,
  dbPath,
  now,
  iso,
  uid,
  sha,
  makePassword,
  checkPassword,
  deriveCode,
  safeEqual,
  transaction,
  audit,
  money,
  rupees,
  pincodeArea,
  haversineKm
};
