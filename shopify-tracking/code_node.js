// Shopify order -> idempotent server-side conversion (Meta CAPI + GA4)
// ---------------------------------------------------------------
// Problem it fixes: Shopify retries webhooks, and the browser pixel already
// fires Purchase. Without a shared event_id you get double-counted purchases
// in Meta and in GA4. This node derives a STABLE event_id from the order and
// drops any delivery it has already emitted.

// --- SHA-256 (Code node blocks require('crypto')) -----------------
function sha256(ascii) {
  function rightRotate(value, amount) { return (value >>> amount) | (value << (32 - amount)); }
  const mathPow = Math.pow, maxWord = mathPow(2, 32);
  let result = '';
  const words = [], asciiBitLength = ascii.length * 8;
  let hash = sha256.h = sha256.h || [];
  const k = sha256.k = sha256.k || [];
  let primeCounter = k.length;
  const isComposite = {};
  for (let candidate = 2; primeCounter < 64; candidate++) {
    if (!isComposite[candidate]) {
      for (let i = 0; i < 313; i += candidate) isComposite[i] = candidate;
      hash[primeCounter] = (mathPow(candidate, 0.5) * maxWord) | 0;
      k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
    }
  }
  ascii += '\x80';
  while (ascii.length % 64 - 56) ascii += '\x00';
  for (let i = 0; i < ascii.length; i++) {
    const j = ascii.charCodeAt(i);
    if (j >> 8) return '';
    words[i >> 2] |= j << (((3 - i) % 4) * 8);
  }
  words[words.length] = (asciiBitLength / maxWord) | 0;
  words[words.length] = asciiBitLength;
  for (let j = 0; j < words.length;) {
    const w = words.slice(j, (j += 16));
    const oldHash = hash.slice(0);
    for (let i = 0; i < 64; i++) {
      const w15 = w[i - 15], w2 = w[i - 2];
      const a = hash[0], e = hash[4];
      const temp1 = hash[7]
        + (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25))
        + ((e & hash[5]) ^ ((~e) & hash[6]))
        + k[i]
        + (w[i] = (i < 16) ? w[i] : (
            w[i - 16]
            + (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3))
            + w[i - 7]
            + (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10))
          ) | 0);
      const temp2 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22))
        + ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));
      hash = [(temp1 + temp2) | 0].concat(hash);
      hash[4] = (hash[4] + temp1) | 0;
    }
    for (let i = 0; i < 8; i++) hash[i] = (hash[i] + oldHash[i]) | 0;
  }
  for (let i = 0; i < 8; i++) {
    for (let j = 3; j + 1; j--) {
      const b = (hash[i] >> (j * 8)) & 255;
      result += (b < 16 ? '0' : '') + b.toString(16);
    }
  }
  return result;
}

const body = $json.body || $json;
const order = body.id ? body : (body.order || {});
const orderId = String(order.id || order.order_number || '');
if (!orderId) { return []; }

const h = (s) => sha256(String(s).trim().toLowerCase());

// Stable event_id: identical for the browser pixel and every webhook retry.
const eventId = h('purchase:' + orderId + ':' + (order.currency || 'USD') + ':' + (order.total_price || '0'));

const staticData = $getWorkflowStaticData('global');
staticData.seen = staticData.seen || {};
const nowMs = Date.now();
for (const key of Object.keys(staticData.seen)) {
  if (nowMs - staticData.seen[key] > 30 * 24 * 3600 * 1000) delete staticData.seen[key];
}
if (staticData.seen[eventId]) {
  return [{ json: { skipped: true, reason: 'duplicate_event_id', event_id: eventId, order_id: orderId } }];
}
staticData.seen[eventId] = nowMs;

const value = Number(order.total_price || 0);
const currency = order.currency || 'USD';
const email = order.email || order.contact_email || '';
const items = (order.line_items || []).map(function (li) {
  return {
    id: String(li.sku || li.variant_id || ''),
    quantity: Number(li.quantity || 1),
    item_price: Number(li.price || 0),
  };
});

const meta = {
  data: [{
    event_name: 'Purchase',
    event_time: Math.floor(nowMs / 1000),
    event_id: eventId,
    action_source: 'website',
    event_source_url: 'https://' + (order.shop_domain || 'shop.example.com') + '/checkout',
    user_data: {
      em: email ? [h(email)] : [],
      external_id: [h(String((order.customer && order.customer.id) || orderId))],
    },
    custom_data: {
      currency: currency,
      value: value,
      order_id: orderId,
      contents: items,
      num_items: items.length,
    },
  }],
};

const ga4 = {
  client_id: String((order.customer && order.customer.id) || orderId),
  events: [{
    name: 'purchase',
    params: { transaction_id: orderId, currency: currency, value: value, items: items },
  }],
};

return [{
  json: {
    event_id: eventId,
    order_id: orderId,
    skipped: false,
    meta: meta,
    ga4: ga4,
    metaJson: JSON.stringify(meta),
    ga4Json: JSON.stringify(ga4),
  },
}];
