/* NearBuy Seller Hub — orders, fulfilment, catalogue, returns and shop settings.
 * Every read and write goes to /api/partner/seller/* on the shared platform
 * backend, so the customer storefront sees the same stock, prices and statuses.
 */
(function () {
  'use strict';
  const PA = window.PA;
  const esc = PA.esc;

  const NAV = [
    { href: '#/overview', label: 'Overview', icon: 'grid' },
    { href: '#/orders', label: 'Orders', icon: 'orders', count: 'newOrders' },
    { href: '#/catalogue', label: 'Catalogue & stock', icon: 'box' },
    { href: '#/returns', label: 'Returns', icon: 'rotate' },
    { href: '#/settings', label: 'Shop settings', icon: 'settings' }
  ];

  let cache = { orders: [], products: [], shop: null };

  /* ------------------------------------------------------------- overview */
  async function overview() {
    const data = await PA.api('GET', '/seller/overview');
    const shop = data.shop;
    const recent = data.recent || [];
    PA.set(`
      <div class="space-between">
        <div>
          <h1>${esc(shop.name)}</h1>
          <p class="muted small">${shop.verified ? '✓ Verified shop' : 'Verification pending'} · ${esc(shop.opensAt)}–${esc(shop.closesAt)} ·
            ${shop.isOpen ? PA.status('online', 'Open now') : PA.status('offline', 'Closed')}</p>
        </div>
        <div class="row">
          <a class="btn" href="#/settings">Shop settings</a>
          <a class="btn btn-primary" href="#/orders">Open orders</a>
        </div>
      </div>

      <div class="grid g4">
        <div class="card stat"><span class="label">New orders</span><span class="value">${data.counts.new}</span><span class="hint">Waiting for your accept or reject</span></div>
        <div class="card stat"><span class="label">Preparing</span><span class="value">${data.counts.preparing}</span><span class="hint">Accepted and being packed</span></div>
        <div class="card stat"><span class="label">On the way</span><span class="value">${data.counts.onTheWay}</span><span class="hint">Runner assigned or self-delivery</span></div>
        <div class="card stat"><span class="label">Completed revenue</span><span class="value">${PA.money(data.revenue)}</span><span class="hint">${data.counts.completed} completed order(s)</span></div>
      </div>

      <div class="grid g2">
        <div class="card flush">
          <div class="card-head"><h2>Needs you now</h2><span class="spacer"></span><a class="small" href="#/orders">All orders</a></div>
          <div class="card-body">
            ${recent.length ? `<div class="list">${recent.map((o) => `
              <div class="item">
                <span class="emoji">${o.fulfillment === 'pickup' ? '🏬' : '🛵'}</span>
                <div class="grow"><b>${esc(o.code)} · ${PA.money(o.total)}</b>
                  <span>${esc(o.customer || 'Customer')} · ${esc(o.fulfillment)} · ${PA.ago(o.createdAt)}</span></div>
                ${PA.status(o.status)}
                <a class="btn btn-sm" href="#/orders/${encodeURIComponent(o.code)}">Open</a>
              </div>`).join('')}</div>`
        : PA.empty('📦', 'No orders yet', 'New customer orders appear here with an alert as soon as they are placed.')}
          </div>
        </div>

        <div class="stack">
          <div class="card flush">
            <div class="card-head"><h3>Low stock</h3><span class="spacer"></span><a class="small" href="#/catalogue">Catalogue</a></div>
            <div class="card-body">
              ${data.lowStock.length ? `<div class="list">${data.lowStock.map((p) => `
                <div class="item"><span class="emoji">${esc(p.emoji || '📦')}</span>
                  <div class="grow"><b>${esc(p.name)}</b><span>${p.stock} left · reorder at ${p.lowAt}</span></div>
                  <a class="btn btn-sm" href="#/catalogue">Restock</a></div>`).join('')}</div>`
        : PA.empty('✅', 'Stock levels are healthy', 'Products at or below their low-stock threshold show up here.')}
            </div>
          </div>
          <div class="card">
            <h3>Runner offers in progress</h3>
            ${data.runnerOffers.length ? `<div class="list" style="margin-top:10px">${data.runnerOffers.map((o) => `
              <div class="item"><span class="emoji">🛵</span><div class="grow"><b>${esc(o.orderCode)}</b>
                <span>Offered to ${esc(o.runner)} · expires ${PA.clock(o.expiresAt)}</span></div></div>`).join('')}</div>`
        : '<p class="muted small" style="margin-top:10px">No delivery partner is holding an offer right now.</p>'}
          </div>
        </div>
      </div>

      <div class="card">
        <h3>How fulfilment works here</h3>
        <div class="grid g3" style="margin-top:12px">
          <div><b class="small">1 · Accept or reject</b><p class="muted small">Accepting reserves nothing extra — the customer’s stock was already held at checkout. Rejecting releases it straight back to the storefront.</p></div>
          <div><b class="small">2 · Pack, then choose</b><p class="muted small">Mark the order ready, then deliver it yourself or request a nearby NearBuy runner. The customer sees each step in their timeline.</p></div>
          <div><b class="small">3 · Verify handover</b><p class="muted small">A runner needs your 4-digit handover PIN. You need the customer’s 6-digit delivery OTP or collection code before an order can close.</p></div>
        </div>
      </div>
    `);
    PA.badges({ newOrders: data.counts.new });
  }

  /* ---------------------------------------------------------------- orders */
  const FILTERS = [
    ['all', 'All'], ['new', 'New'], ['active', 'In progress'], ['completed', 'Completed'], ['cancelled', 'Cancelled / rejected']
  ];

  async function orders(match, ctx) {
    const filter = new URLSearchParams(location.hash.split('?')[1] || '').get('status') || 'all';
    const data = await PA.api('GET', `/seller/orders?status=${encodeURIComponent(filter)}`);
    cache.orders = data.orders;
    const counts = { newOrders: data.orders.filter((o) => o.status === 'placed').length };
    PA.badges(counts);
    if (!ctx.isCurrent()) return;
    PA.set(`
      <div class="space-between">
        <div><h1>Orders</h1><p class="muted small">${esc(data.shop.name)} · only your items and your money</p></div>
        <div class="row">${FILTERS.map(([key, label]) => `<a class="btn btn-sm ${key === filter ? 'btn-dark' : ''}" href="#/orders?status=${key}">${label}</a>`).join('')}</div>
      </div>
      ${data.orders.length ? `<div class="stack">${data.orders.map(orderCard).join('')}</div>`
        : `<div class="card">${PA.empty('🧾', 'Nothing here', filter === 'new' ? 'No new orders are waiting for you.' : 'No orders match this filter yet.')}</div>`}
    `);
    wireOrders();
  }

  const NEXT = {
    placed: [['accept', 'Accept order', 'btn-success'], ['reject', 'Reject', 'btn-danger']],
    accepted: [['prepare', 'Start preparing', 'btn-primary'], ['cancel', 'Cancel', 'btn-danger']],
    preparing: [['ready', 'Mark ready', 'btn-primary']],
    ready: [['request_runner', 'Find a NearBuy runner', 'btn-primary'], ['self_deliver', 'Deliver myself', '']],
    out_for_delivery: [['deliver', 'Complete with delivery OTP', 'btn-success']]
  };

  function orderCard(o) {
    const actions = [];
    if (o.status === 'ready' && o.fulfillment === 'pickup') actions.push(['complete_pickup', 'Verify collection code', 'btn-success']);
    else if (NEXT[o.status]) actions.push(...NEXT[o.status]);
    const address = o.address;
    return `
      <article class="card" data-order="${esc(o.code)}">
        <div class="space-between">
          <div>
            <div class="row tight"><b class="mono">${esc(o.code)}</b>${PA.status(o.status, o.statusLabel)}
              ${PA.badge(o.fulfillment === 'pickup' ? 'Store pickup' : 'Home delivery', o.fulfillment === 'pickup' ? 'blue' : 'grey')}
              ${o.paymentMethod === 'cod' ? PA.badge('Cash on delivery', 'amber') : o.paymentMethod === 'pay_at_store' ? PA.badge('Pay at store', 'amber') : PA.badge('Online', 'blue')}
            </div>
            <div class="muted small">${PA.dateTime(o.createdAt)} · parent order <span class="mono">${esc(o.parentCode)}</span> · ${o.itemCount} item(s)</div>
          </div>
          <div class="right"><b style="font-size:19px;color:var(--deep)">${PA.money(o.total)}</b>
            <div class="muted small">${o.paymentStatus === 'paid' ? 'Paid' : 'Payment pending'}</div></div>
        </div>

        <div class="grid g2" style="margin-top:14px">
          <div>
            <b class="small">Items</b>
            <div class="list" style="margin-top:6px">
              ${o.items.map((i) => `<div class="item"><span class="emoji">${esc(i.emoji || '📦')}</span>
                <div class="grow"><b>${esc(i.name)}</b><span>${esc(i.unit || '')} · ${i.qty} × ${PA.money(i.price)}</span></div>
                <b>${PA.money(i.price * i.qty)}</b></div>`).join('')}
            </div>
          </div>
          <div class="stack" style="gap:8px">
            ${PA.kv([
              ['Customer', o.customer.name + (o.customer.maskedPhone ? ' · ' + o.customer.maskedPhone : '')],
              o.fulfillment === 'pickup' ? ['Collect from', 'Your counter'] : ['Deliver to', [address?.line1, address?.locality, address?.pincode].filter(Boolean).join(', ')],
              address?.instructions ? ['Instructions', address.instructions] : null,
              ['Subtotal', PA.money(o.subtotal)],
              o.discount ? ['Discount', '−' + PA.money(o.discount)] : null,
              ['Delivery / pickup fee', PA.money(o.deliveryFee)],
              ['Tax', PA.money(o.tax)]
            ])}
            ${o.handoverPin ? `<div class="banner-note info"><b>Handover PIN ${o.handoverPin}</b> — give this to the NearBuy runner at pickup. It is generated per order and never shown to the customer.</div>` : ''}
            ${o.receiptUrl ? `<a class="btn btn-sm" href="${o.receiptUrl}" target="_blank" rel="noopener">${PA.icon('print')} Print seller receipt</a>` : ''}
          </div>
        </div>

        ${actions.length || o.status === 'completed' || o.status === 'delivered' ? `<div class="card-foot" style="margin:14px -18px -18px;border-radius:0 0 16px 16px">
          <div class="row">
            ${actions.map(([action, label, cls]) => `<button class="btn ${cls}" data-act="${action}" data-code="${esc(o.code)}">${esc(label)}</button>`).join('')}
            <span class="spacer"></span>
            <a class="btn btn-sm" href="#/orders/${encodeURIComponent(o.code)}">Order detail</a>
          </div></div>` : ''}
      </article>`;
  }

  function wireOrders() {
    PA.onAll('[data-act]', 'click', async (e) => {
      const btn = e.currentTarget;
      const action = btn.dataset.act;
      const code = btn.dataset.code;
      const order = cache.orders.find((o) => o.code === code);
      try {
        if (action === 'reject' || action === 'cancel') {
          const reason = await promptText(action === 'reject' ? 'Why are you rejecting this order?' : 'Why are you cancelling?',
            'The customer sees this reason on their order page.');
          if (!reason) return;
          btn.disabled = true;
          await PA.api('POST', `/seller/orders/${encodeURIComponent(code)}/action`, { action, reason });
          PA.toast('Order ' + (action === 'reject' ? 'rejected' : 'cancelled') + ' and stock released.');
          return PA.render();
        }
        if (action === 'deliver' || action === 'complete_pickup') {
          const otp = await promptText(action === 'deliver' ? 'Customer delivery OTP' : 'Customer collection code',
            'Ask the customer to read the 6-digit code from their order page. It is verified on the server.');
          if (!otp) return;
          btn.disabled = true;
          await PA.api('POST', `/seller/orders/${encodeURIComponent(code)}/action`, { action, otp: String(otp).trim() });
          PA.toast(action === 'deliver' ? 'Delivery verified with OTP.' : 'Collection verified.');
          return PA.render();
        }
        btn.disabled = true;
        const res = await PA.api('POST', `/seller/orders/${encodeURIComponent(code)}/action`, { action });
        PA.toast(res.message || 'Order updated.');
        PA.render();
      } catch (err) {
        btn.disabled = false;
        if (err.data && err.data.alternatives) {
          PA.modal({
            title: 'No runner available',
            body: `<p>${esc(err.message)}</p><ul class="small muted">${err.data.alternatives.map((a) => `<li>${esc(a)}</li>`).join('')}</ul>`,
            actions: [{ label: 'Close' }]
          });
          return;
        }
        PA.toast(err.message, 'err');
      }
    });
  }

  function promptText(title, help) {
    return new Promise((resolve) => {
      let value = '';
      PA.modal({
        title,
        body: `<p class="muted small">${esc(help || '')}</p>
          <div class="field"><label for="prompt-value">${esc(title)}</label>
          <input class="input" id="prompt-value" autocomplete="off" ${/OTP|code/i.test(title) ? 'inputmode="numeric" maxlength="6"' : ''} /></div>`,
        actions: [
          { label: 'Cancel', onClick: () => { resolve(''); } },
          { label: 'Submit', primary: true, onClick: (back) => { value = back.querySelector('#prompt-value').value.trim(); resolve(value); } }
        ],
        onMount: (back) => { back.querySelector('#prompt-value').focus(); }
      });
    });
  }

  async function orderDetail(match, ctx) {
    const code = decodeURIComponent(match[1]);
    const data = await PA.api('GET', '/seller/orders?status=all');
    cache.orders = data.orders;
    const o = data.orders.find((x) => x.code === code);
    if (!ctx.isCurrent()) return;
    if (!o) {
      PA.set(`<div class="card">${PA.empty('🔍', 'Order not found', 'This order does not belong to your shop.', '<a class="btn" href="#/orders">Back to orders</a>')}</div>`);
      return;
    }
    PA.set(`${orderCard(o)}
      <div class="card"><div class="row"><a class="btn" href="#/orders">← All orders</a>
        ${o.receiptUrl ? `<a class="btn" href="${o.receiptUrl}" target="_blank" rel="noopener">${PA.icon('print')} Receipt</a>` : ''}
        <span class="spacer"></span><span class="muted small">Stock was reserved when the customer paid and is deducted when you accept.</span></div></div>`);
    wireOrders();
  }

  /* ------------------------------------------------------------- catalogue */
  async function catalogue(match, ctx) {
    const data = await PA.api('GET', '/seller/products');
    cache.products = data.products;
    if (!ctx.isCurrent()) return;
    PA.set(`
      <div class="space-between">
        <div><h1>Catalogue & stock</h1><p class="muted small">Edits here change the customer storefront immediately — there is no second copy of the catalogue.</p></div>
        <a class="btn btn-primary" href="#/catalogue/new">${PA.icon('plus')} Add product</a>
      </div>
      <div class="card flush">
        <div class="table-wrap"><table class="data">
          <thead><tr><th>Product</th><th>Category</th><th class="num">Price</th><th class="num">MRP</th>
            <th class="num">Stock</th><th class="num">Reserved</th><th>Status</th><th></th></tr></thead>
          <tbody>
            ${data.products.map((p) => `<tr data-product="${esc(p.id)}">
              <td><b>${esc(p.emoji || '📦')} ${esc(p.name)}</b><div class="muted small">${esc(p.unit || '')}${p.brand ? ' · ' + esc(p.brand) : ''}</div></td>
              <td class="small">${esc(p.category)}</td>
              <td class="num"><input class="input" style="width:96px;min-height:34px;text-align:right" data-price value="${Math.round(p.price / 100)}" inputmode="decimal" aria-label="Price in rupees for ${esc(p.name)}" /></td>
              <td class="num small">${PA.money(p.mrp)}</td>
              <td class="num"><input class="input" style="width:82px;min-height:34px;text-align:right" data-stock value="${p.stock}" inputmode="numeric" aria-label="Stock for ${esc(p.name)}" /></td>
              <td class="num small">${p.reserved}</td>
              <td>${p.active ? PA.status('published', 'Live') : PA.status('hidden', 'Hidden')}
                ${p.stock - p.reserved <= p.lowAt ? '<div class="small" style="color:#8a5b00">Low stock</div>' : ''}</td>
              <td class="right"><button class="btn btn-sm btn-primary" data-save>Save</button>
                <button class="btn btn-sm" data-toggle>${p.active ? 'Hide' : 'Publish'}</button></td>
            </tr>`).join('')}
          </tbody>
        </table></div>
        <div class="card-foot muted small">${data.products.length} product(s) · reserved quantities are held by open orders and cannot be sold twice.</div>
      </div>
    `);

    PA.onAll('[data-save]', 'click', async (e) => {
      const row = e.currentTarget.closest('tr');
      const id = row.dataset.product;
      const price = Math.round(Number(row.querySelector('[data-price]').value) * 100);
      const stock = Number(row.querySelector('[data-stock]').value);
      if (!Number.isFinite(price) || price < 100) return PA.toast('Price must be at least ₹1.', 'err');
      if (!Number.isFinite(stock) || stock < 0) return PA.toast('Stock cannot be negative.', 'err');
      e.currentTarget.disabled = true;
      try {
        const res = await PA.api('PATCH', `/seller/products/${encodeURIComponent(id)}`, { price, stock });
        PA.toast(res.message || 'Saved.');
        PA.render();
      } catch (err) { e.currentTarget.disabled = false; PA.toast(err.message, 'err'); }
    });
    PA.onAll('[data-toggle]', 'click', async (e) => {
      const row = e.currentTarget.closest('tr');
      const id = row.dataset.product;
      const product = cache.products.find((p) => p.id === id);
      e.currentTarget.disabled = true;
      try {
        await PA.api('PATCH', `/seller/products/${encodeURIComponent(id)}`, { active: !product.active });
        PA.toast(product.active ? 'Hidden from the storefront.' : 'Published to the storefront.');
        PA.render();
      } catch (err) { e.currentTarget.disabled = false; PA.toast(err.message, 'err'); }
    });
  }

  async function newProduct() {
    const cats = await PA.api('GET', '/seller/products');
    const categories = [...new Set(cats.products.map((p) => p.category))];
    PA.set(`
      <div class="space-between"><div><h1>Add a product</h1>
        <p class="muted small">It appears in the customer storefront for your shop as soon as you save.</p></div>
        <a class="btn" href="#/catalogue">← Catalogue</a></div>
      <form class="card stack" id="new-product" novalidate>
        <div class="grid g2">
          ${PA.field('name', 'Product name', '', { required: true, placeholder: 'Amul Taaza Toned Milk 1 L' })}
          ${PA.field('brand', 'Brand', '', { placeholder: 'Amul' })}
          ${PA.field('category', 'Category slug', categories[0] || 'groceries', { help: categories.length ? 'Existing: ' + categories.join(', ') : 'Use a category slug such as groceries.' })}
          ${PA.field('unit', 'Unit / pack size', '1 pc', { placeholder: '1 L pack' })}
          ${PA.field('price', 'Selling price (₹)', '', { type: 'number', min: 1, step: 1, required: true })}
          ${PA.field('mrp', 'MRP (₹)', '', { type: 'number', min: 1, step: 1 })}
          ${PA.field('stock', 'Stock quantity', 10, { type: 'number', min: 0, step: 1 })}
          ${PA.field('lowStock', 'Low-stock alert at', 5, { type: 'number', min: 0, step: 1 })}
          ${PA.field('returnDays', 'Return window (days)', 0, { type: 'number', min: 0, max: 30, step: 1 })}
          ${PA.field('emoji', 'List icon', '🛍️', { help: 'A single emoji used on cards until a photo is added.' })}
        </div>
        <div class="form-error hidden" id="np-error"></div>
        <div class="row"><button class="btn btn-primary" type="submit">Publish product</button>
          <span class="muted small">Prices and stock are validated on the server.</span></div>
      </form>`);
    PA.on('#new-product', 'submit', async (e) => {
      e.preventDefault();
      const val = (id) => document.getElementById(id).value.trim();
      const body = {
        name: val('name'), brand: val('brand'), category: val('category'), unit: val('unit'),
        price: Math.round(Number(val('price')) * 100), mrp: val('mrp') ? Math.round(Number(val('mrp')) * 100) : undefined,
        stock: Number(val('stock')), lowStock: Number(val('lowStock')), returnDays: Number(val('returnDays')), emoji: val('emoji')
      };
      const errBox = document.getElementById('np-error');
      errBox.classList.add('hidden');
      try {
        const res = await PA.api('POST', '/seller/products', body);
        PA.toast(res.message || 'Product published.');
        PA.go('#/catalogue');
      } catch (err) {
        errBox.textContent = err.message;
        errBox.classList.remove('hidden');
      }
    });
  }

  /* --------------------------------------------------------------- returns */
  function returnCard(r) {
    const evidence = (r.images || []).map((src) =>
      '<a href="' + esc(src) + '" target="_blank" rel="noopener"><img src="' + esc(src) +
      '" alt="Return evidence" style="width:64px;height:64px;object-fit:cover;border-radius:10px;border:1px solid var(--border)" /></a>'
    ).join('');
    const closed = ['completed', 'rejected'].includes(r.status);
    const actions = closed ? '' : `
      <div class="card-foot" style="margin:14px -18px -18px">
        <div class="row">
          ${r.status === 'requested' ? '<button class="btn btn-sm" data-ret="review" data-code="' + esc(r.code) + '">Mark under review</button>' : ''}
          <button class="btn btn-sm btn-primary" data-ret="approve" data-code="${esc(r.code)}">Approve refund</button>
          <button class="btn btn-sm btn-success" data-ret="complete" data-code="${esc(r.code)}">Refund completed</button>
          <button class="btn btn-sm btn-danger" data-ret="reject" data-code="${esc(r.code)}">Reject</button>
        </div>
      </div>`;
    return `
      <article class="card">
        <div class="space-between">
          <div><div class="row tight"><b class="mono">${esc(r.code)}</b>${PA.status(r.status)}</div>
            <div class="muted small">Order ${esc(r.orderCode)} · ${esc(r.sellerOrderCode)} · ${PA.date(r.createdAt)}</div></div>
          <b>${PA.money(r.amount)}</b>
        </div>
        <div class="grid g2" style="margin-top:12px">
          <div class="item"><span class="emoji">${esc(r.item.emoji || '📦')}</span>
            <div class="grow"><b>${esc(r.item.name)}</b><span>Quantity ${r.item.qty}</span></div></div>
          <div><b class="small">Reason</b><p class="small">${esc(r.reason)}${r.comment ? ' — ' + esc(r.comment) : ''}</p></div>
        </div>
        ${evidence ? '<div class="row" style="margin-top:8px">' + evidence + '</div>' : ''}
        ${actions}
      </article>`;
  }

  async function returns(match, ctx) {
    const data = await PA.api('GET', '/seller/returns');
    if (!ctx.isCurrent()) return;
    const body = data.returns.length
      ? '<div class="stack">' + data.returns.map(returnCard).join('') + '</div>'
      : '<div class="card">' + PA.empty('↩️', 'No return requests', 'Customers can request a return from a delivered order inside the return window.') + '</div>';
    PA.set(`
      <div class="space-between"><div><h1>Returns</h1>
        <p class="muted small">Approving a return moves the refund to processing. Only completing it restocks the item and notifies the customer.</p></div></div>
      ${body}
    `);
    PA.onAll('[data-ret]', 'click', async (e) => {
      const action = e.currentTarget.dataset.ret;
      const code = e.currentTarget.dataset.code;
      let note = '';
      if (action === 'reject' || action === 'complete') {
        note = (await promptText(action === 'reject' ? 'Why is this return rejected?' : 'Refund reference or note', 'Stored on the return and shown to the customer.')) || '';
        if (action === 'reject' && !note) return;
      }
      e.currentTarget.disabled = true;
      try {
        const res = await PA.api('POST', '/seller/returns/' + encodeURIComponent(code) + '/action', { action, note });
        PA.toast(res.message || 'Return updated.');
        PA.render();
      } catch (err) { e.currentTarget.disabled = false; PA.toast(err.message, 'err'); }
    });
  }

  /* -------------------------------------------------------------- settings */
  async function settings() {
    const data = await PA.api('GET', '/seller/shop');
    const s = data.shop;
    cache.shop = s;
    PA.set(`
      <div class="space-between"><div><h1>Shop settings</h1>
        <p class="muted small">Fulfilment, fees and delivery radius are read by checkout on the customer storefront.</p></div></div>
      <form class="card stack" id="shop-settings" novalidate>
        <div class="grid g2">
          <div class="stack">
            <div class="field"><label>Shop status</label>
              <label class="check"><input type="checkbox" id="isOpen" ${s.is_open ? 'checked' : ''} /> Open and accepting orders</label>
              <span class="help">Closing the shop blocks new checkout for your items but never cancels orders already placed.</span>
            </div>
            <div class="field"><label>Fulfilment</label>
              <label class="check"><input type="checkbox" id="delivery" ${s.delivery_enabled ? 'checked' : ''} /> Home delivery</label>
              <label class="check"><input type="checkbox" id="pickup" ${s.pickup_enabled ? 'checked' : ''} /> Store pickup</label>
              <span class="help">At least one option must stay enabled.</span>
            </div>
            ${PA.field('prepMinutes', 'Preparation time (minutes)', s.prep_minutes, { type: 'number', min: 1, max: 240 })}
          </div>
          <div class="stack">
            ${PA.field('deliveryFee', 'Delivery fee (₹)', Math.round(s.delivery_fee_paise / 100), { type: 'number', min: 0 })}
            ${PA.field('pickupFee', 'Pickup fee (₹)', Math.round(s.pickup_fee_paise / 100), { type: 'number', min: 0 })}
            ${PA.field('minOrder', 'Minimum order (₹)', Math.round(s.min_order_paise / 100), { type: 'number', min: 0 })}
            ${PA.field('radiusKm', 'Delivery radius (km)', s.radius_km, { type: 'number', min: 0.5, max: 50, step: 0.5 })}
            <div class="grid g2">
              ${PA.field('opensAt', 'Opens at', s.opens_at, { placeholder: '07:00' })}
              ${PA.field('closesAt', 'Closes at', s.closes_at, { placeholder: '23:00' })}
            </div>
            ${PA.field('phone', 'Public phone', s.phone || '', { placeholder: '011 4000 1234' })}
          </div>
        </div>
        <div class="form-error hidden" id="ss-error"></div>
        <div class="row"><button class="btn btn-primary" type="submit">Save shop settings</button>
          <span class="muted small">Service PINs: ${(s.service_pincodes || []).join(', ') || 'all serviceable areas'}</span></div>
      </form>`);
    PA.on('#shop-settings', 'submit', async (e) => {
      e.preventDefault();
      const val = (id) => document.getElementById(id).value.trim();
      const errBox = document.getElementById('ss-error');
      errBox.classList.add('hidden');
      try {
        const res = await PA.api('PATCH', '/seller/shop', {
          isOpen: document.getElementById('isOpen').checked,
          deliveryEnabled: document.getElementById('delivery').checked,
          pickupEnabled: document.getElementById('pickup').checked,
          prepMinutes: Number(val('prepMinutes')),
          deliveryFee: Math.round(Number(val('deliveryFee')) * 100),
          pickupFee: Math.round(Number(val('pickupFee')) * 100),
          minOrder: Math.round(Number(val('minOrder')) * 100),
          radiusKm: Number(val('radiusKm')),
          opensAt: val('opensAt'), closesAt: val('closesAt'), phone: val('phone')
        });
        PA.toast(res.message || 'Saved.');
      } catch (err) {
        errBox.textContent = err.message;
        errBox.classList.remove('hidden');
      }
    });
  }

  PA.start({
    mode: 'seller',
    title: 'Seller Hub',
    home: '#/overview',
    nav: NAV,
    routes: [
      [/^\/overview$/, overview],
      [/^\/orders$/, orders],
      [/^\/orders\/([A-Za-z0-9-]+)$/, orderDetail],
      [/^\/catalogue$/, catalogue],
      [/^\/catalogue\/new$/, newProduct],
      [/^\/returns$/, returns],
      [/^\/settings$/, settings]
    ]
  });
})();
