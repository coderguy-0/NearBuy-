/* NearBuy Runner Portal — nearby delivery offers, pickup with the shop's
 * handover PIN, out-for-delivery and completion with the customer's OTP.
 * All state lives in the shared platform database through /api/partner/runner/*.
 */
(function () {
  'use strict';
  const PA = window.PA;
  const esc = PA.esc;
  let overviewData = null;

  const NAV = [
    { href: '#/overview', label: 'Today', icon: 'bike', count: 'offers' },
    { href: '#/history', label: 'Delivery history', icon: 'route' },
    { href: '#/profile', label: 'Partner profile', icon: 'settings' }
  ];

  async function overview(match, ctx) {
    const data = await PA.api('GET', '/runner/overview');
    overviewData = data;
    if (!ctx.isCurrent()) return;
    PA.badges({ offers: data.offers.length });
    const online = data.runner.status === 'online';
    const chip = document.getElementById('conn-chip');
    if (chip) chip.classList.toggle('off', !online);

    PA.set(`
      <div class="space-between">
        <div><h1>Today</h1>
        <p class="muted small">${online ? 'You are online and receiving offers.' : 'You are offline — go online to receive delivery offers.'}</p></div>
        <div class="row">
          <span class="badge ${online ? 'green' : 'grey'}">${online ? 'Online' : 'Offline'}</span>
          <button class="btn ${online ? '' : 'btn-success'}" id="toggle-online">${online ? 'Go offline' : 'Go online'}</button>
        </div>
      </div>

      <div class="grid g4">
        <div class="card stat"><span class="label">Open offers</span><span class="value">${data.offers.length}</span><span class="hint">One delivery at a time</span></div>
        <div class="card stat"><span class="label">Active delivery</span><span class="value">${data.activeJobCount}</span><span class="hint">Accepted, not yet delivered</span></div>
        <div class="card stat"><span class="label">Paid earnings</span><span class="value">${PA.money(data.earnings)}</span><span class="hint">Delivered assignments</span></div>
        <div class="card stat"><span class="label">Rating</span><span class="value">${data.runner.rating.toFixed(1)}</span><span class="hint">${data.runner.completed} lifetime deliveries</span></div>
      </div>

      ${data.active.length ? `<div class="stack">
        <h2>On the road now</h2>
        ${data.active.map(activeJob).join('')}
      </div>` : ''}

      <div class="stack">
        <h2>Next offer for you</h2>
        ${data.offers.length ? data.offers.map(offerCard).join('')
          : `<div class="card">${PA.empty('📡', data.activeJobCount ? 'Finish your current delivery first' : 'No offers right now',
            data.activeJobCount ? 'NearBuy sends one delivery at a time so you never juggle two customers.' : 'Stay online — sellers request a runner when an order is packed and ready.')}</div>`}
      </div>

      <div class="card">
        <h3>How handover works</h3>
        <div class="grid g3" style="margin-top:12px">
          <div><b class="small">Pick up</b><p class="muted small">The shop shows you a 4-digit handover PIN. Enter it to confirm you collected the right parcel.</p></div>
          <div><b class="small">Deliver</b><p class="muted small">The customer reads you their 6-digit delivery OTP. The order can only close after the server verifies it.</p></div>
          <div><b class="small">Privacy</b><p class="muted small">Customer phone numbers stay masked and the shop phone is only shown for the order you accepted.</p></div>
        </div>
      </div>
    `);

    PA.on('#toggle-online', 'click', async (e) => {
      e.currentTarget.disabled = true;
      try {
        const next = online ? 'offline' : 'online';
        const body = { status: next };
        if (next === 'online' && navigator.geolocation) {
          navigator.geolocation.getCurrentPosition((pos) => {
            PA.api('POST', '/runner/status', { status: 'online', lat: pos.coords.latitude, lng: pos.coords.longitude })
              .then(() => PA.render()).catch((err) => PA.toast(err.message, 'err'));
          }, () => {
            PA.api('POST', '/runner/status', { status: 'online' }).then(() => PA.render()).catch((err) => PA.toast(err.message, 'err'));
          }, { timeout: 6000 });
          PA.toast('Asking your browser for a location so nearby offers are accurate.', 'warn');
          return;
        }
        await PA.api('POST', '/runner/status', body);
        PA.toast(next === 'online' ? 'You are online.' : 'You are offline. No new offers will arrive.');
        PA.render();
      } catch (err) { e.currentTarget.disabled = false; PA.toast(err.message, 'err'); }
    });

    wireJobActions();
  }

  function offerCard(o) {
    const minutes = Math.max(0, Math.round((new Date(o.expiresAt).getTime() - Date.now()) / 60000));
    return `<article class="card">
      <div class="space-between">
        <div>
          <div class="row tight"><b class="mono">${esc(o.orderCode)}</b>${PA.badge('New offer', 'amber')}</div>
          <div class="muted small">${esc(o.shop.emoji || '🏪')} ${esc(o.shop.name)} · ${esc(o.shop.locality)} · ${o.itemCount} item(s)</div>
        </div>
        <div class="right"><b style="font-size:19px;color:var(--deep)">${PA.money(o.payout)}</b>
          <div class="muted small">${o.distanceKm} km to shop</div></div>
      </div>
      <p class="muted small" style="margin-top:10px">${esc(o.deliveryArea)} Offer expires in ${minutes} minute(s).</p>
      <div class="row" style="margin-top:8px">
        <button class="btn btn-success" data-offer="accept" data-id="${esc(o.id)}">Accept delivery</button>
        <button class="btn btn-danger" data-offer="decline" data-id="${esc(o.id)}">Decline</button>
      </div>
    </article>`;
  }

  function activeJob(job) {
    const step = job.status === 'runner_assigned' ? 1 : job.status === 'picked_up' ? 2 : job.status === 'out_for_delivery' ? 3 : 0;
    return `<article class="card">
      <div class="space-between">
        <div>
          <div class="row tight"><b class="mono">${esc(job.orderCode)}</b>${PA.status(job.status)}</div>
          <div class="muted small">${PA.money(job.payout)} payout · collect from ${esc(job.shop.name)}</div>
        </div>
        <a class="btn btn-sm" href="#/jobs/${esc(job.assignmentId)}">Delivery detail</a>
      </div>
      <div class="timeline" style="margin-top:12px">
        ${['Collect from shop', 'Picked up', 'Out for delivery', 'Delivered with OTP'].map((label, i) => `
          <div class="step ${i < step ? 'done' : i === step ? 'current' : ''}"><span class="dot">${i + 1}</span>
            <div><b>${label}</b></div></div>`).join('')}
      </div>
      <div class="row">
        ${job.canPickup ? `<button class="btn btn-primary" data-job="${esc(job.assignmentId)}" data-action="picked_up">Confirm pickup with handover PIN</button>` : ''}
        ${job.status === 'picked_up' ? `<button class="btn btn-primary" data-job="${esc(job.assignmentId)}" data-action="out_for_delivery">Start delivery</button>` : ''}
        ${job.status === 'out_for_delivery' ? `<button class="btn btn-success" data-job="${esc(job.assignmentId)}" data-action="delivered">Complete with customer OTP</button>` : ''}
        <button class="btn btn-sm" data-job="${esc(job.assignmentId)}" data-action="arrived">I have reached the shop</button>
        <button class="btn btn-sm" data-job="${esc(job.assignmentId)}" data-action="share_location">Share my location</button>
      </div>
    </article>`;
  }

  async function jobDetail(match, ctx) {
    const id = match[1];
    const data = overviewData && overviewData.activeJobCount ? overviewData : await PA.api('GET', '/runner/overview');
    overviewData = data;
    if (!ctx.isCurrent()) return;
    const job = data.active.find((j) => j.assignmentId === id);
    if (!job) {
      PA.set(`<div class="card">${PA.empty('🛵', 'No active delivery', 'This delivery is finished, cancelled or not assigned to you.', '<a class="btn" href="#/overview">Back to today</a>')}</div>`);
      return;
    }
    const a = job.address || {};
    PA.set(`
      <div class="space-between"><div><h1>Delivery ${esc(job.orderCode)}</h1>
        <p class="muted small">${PA.status(job.status)} · payout ${PA.money(job.payout)}</p></div>
        <a class="btn" href="#/overview">← Back</a></div>
      <div class="grid g2">
        <div class="card">
          <h3>Collect from</h3>
          ${PA.kv([['Shop', job.shop.name], ['Address', [job.shop.address, job.shop.locality].filter(Boolean).join(', ')], ['Phone', job.shop.phone || 'Not provided']])}
          <div class="row" style="margin-top:12px">
            ${job.canPickup ? `<button class="btn btn-primary" data-job="${esc(job.assignmentId)}" data-action="picked_up">Pick up with handover PIN</button>` : ''}
            ${job.status === 'picked_up' ? `<button class="btn btn-primary" data-job="${esc(job.assignmentId)}" data-action="out_for_delivery">Start delivery</button>` : ''}
            ${job.status === 'out_for_delivery' ? `<button class="btn btn-success" data-job="${esc(job.assignmentId)}" data-action="delivered">Complete with OTP</button>` : ''}
          </div>
        </div>
        <div class="card">
          <h3>Deliver to</h3>
          ${PA.kv([
            ['Customer', job.customer.name],
            ['Phone', job.customer.phoneMasked || 'masked'],
            ['Address', [a.line1, a.line2, a.locality, a.city, a.pincode].filter(Boolean).join(', ')],
            a.landmark ? ['Landmark', a.landmark] : null,
            a.instructions ? ['Instructions', a.instructions] : null
          ])}
          <div class="banner-note" style="margin-top:10px">Photo and exact flat details are shared only for this delivery. Never share the customer’s number.</div>
        </div>
      </div>
      <div class="card">
        <h3>Parcel contents (${job.items.length})</h3>
        <div class="list" style="margin-top:10px">
          ${job.items.map((i) => `<div class="item"><span class="emoji">📦</span><div class="grow"><b>${esc(i.name)}</b></div><b>×${i.qty}</b></div>`).join('')}
        </div>
      </div>
    `);
    wireJobActions();
  }

  function wireJobActions() {
    PA.onAll('[data-offer]', 'click', async (e) => {
      const btn = e.currentTarget;
      btn.disabled = true;
      try {
        const res = await PA.api('POST', `/runner/offers/${encodeURIComponent(btn.dataset.id)}/${btn.dataset.offer}`, {});
        PA.toast(res.message || 'Offer updated.', btn.dataset.offer === 'accept' ? 'ok' : 'warn');
        PA.render();
      } catch (err) { btn.disabled = false; PA.toast(err.message, 'err'); }
    });

    PA.onAll('[data-job]', 'click', async (e) => {
      const btn = e.currentTarget;
      const action = btn.dataset.action;
      const id = btn.dataset.job;
      try {
        if (action === 'picked_up') {
          const pin = await ask('Shop handover PIN', 'Ask the shopkeeper for the 4-digit PIN shown on their Seller Hub order card.', 'numeric', 4);
          if (!pin) return;
          btn.disabled = true;
          const res = await PA.api('POST', `/runner/jobs/${encodeURIComponent(id)}/action`, { action, pickupPin: pin });
          PA.toast(res.message || 'Pickup confirmed.');
          return PA.render();
        }
        if (action === 'delivered') {
          const otp = await ask('Customer delivery OTP', 'Only enter the 6-digit code the customer reads to you after receiving the items.', 'numeric', 6);
          if (!otp) return;
          btn.disabled = true;
          const res = await PA.api('POST', `/runner/jobs/${encodeURIComponent(id)}/action`, { action, otp });
          PA.toast(res.message || 'Delivery completed.');
          return PA.render();
        }
        if (action === 'share_location') {
          if (!navigator.geolocation) return PA.toast('This browser cannot share a location.', 'err');
          navigator.geolocation.getCurrentPosition(async (pos) => {
            try {
              const res = await PA.api('POST', `/runner/jobs/${encodeURIComponent(id)}/location`, { lat: pos.coords.latitude, lng: pos.coords.longitude });
              PA.toast(res.message || 'Location shared.');
            } catch (err) { PA.toast(err.message, 'err'); }
          }, () => PA.toast('Location permission was refused, so nothing was shared.', 'err'));
          return;
        }
        btn.disabled = true;
        const res = await PA.api('POST', `/runner/jobs/${encodeURIComponent(id)}/action`, { action });
        PA.toast(res.message || 'Updated.');
        PA.render();
      } catch (err) { btn.disabled = false; PA.toast(err.message, 'err'); }
    });
  }

  function ask(title, help, mode, maxLength) {
    return new Promise((resolve) => {
      PA.modal({
        title,
        body: `<p class="muted small">${esc(help)}</p>
          <div class="field"><label for="ask-input">${esc(title)}</label>
          <input class="input" id="ask-input" ${mode === 'numeric' ? `inputmode="numeric" maxlength="${maxLength}"` : ''} autocomplete="off" /></div>`,
        actions: [
          { label: 'Cancel', onClick: () => resolve('') },
          { label: 'Verify', primary: true, onClick: (back) => resolve(back.querySelector('#ask-input').value.trim()) }
        ],
        onMount: (back) => back.querySelector('#ask-input').focus()
      });
    });
  }

  async function history(match, ctx) {
    const data = await PA.api('GET', '/runner/overview');
    const jobs = await PA.api('GET', '/runner/jobs');
    if (!ctx.isCurrent()) return;
    PA.set(`
      <div class="space-between"><div><h1>Delivery history</h1>
        <p class="muted small">Payouts recorded for deliveries you completed on the platform.</p></div>
        <div class="badge green">${PA.money(data.earnings)} earned</div></div>
      ${jobs.jobs.length ? `<div class="card flush"><div class="table-wrap"><table class="data">
        <thead><tr><th>Assignment</th><th>Status</th><th class="num">Distance</th><th class="num">Payout</th><th>Created</th><th>Delivered</th></tr></thead>
        <tbody>${jobs.jobs.map((j) => `<tr>
          <td class="mono small">${esc(j.id.slice(0, 8))}</td>
          <td>${PA.status(j.status)}</td>
          <td class="num">${j.distanceKm ?? '—'} km</td>
          <td class="num">${PA.money(j.payout)}</td>
          <td class="small">${PA.dateTime(j.createdAt)}</td>
          <td class="small">${j.deliveredAt ? PA.dateTime(j.deliveredAt) : '—'}</td>
        </tr>`).join('')}</tbody></table></div></div>`
        : `<div class="card">${PA.empty('🧭', 'No deliveries yet', 'Accept an offer from Today and it will appear here after completion.')}</div>`}
    `);
  }

  async function profile(match, ctx) {
    const data = await PA.api('GET', '/me');
    if (!ctx.isCurrent()) return;
    const r = data.runner || {};
    PA.set(`
      <div class="space-between"><div><h1>Partner profile</h1>
        <p class="muted small">Your delivery account on the shared platform.</p></div></div>
      <div class="grid g2">
        <div class="card">
          <h3>Account</h3>
          ${PA.kv([['Name', state().name], ['Email', state().email], ['Phone', state().phone], ['Role', 'Delivery partner']])}
        </div>
        <div class="card">
          <h3>Delivery profile</h3>
          ${PA.kv([['Status', r.status || 'offline'], ['Vehicle', r.vehicle || '—'], ['Rating', r.rating != null ? r.rating.toFixed(1) : '—'], ['Completed', r.completed ?? 0]])}
          <a class="btn btn-sm" style="margin-top:12px" href="#/overview">Manage availability</a>
        </div>
      </div>
      <div class="card">
        <h3>Privacy and safety</h3>
        <p class="muted small" style="margin-top:8px">Customer phone numbers stay masked in your console and the full delivery address is only available for an active assignment. Delivery OTPs are generated per order and verified by the server; a wrong code is rejected and counted against the order.</p>
      </div>
    `);
    function state() { return PA.state.user || {}; }
  }

  PA.start({
    mode: 'runner',
    title: 'Runner Portal',
    home: '#/overview',
    nav: NAV,
    routes: [
      [/^\/overview$/, overview],
      [/^\/jobs\/([A-Za-z0-9-]+)$/, jobDetail],
      [/^\/history$/, history],
      [/^\/profile$/, profile]
    ]
  });
})();
