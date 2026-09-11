'use strict';
const form = document.getElementById('setup-form');
form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const error = document.getElementById('error');
  error.textContent = '';
  const payload = {
    local_node: document.getElementById('local-node').value.trim(),
    nodes: document.getElementById('nodes').value,
    vip_prefix: Number(document.getElementById('prefix').value),
    preempt_delay: Number(document.getElementById('delay').value),
    session_hours: Number(document.getElementById('hours').value),
    cookie_secure: document.getElementById('secure').checked,
    totp_issuer: document.getElementById('issuer').value.trim(),
    enrollment_code: document.getElementById('enrollment').value.trim()
  };
  try {
    const response = await fetch('/api/setup', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)});
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'No se pudo guardar');
    form.hidden = true;
    document.getElementById('result').hidden = false;
    document.getElementById('code').value = result.enrollment_code || 'Nodo incorporado; no se genera otro cÃ³digo.';
  } catch (reason) { error.textContent = reason.message || String(reason); }
});
