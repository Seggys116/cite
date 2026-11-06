import { h, clear } from '../dom.js';
import { nodeApi } from '../api.js';
import {
  button, card, field, pill, toast, withBusy, formatError,
} from '../ui.js';
import { isUnsupported } from '../archivelib.js';
import {
  ACME_PERMISSIONS, DEFAULT_ORIGIN_CA_DAYS, DEFAULT_SELF_SIGNED_DAYS, JOB_POLL_MS, MAX_SELF_SIGNED_DAYS, ORIGIN_CA_PERMISSIONS, ORIGIN_CA_VALIDITY,
  acmeBody, acmeProblem, generateBody, generateProblem, hostChoices, jobReduce, jobStart, jobStatusText, originCaBody, originCaProblem, shouldPoll,
} from '../certissue.js';

const TERMS_URL = 'https://letsencrypt.org/repository/';

function errorBoxes() {
  const errorBox = h('div', { class: 'form-error', role: 'alert', hidden: true });
  const status = h('p', { class: 'muted', role: 'status', 'aria-live': 'polite' });
  const fail = (message) => {
    errorBox.textContent = message;
    errorBox.hidden = !message;
  };
  return { errorBox, status, fail };
}

// Tokens live only in password inputs that are emptied after every submit and whenever the form closes
function tokenInput(label) {
  return h('input', {
    class: 'input mono', type: 'password', autocomplete: 'new-password', spellcheck: 'false', autocapitalize: 'off', 'aria-label': label, maxlength: '256',
  });
}

function permissionList(items) {
  return h('ul', { class: 'stack-sm', style: { 'padding-left': '20px' } }, items.map((p) => h('li', {}, h('code', { class: 'mono' }, p))));
}

function stepList(items) {
  return h('ol', { class: 'stack-sm', style: { 'padding-left': '20px' } }, items.map((t) => h('li', {}, t)));
}

// Checkboxes for the node's known hosts plus a free box for anything else
function hostPicker(choices) {
  const boxes = choices.map((c) => ({
    c, input: h('input', { type: 'checkbox', checked: c.uncovered, 'aria-label': `Cover ${c.host}` }),
  }));
  const extra = h('textarea', {
    class: 'textarea mono', rows: '2', placeholder: '*.example.com', 'aria-label': 'Other host names, separated by spaces or new lines', autocomplete: 'off', spellcheck: 'false', wrap: 'off',
  });
  const list = boxes.length ? h('div', { class: 'stack-sm', role: 'group', 'aria-label': 'Hosts on this node' },
    boxes.map(({ c, input }) => h('label', { class: 'check-row' }, input, h('span', { class: 'mono' }, c.host),
      c.uncovered ? pill('no certificate yet', 'warn') : null))) : h('p', { class: 'muted' }, 'No site hosts found on this node. Type the host names below.');
  const element = h('div', { class: 'field' }, h('span', { class: 'field-label' }, 'Hosts to cover'), list, extra,
    h('span', { class: 'hint' }, 'Wildcards like *.example.com are allowed. Add any host names that are not listed.'));
  return {
    element,
    text: () => boxes.filter(({ input }) => input.checked).map(({ c }) => c.host).concat(extra.value).join('\n'),
  };
}

function nameField() {
  const input = h('input', { class: 'input', type: 'text', maxlength: '64', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Certificate name (optional)', placeholder: 'chosen for you if left blank' });
  return { input, element: field('Name (optional)', input, 'Shown in the certificate list.') };
}

function selfSignedForm(ctx) {
  const hosts = hostPicker(ctx.choices);
  const name = nameField();
  const days = h('input', { class: 'input mono', type: 'number', min: '1', max: String(MAX_SELF_SIGNED_DAYS), value: String(DEFAULT_SELF_SIGNED_DAYS), 'aria-label': 'Days the certificate is valid' });
  const { errorBox, status, fail } = errorBoxes();
  const submit = button('Create certificate', { kind: 'primary', iconName: 'plus' });
  submit.addEventListener('click', async () => {
    fail('');
    const values = { hostsText: hosts.text(), name: name.input.value, days: days.value };
    const problem = generateProblem(values);
    if (problem) {
      fail(problem);
      return;
    }
    status.textContent = 'Creating the certificate on the node...';
    try {
      const saved = await withBusy(submit, () => ctx.n.post('/certificates/generate', generateBody(values)));
      status.textContent = '';
      ctx.finish(saved, 'Certificate created');
    } catch (ex) {
      status.textContent = '';
      fail(formatError(ex));
    }
  });
  const element = h('div', { class: 'form' },
    h('p', {}, 'The node makes a certificate and a private key for you. Nothing is sent to any other service.'),
    h('p', { class: 'notice', role: 'note' }, 'Use this when Cloudflare sits in front of the site with SSL mode Full (not Full strict). Cloudflare accepts it. Visitors who reach the node directly, without Cloudflare, will see a browser warning because no one trusts a certificate you made yourself.'),
    hosts.element, name.element,
    field('Valid for (days)', days, `Up to ${MAX_SELF_SIGNED_DAYS} days. It is not renewed automatically.`),
    errorBox, status,
    h('div', { class: 'form-actions' }, ctx.cancelButton(), submit));
  return { element, wipe: () => {} };
}

function originCaForm(ctx) {
  const hosts = hostPicker(ctx.choices);
  const name = nameField();
  const token = tokenInput('Cloudflare API token');
  const validity = h('select', { class: 'select', 'aria-label': 'How long the certificate is valid' },
    ORIGIN_CA_VALIDITY.map((v) => h('option', { value: String(v.days) }, v.label)));
  validity.value = String(DEFAULT_ORIGIN_CA_DAYS);
  const remember = h('input', { type: 'checkbox', 'aria-label': 'Remember the token on this node' });
  const { errorBox, status, fail } = errorBoxes();
  const submit = button('Request certificate', { kind: 'primary', iconName: 'plus' });
  const wipe = () => {
    token.value = '';
  };
  submit.addEventListener('click', async () => {
    fail('');
    const values = {
      hostsText: hosts.text(), name: name.input.value, token: token.value, days: validity.value, remember: remember.checked,
    };
    const problem = originCaProblem(values);
    if (problem) {
      fail(problem);
      return;
    }
    const body = originCaBody(values);
    wipe();
    status.textContent = 'Asking Cloudflare for an Origin CA certificate...';
    try {
      const saved = await withBusy(submit, () => ctx.n.post('/certificates/origin-ca', body));
      body.cloudflare_token = '';
      status.textContent = '';
      ctx.finish(saved, 'Origin CA certificate created');
    } catch (ex) {
      body.cloudflare_token = '';
      status.textContent = 'The token box was cleared. Paste the token again to retry.';
      fail(formatError(ex));
    }
  });
  const element = h('div', { class: 'form' },
    h('p', {}, 'Cloudflare signs a certificate that only Cloudflare trusts. It works with SSL mode Full (strict), lasts up to 15 years and needs no renewal.'),
    h('p', { class: 'notice', role: 'note' }, 'Use this when every visitor goes through Cloudflare. Browsers that reach the node directly will not trust it.'),
    h('p', { class: 'field-label' }, 'Before you start'),
    stepList([
      'In the Cloudflare dashboard open My Profile, then API Tokens, then Create Token, and choose Create Custom Token.',
      'Give it these permissions:',
      'Limit it to the zones you are covering, create it and copy the token. Cloudflare shows it only once.',
    ]),
    permissionList(ORIGIN_CA_PERMISSIONS),
    hosts.element, name.element,
    field('Cloudflare API token', token, 'Sent to the node over the dashboard connection and used for this request. It is not shown again.'),
    field('Valid for', validity),
    h('div', { class: 'stack-sm' },
      h('label', { class: 'check-row' }, remember, h('span', {}, 'Remember this token on the node')),
      h('span', { class: 'hint' }, 'Off by default. If you turn it on the node keeps the token in its own configuration so it can request the next certificate without asking you. Anyone with access to the node can read it. Leave it off if you would rather paste it again.')),
    errorBox, status,
    h('div', { class: 'form-actions' }, ctx.cancelButton(), submit));
  return { element, wipe };
}

function jobProgress(ctx, jobId, startedAt) {
  const text = h('p', { role: 'status', 'aria-live': 'polite' });
  const banner = h('div', { class: 'form-error', role: 'alert', hidden: true });
  const wrap = h('div', { class: 'stack-sm' }, h('h4', {}, 'Let\'s Encrypt progress'), text, banner);
  let state = jobReduce(jobStart(startedAt), { type: 'accepted', jobId });
  let timer = 0;
  const render = () => {
    text.textContent = jobStatusText(state);
    const ended = state.phase === 'failed' || state.phase === 'lost';
    banner.textContent = ended ? state.error : '';
    banner.hidden = !ended;
  };
  const stop = () => clearTimeout(timer);
  const tick = async () => {
    if (!wrap.isConnected) return;
    try {
      const job = await ctx.n.get('/certificates/acme/' + encodeURIComponent(jobId));
      state = jobReduce(state, { type: 'poll', job }, Date.now());
    } catch (ex) {
      state = jobReduce(state, { type: 'pollError', message: formatError(ex) }, Date.now());
    }
    render();
    if (state.phase === 'issued') {
      toast('Certificate issued', 'success');
      ctx.changed();
    }
    if (shouldPoll(state)) timer = setTimeout(tick, JOB_POLL_MS);
  };
  render();
  timer = setTimeout(tick, JOB_POLL_MS);
  return { element: wrap, stop };
}

function managedList(items) {
  if (!items.length) return null;
  return h('div', { class: 'stack-sm' }, h('h4', {}, 'Let\'s Encrypt certificates on this node'),
    h('ul', { class: 'stack-sm' }, items.map((m) => h('li', {},
      h('span', { class: 'mono' }, (m.hosts || []).join(', ')), ' ',
      pill(m.staging ? `${m.status} (test)` : m.status, m.status === 'issued' ? 'ok' : m.status === 'failed' ? 'bad' : 'muted'),
      m.renew_at ? h('span', { class: 'muted' }, ` renews ${String(m.renew_at).slice(0, 10)}`) : null,
      m.error ? h('span', { class: 'error-text' }, ` ${m.error}`) : null))));
}

function acmeForm(ctx) {
  const hosts = hostPicker(ctx.choices);
  const name = nameField();
  const email = h('input', { class: 'input', type: 'email', autocomplete: 'email', spellcheck: 'false', 'aria-label': 'Email address for expiry notices' });
  const token = tokenInput('Cloudflare API token');
  const staging = h('input', { type: 'checkbox', 'aria-label': 'Test certificates (not trusted)' });
  const agree = h('input', { type: 'checkbox', 'aria-label': 'I agree to the Let\'s Encrypt terms' });
  const { errorBox, status, fail } = errorBoxes();
  const submit = button('Request certificate', { kind: 'primary', iconName: 'plus' });
  const progress = h('div', { class: 'stack-sm' });
  const managed = h('div', {});
  let watcher = null;
  const wipe = () => {
    token.value = '';
  };
  const watch = (jobId) => {
    if (watcher) watcher.stop();
    watcher = jobProgress(ctx, jobId, Date.now());
    clear(progress).append(watcher.element);
  };
  ctx.n.get('/certificates/acme').then((info) => {
    const items = (info && info.managed) || [];
    const list = managedList(items);
    if (list) managed.append(list);
    const running = ((info && info.jobs) || []).find((j) => j.status === 'pending');
    if (running && managed.isConnected && !watcher) {
      managed.append(h('p', { class: 'notice', role: 'note' }, `A request for ${(running.hosts || []).join(', ')} is still running.`),
        button('Watch its progress', { size: 'sm', onClick: () => watch(running.job_id) }));
    }
  }).catch((ex) => {
    if (!isUnsupported(ex)) managed.append(h('p', { class: 'muted' }, 'Could not load the list of Let\'s Encrypt certificates: ' + formatError(ex)));
  });

  submit.addEventListener('click', async () => {
    fail('');
    const values = {
      hostsText: hosts.text(), name: name.input.value, token: token.value, email: email.value, agree: agree.checked, staging: staging.checked,
    };
    const problem = acmeProblem(values);
    if (problem) {
      fail(problem);
      return;
    }
    const body = acmeBody(values);
    wipe();
    status.textContent = 'Sending the request to the node...';
    try {
      const accepted = await withBusy(submit, () => ctx.n.post('/certificates/acme', body));
      body.cloudflare_token = '';
      status.textContent = '';
      if (!accepted || !accepted.job_id) throw new Error('The node did not return a job to follow.');
      watch(String(accepted.job_id));
    } catch (ex) {
      body.cloudflare_token = '';
      status.textContent = 'The token box was cleared. Paste the token again to retry.';
      fail(formatError(ex));
    }
  });

  const element = h('div', { class: 'form' },
    h('p', {}, 'Let\'s Encrypt issues free certificates that every browser trusts, so the site works with or without Cloudflare. They last 90 days and the node renews them on its own.'),
    h('p', { class: 'field-label' }, 'Before you start'),
    stepList([
      'In the Cloudflare dashboard open My Profile, then API Tokens, then Create Token, and choose Create Custom Token.',
      'Give it these permissions, limited to the zones you are covering:',
    ]),
    permissionList(ACME_PERMISSIONS),
    hosts.element, name.element,
    field('Email address', email, 'Let\'s Encrypt writes here if a certificate is about to expire without renewing.'),
    field('Cloudflare API token', token, 'Used to prove you own the domain by adding a temporary DNS record.'),
    h('p', { class: 'notice warn', role: 'note' }, 'Renewal happens every 60 days or so without you, so the node must keep this token. It is stored on the node, in its own configuration, until you delete the certificate. Anyone with access to the node can read it.'),
    h('div', { class: 'stack-sm' },
      h('label', { class: 'check-row' }, agree, h('span', {}, 'I agree to the Let\'s Encrypt terms, and that the token is stored on this node for renewal')),
      h('a', { href: TERMS_URL, target: '_blank', rel: 'noopener noreferrer' }, 'Read the Let\'s Encrypt subscriber agreement')),
    h('div', { class: 'stack-sm' },
      h('label', { class: 'check-row' }, staging, h('span', {}, 'Use test certificates (not trusted)')),
      h('span', { class: 'hint' }, 'Good for a dry run: it has much higher rate limits, but browsers will warn about the result.')),
    errorBox, status,
    h('div', { class: 'form-actions' }, ctx.cancelButton(), submit),
    progress, managed);
  return { element, wipe: () => { wipe(); if (watcher) watcher.stop(); } };
}

const TOOLS = [
  {
    id: 'generate', title: 'Create a certificate for me', build: selfSignedForm,
    blurb: 'Quickest option. The node makes a self-signed certificate. Fine behind Cloudflare with SSL mode Full.',
  },
  {
    id: 'origin', title: 'Cloudflare Origin CA', build: originCaForm,
    blurb: 'A long-lived certificate signed by Cloudflare. Best when all traffic goes through Cloudflare.',
  },
  {
    id: 'acme', title: 'Let\'s Encrypt', build: acmeForm,
    blurb: 'A free certificate every browser trusts, renewed automatically.',
  },
];

export function certToolsCard(node, onChanged) {
  const n = nodeApi(node);
  const stage = h('div', {});
  const result = h('p', { class: 'muted', role: 'status', 'aria-live': 'polite' });
  let active = null;

  const close = () => {
    if (active) active.wipe();
    active = null;
    clear(stage);
    showMenu();
  };
  const changed = () => {
    if (onChanged) onChanged();
  };

  async function loadChoices() {
    const [list, sites] = await Promise.all([
      n.get('/certificates').catch(() => null),
      n.get('/sites').catch(() => []),
    ]);
    return hostChoices(sites, list && list.uncovered_hosts);
  }

  async function open(tool, trigger) {
    const choices = await withBusy(trigger, loadChoices);
    result.textContent = '';
    const ctx = {
      n,
      choices,
      changed,
      cancelButton: () => button('Cancel', { onClick: close }),
      finish: (saved, message) => {
        const warning = saved && typeof saved.warning === 'string' ? saved.warning : '';
        toast(message, 'success');
        if (warning) toast(warning, 'info', 10000);
        close();
        result.textContent = `${message}${saved && saved.name ? ': ' + saved.name : ''}.${warning ? ' Node warning: ' + warning : ''}`;
        changed();
      },
    };
    active = tool.build(ctx);
    clear(stage).append(h('h4', {}, tool.title), active.element);
  }

  function showMenu() {
    stage.append(h('div', { class: 'grid-cards' }, TOOLS.map((tool) => {
      const trigger = button('Start', { kind: 'primary', title: `Start: ${tool.title}` });
      trigger.addEventListener('click', () => open(tool, trigger).catch((ex) => toast(formatError(ex), 'error')));
      return card({ title: tool.title, subtitle: tool.blurb, body: trigger });
    })));
  }

  showMenu();
  return card({
    title: 'Get a certificate',
    subtitle: 'Let the node create or request one instead of uploading files. New certificates appear in the list above.',
    body: h('div', { class: 'stack-sm' }, stage, result),
  });
}
