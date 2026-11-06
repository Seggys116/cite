import { h } from '../dom.js';
import { nodeApi } from '../api.js';
import {
  button, card, confirmDialog, dataTable, field, kvList, loadInto, openModal, pill, skeletonBlock, toast, withBusy, formatError, fmtInt,
} from '../ui.js';
import { isUnsupported } from '../archivelib.js';
import { certToolsCard } from './certTools.js';
import {
  HTTPS_OFF_NOTE, MANUAL_BADGE, MAX_PEM_BYTES, NAME_RULE, SUPPORT_NOTE, isManualCert, expiryState, hostList, parsePort, parseRanges, rangesSaveNote, rangesToText,
  shortFingerprint, uncoveredNote, uploadProblem,
} from '../certlib.js';

const MAX_SAN_CHIPS = 4;

function sanChips(sans) {
  const list = Array.isArray(sans) ? sans : [];
  if (!list.length) return h('span', { class: 'muted' }, '-');
  const extra = list.length - MAX_SAN_CHIPS;
  return h('div', { class: 'chips' },
    list.slice(0, MAX_SAN_CHIPS).map((san) => h('span', { class: 'chip chip-static mono', title: san }, san)),
    extra > 0 ? h('span', { class: 'muted', title: list.slice(MAX_SAN_CHIPS).join(', ') }, `+${extra} more`) : null);
}

function expiryCell(cert) {
  if (!cert.not_after) return h('span', { class: 'muted' }, '-');
  const state = expiryState(cert.days_left);
  return h('div', { class: 'stack-sm' },
    h('span', { class: 'mono' }, String(cert.not_after || '').slice(0, 10) || '-'),
    state.kind ? pill(state.text, state.kind) : h('span', { class: 'muted' }, state.text));
}

// Reads a chosen file into the box so the key and chain can be pasted or picked; the file input is emptied right after
function fileButton(label, area, fail) {
  const input = h('input', { type: 'file', accept: '.pem,.crt,.cer,.key,.txt,text/plain', hidden: true, 'aria-label': label });
  input.addEventListener('change', () => {
    const file = input.files && input.files[0];
    input.value = '';
    if (!file) return;
    if (file.size > MAX_PEM_BYTES) {
      fail(`That file is larger than ${MAX_PEM_BYTES / 1024} KiB.`);
      return;
    }
    const reader = new FileReader();
    reader.addEventListener('load', () => {
      // A dialog closed mid-read must not receive the file afterwards
      if (!area.isConnected) return;
      area.value = String(reader.result || '');
      fail('');
    });
    reader.addEventListener('error', () => fail('That file could not be read.'));
    reader.readAsText(file);
  });
  return h('span', {}, input, button(label, { size: 'sm', onClick: () => input.click() }));
}

function pemArea(label, placeholder) {
  return h('textarea', {
    class: 'textarea mono', rows: '7', placeholder, 'aria-label': label, autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off', wrap: 'off',
  });
}

// Upload when no certificate is given, replace when one is; the key never leaves the textarea except in the request body
export function openCertificateDialog({ node, existing, onDone }) {
  const n = nodeApi(node);
  const replacing = Boolean(existing);
  const nameIn = h('input', { class: 'input', type: 'text', maxlength: '64', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Certificate name', placeholder: 'main-site', value: replacing ? existing.name : '' });
  const certIn = pemArea('Certificate chain in PEM format', '-----BEGIN CERTIFICATE-----');
  const keyIn = pemArea('Private key in PEM format', '-----BEGIN PRIVATE KEY-----');
  const errorBox = h('div', { class: 'form-error', role: 'alert', hidden: true });
  const status = h('p', { class: 'muted', role: 'status', 'aria-live': 'polite' });
  const fail = (message) => {
    errorBox.textContent = message;
    errorBox.hidden = !message;
  };
  const wipe = () => {
    certIn.value = '';
    keyIn.value = '';
  };
  const submit = button(replacing ? 'Replace certificate' : 'Upload certificate', { kind: 'primary', iconName: replacing ? 'refresh' : 'plus' });
  const cancel = button('Cancel', { onClick: () => modal.close() });

  submit.addEventListener('click', async () => {
    fail('');
    const problem = uploadProblem({ name: nameIn.value, certificate: certIn.value, privateKey: keyIn.value, requireName: !replacing });
    if (problem) {
      fail(problem);
      return;
    }
    const body = { certificate: certIn.value, private_key: keyIn.value };
    const name = nameIn.value.trim();
    if (!replacing) body.name = name;
    else if (name && name !== existing.name) body.name = name;
    status.textContent = replacing ? 'Replacing the certificate...' : 'Uploading the certificate...';
    try {
      const saved = await withBusy(submit, () => (replacing
        ? n.put('/certificates/' + encodeURIComponent(existing.id), body)
        : n.post('/certificates', body))).finally(() => {
        body.private_key = '';
        body.certificate = '';
      });
      wipe();
      modal.close();
      toast(replacing ? 'Certificate replaced' : 'Certificate uploaded', 'success');
      const warning = saved && typeof saved.warning === 'string' ? saved.warning : '';
      if (warning) toast(warning, 'info', 10000);
      if (onDone) onDone({ name: (saved && saved.name) || name, warning });
    } catch (ex) {
      // The key leaves the form on failure too, so it never lingers; the server text is shown exactly as sent
      keyIn.value = '';
      status.textContent = 'The private key box was cleared. Add the key again to retry.';
      fail(formatError(ex));
    }
  });

  const content = h('div', { class: 'form' },
    h('p', { class: 'muted' }, 'Paste the PEM text or choose the files. The private key is sent to the node over the dashboard connection and is never shown again.'),
    field('Name', nameIn, replacing ? 'Change the name or leave it as it is. ' + NAME_RULE : NAME_RULE),
    h('div', { class: 'field' },
      h('div', { class: 'section-row' }, h('span', { class: 'field-label' }, 'Certificate chain'), fileButton('Choose certificate file', certIn, fail)),
      certIn, h('span', { class: 'hint' }, 'The certificate first, then any intermediate certificates.')),
    h('div', { class: 'field' },
      h('div', { class: 'section-row' }, h('span', { class: 'field-label' }, 'Private key'), fileButton('Choose key file', keyIn, fail)),
      keyIn, h('span', { class: 'hint' }, 'Unencrypted PEM. It is cleared from this form when the dialog closes.')),
    errorBox, status);
  const modal = openModal({
    title: replacing ? `Replace ${existing.name}` : 'Upload a certificate',
    content,
    actions: [cancel, submit],
    wide: true,
    onClose: wipe,
  });
  return modal;
}

// The HTTPS listener is off until a port is set, so this offers to set it with the same whole-settings write the other panels use
function httpsPortControl(n, again) {
  const input = h('input', { class: 'input mono', type: 'number', min: '1', max: '65535', inputmode: 'numeric', value: '443', 'aria-label': 'HTTPS port' });
  const save = button('Save port', { kind: 'primary', iconName: 'check' });
  const errorBox = h('div', { class: 'form-error', role: 'alert', hidden: true });
  save.addEventListener('click', async () => {
    errorBox.hidden = true;
    const parsed = parsePort(input.value);
    if (parsed.error) {
      errorBox.textContent = parsed.error;
      errorBox.hidden = false;
      return;
    }
    try {
      await withBusy(save, async () => {
        const current = await n.get('/settings');
        await n.put('/settings', { ...current, https_port: parsed.value });
      });
      toast('HTTPS port saved', 'success');
      again();
    } catch (ex) {
      errorBox.textContent = formatError(ex);
      errorBox.hidden = false;
    }
  });
  return h('div', { class: 'stack-sm' },
    h('p', { class: 'notice warn', role: 'note' }, HTTPS_OFF_NOTE),
    h('div', { class: 'inline-form' }, input, save),
    errorBox);
}

export function certificatesPanel(node) {
  const n = nodeApi(node);
  const status = h('p', { class: 'muted', role: 'status', 'aria-live': 'polite' });
  const host = h('div', {});
  const uploadBtn = button('Upload certificate', { kind: 'primary', iconName: 'plus' });
  let run = null;

  const load = async () => {
    try {
      const list = await n.get('/certificates');
      uploadBtn.hidden = false;
      return list || { items: [] };
    } catch (ex) {
      if (isUnsupported(ex)) {
        uploadBtn.hidden = true;
        return null;
      }
      throw ex;
    }
  };

  const done = (verb) => (info) => {
    status.textContent = `${verb} ${info.name}.${info.warning ? ' Node warning: ' + info.warning : ''}`;
    run();
  };

  const remove = async (cert, again) => {
    const ok = await confirmDialog({
      title: 'Delete certificate',
      message: `Delete ${cert.name} from ${node}? Hosts that only this certificate covers stop being served over HTTPS until another one covers them. This cannot be undone.`,
      confirmLabel: 'Delete',
      danger: true,
    });
    if (!ok) return;
    try {
      await n.del('/certificates/' + encodeURIComponent(cert.id));
      status.textContent = `Deleted ${cert.name}.`;
      again();
    } catch (ex) {
      toast(formatError(ex), 'error');
    }
  };

  // Files placed on the node by hand are read-only through the API, so they get a badge instead of buttons
  const rowActions = (cert, again) => (isManualCert(cert) ? pill(MANUAL_BADGE, 'muted') : h('div', { class: 'pill-row' },
    button('Replace', {
      size: 'sm', iconName: 'refresh', title: `Replace ${cert.name}`,
      onClick: () => openCertificateDialog({ node, existing: cert, onDone: done('Replaced') }),
    }),
    button('Delete', { size: 'sm', iconName: 'trash', kind: 'danger', title: `Delete ${cert.name}`, onClick: () => remove(cert, again) })));

  run = loadInto(host, load, (list, again) => {
    if (list === null) return h('p', { class: 'notice', role: 'note' }, SUPPORT_NOTE);
    const items = list.items || [];
    const missing = uncoveredNote(list.uncovered_hosts);
    const parts = [];
    if (missing) parts.push(h('p', { class: 'notice warn', role: 'note' }, missing));
    if (list.dir_ready === false) parts.push(h('p', { class: 'notice warn', role: 'note' }, 'The certificate directory on this node is not ready, so uploaded certificates cannot be served yet.'));
    if (list.https_port === null || list.https_port === undefined) parts.push(httpsPortControl(n, again));
    else parts.push(kvList([['HTTPS port', h('span', { class: 'mono' }, String(list.https_port))]]));
    parts.push(items.length ? dataTable({
      columns: [
        {
          label: 'Name',
          render: (c) => h('div', { class: 'stack-sm' }, h('b', { class: 'cell-strong' }, c.name), h('span', { class: 'mono muted wrap-any' }, c.subject || '-'),
            c.warning ? h('span', { class: 'error-text', role: 'note' }, c.warning) : null),
        },
        { label: 'Names', render: (c) => sanChips(c.sans) },
        { label: 'Issuer', render: (c) => h('span', { class: 'wrap-any' }, c.issuer || '-') },
        { label: 'Expires', render: expiryCell },
        { label: 'Key', render: (c) => h('span', { class: 'mono muted' }, c.key_type || '-') },
        { label: 'SHA-256', render: (c) => h('span', { class: 'mono muted', title: c.fingerprint_sha256 || '' }, shortFingerprint(c.fingerprint_sha256)) },
        { label: 'Covers', render: (c) => h('span', { class: 'muted' }, hostList(c.covers)) },
        { label: 'Actions', render: (c) => rowActions(c, again) },
      ],
      rows: items,
    }) : h('p', { class: 'muted' }, 'No certificates yet. Upload one to serve HTTPS for your site hosts from this node.'));
    if (items.length) parts.push(h('p', { class: 'muted' }, `${fmtInt(items.length)} ${items.length === 1 ? 'certificate' : 'certificates'} on this node.`));
    return h('div', { class: 'stack-sm' }, parts);
  }, { skeleton: () => skeletonBlock(80) });

  uploadBtn.addEventListener('click', () => openCertificateDialog({ node, onDone: done('Uploaded') }));
  return h('div', { class: 'stack' },
    card({
      title: 'Certificates',
      subtitle: 'TLS certificates the node serves for HTTPS. Sites where Cloudflare handles HTTPS do not need one.',
      actions: [uploadBtn],
      body: h('div', { class: 'stack-sm' }, host, status),
    }),
    certToolsCard(node, () => run()));
}

// Shows the list the edge trusts and lets it be overridden; an empty override means the node's built-in list
export function cloudflarePanel(node) {
  const n = nodeApi(node);
  const host = h('div', {});
  loadInto(host, async () => {
    try {
      const [info, settings] = await Promise.all([n.get('/cloudflare/ranges'), n.get('/settings')]);
      return { info, settings };
    } catch (ex) {
      if (isUnsupported(ex)) return null;
      throw ex;
    }
  }, (data, again) => {
    if (data === null) return h('p', { class: 'notice', role: 'note' }, 'This node needs a connector update before it can report or change its Cloudflare ranges.');
    const { info, settings } = data;
    const custom = info.source === 'custom';
    const area = h('textarea', {
      class: 'textarea mono', rows: '8', placeholder: '173.245.48.0/20', 'aria-label': 'Custom Cloudflare ranges, one per line', autocomplete: 'off', spellcheck: 'false', wrap: 'off',
    });
    area.value = rangesToText(settings.cloudflare_ranges);
    const result = h('p', { class: 'hint', role: 'status', 'aria-live': 'polite' });
    const errorBox = h('div', { class: 'form-error', role: 'alert', hidden: true });
    const save = button('Save ranges', { kind: 'primary', iconName: 'check' });
    const reset = button('Use built-in list', { iconName: 'refresh', disabled: !(settings.cloudflare_ranges || []).length });
    const sync = () => {
      const parsed = parseRanges(area.value);
      result.textContent = parsed.errors.length ? parsed.errors[0] : rangesSaveNote(parsed.ranges);
    };
    area.addEventListener('input', sync);
    sync();

    const write = async (ranges, message, trigger) => {
      errorBox.hidden = true;
      try {
        await withBusy(trigger, async () => {
          const current = await n.get('/settings');
          await n.put('/settings', { ...current, cloudflare_ranges: ranges });
        });
        toast(message, 'success');
        again();
      } catch (ex) {
        errorBox.textContent = formatError(ex);
        errorBox.hidden = false;
      }
    };
    save.addEventListener('click', () => {
      const parsed = parseRanges(area.value);
      if (parsed.errors.length) {
        errorBox.textContent = parsed.errors.slice(0, 3).join(' ');
        errorBox.hidden = false;
        return;
      }
      write(parsed.ranges, parsed.ranges.length ? 'Cloudflare ranges saved' : 'Using the built-in list', save);
    });
    reset.addEventListener('click', async () => {
      const ok = await confirmDialog({ title: 'Use built-in list', message: `Discard the custom Cloudflare ranges on ${node} and use the list built into the node?`, confirmLabel: 'Use built-in list' });
      if (ok) write([], 'Using the built-in list', reset);
    });

    return h('div', { class: 'stack' },
      card({
        title: 'Active ranges',
        subtitle: 'Sites set to Only allow traffic through the Cloudflare proxy accept requests from these addresses and no others.',
        body: h('div', { class: 'stack-sm' },
          kvList([
            ['Source', pill(custom ? 'Custom list' : 'Built-in list', 'muted')],
            ['Updated', h('span', { class: 'mono' }, info.updated || '-')],
            ['Ranges', h('span', { class: 'mono' }, String((info.ranges || []).length))],
          ]),
          h('pre', { class: 'code-block' }, (info.ranges || []).join('\n'))),
      }),
      card({
        title: 'Override the list',
        subtitle: 'Use this only if Cloudflare publishes new ranges before the node is updated.',
        body: h('div', { class: 'form' },
          field('Custom ranges', area, 'One CIDR range per line, IPv4 or IPv6. A wrong list locks real visitors out of sites that only accept Cloudflare traffic.'),
          result, errorBox,
          h('div', { class: 'form-actions' }, reset, save)),
      }));
  }, { skeleton: () => skeletonBlock(160) });
  return host;
}
