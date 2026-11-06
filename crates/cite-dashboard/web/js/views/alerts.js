import { h, clear } from '../dom.js';
import { nodeApi } from '../api.js';
import {
  button, card, field, loadInto, pill, skeletonBlock, toast, toggle, withBusy, formatError,
} from '../ui.js';
import { isUnsupported } from '../archivelib.js';
import {
  ALERT_EVENTS, MAX_RECIPIENTS, MAX_WEBHOOKS, TLS_MODES, WEBHOOK_KINDS, emptyEmail, emptyWebhook, formFromSettings, formSignature, isDirty, maskUrl, secretBadge,
  settingsFromForm, testResultText, testTarget, toggleEvent,
} from '../alertslib.js';

const SUPPORT_NOTE = 'This node needs a connector update before it can send alerts.';

function textInput(label, value, onInput, extra = {}) {
  const input = h('input', {
    class: 'input', type: 'text', autocomplete: 'off', spellcheck: 'false', 'aria-label': label, value, ...extra,
  });
  input.addEventListener('input', () => onInput(input.value));
  return input;
}

// A stored secret is never sent back to the browser, so the box starts empty and an empty box means keep it
function secretInput(label, onInput, placeholder) {
  const input = h('input', {
    class: 'input mono', type: 'password', autocomplete: 'new-password', spellcheck: 'false', autocapitalize: 'off', 'aria-label': label, placeholder, maxlength: '2048',
  });
  input.addEventListener('input', () => onInput(input.value));
  return input;
}

function eventChecks(label, events, onChange) {
  return h('div', { class: 'check-pills', role: 'group', 'aria-label': label },
    ALERT_EVENTS.map((e) => {
      const input = h('input', { type: 'checkbox', checked: events.includes(e.value), 'aria-label': `${label}: ${e.label}` });
      input.addEventListener('change', () => onChange(e.value, input.checked));
      return h('label', { class: 'check-pill' }, input, h('span', {}, e.label));
    }));
}

function testControl(n, target, enabled, disabledReason) {
  const result = h('span', { class: 'hint', role: 'status', 'aria-live': 'polite' });
  const send = button('Send test', { size: 'sm', iconName: 'bolt', disabled: !enabled, title: enabled ? '' : disabledReason });
  send.addEventListener('click', async () => {
    result.textContent = 'Sending...';
    try {
      const reply = await withBusy(send, () => n.post('/alerts/test', { target }));
      result.textContent = testResultText(reply);
    } catch (ex) {
      result.textContent = testResultText({ ok: false, error: formatError(ex) });
    }
  });
  return h('div', { class: 'pill-row' }, send, result);
}

export function alertsPanel(node) {
  const n = nodeApi(node);
  const host = h('div', {});

  loadInto(host, async () => {
    try {
      return await n.get('/alerts');
    } catch (ex) {
      if (isUnsupported(ex)) return null;
      throw ex;
    }
  }, (settings, again) => {
    if (settings === null) return h('p', { class: 'notice', role: 'note' }, SUPPORT_NOTE);
    const form = formFromSettings(settings);
    const savedEmail = Boolean(settings.email);
    const baseline = formSignature(form);
    const errorBox = h('div', { class: 'form-error', role: 'alert', hidden: true });
    const dirtyPill = pill('Unsaved changes', 'warn');
    dirtyPill.hidden = true;
    const save = button('Save alerts', { kind: 'primary', iconName: 'check' });
    const webhooksBox = h('div', { class: 'stack-sm' });
    const emailBox = h('div', { class: 'stack-sm' });

    const sync = () => {
      dirtyPill.hidden = !isDirty(form, baseline);
    };

    const drawWebhooks = () => {
      clear(webhooksBox);
      form.webhooks.forEach((w, i) => {
        const url = secretInput(`Webhook ${i + 1} URL`, (v) => {
          w.url = v;
          sync();
        }, w.storedUrl ? `Saved: ${maskUrl(w.storedUrl)} (leave empty to keep it)` : 'https://...');
        const kind = h('select', { class: 'select', 'aria-label': `Webhook ${i + 1} type` },
          WEBHOOK_KINDS.map((k) => h('option', { value: k.value }, k.label)));
        kind.value = w.kind;
        kind.addEventListener('change', () => {
          w.kind = kind.value;
          sync();
        });
        const remove = button('Remove', {
          size: 'sm', kind: 'danger', iconName: 'trash', title: `Remove webhook ${i + 1}`,
          onClick: () => {
            form.webhooks.splice(i, 1);
            drawWebhooks();
            sync();
          },
        });
        webhooksBox.append(h('div', {
          class: 'stack-sm', role: 'group', 'aria-label': `Webhook ${i + 1}`, style: { border: '1px solid var(--border)', 'border-radius': '8px', padding: 'var(--s3)' },
        },
          h('div', { class: 'inline-form' }, textInput(`Webhook ${i + 1} name`, w.name, (v) => {
            w.name = v;
            sync();
          }, { placeholder: 'Name, for example Ops chat', maxlength: '64' }), kind),
          field('Webhook URL', url, 'Must start with https://. Treat it like a password: anyone with the URL can post to it.'),
          w.storedUrl ? h('span', { class: 'hint' }, ['URL ', pill(secretBadge(true), 'ok'), ' ', h('span', { class: 'mono' }, maskUrl(w.storedUrl))]) : null,
          eventChecks(`Webhook ${i + 1} events`, w.events, (value, on) => {
            w.events = toggleEvent(w.events, value, on);
            sync();
          }),
          h('div', { class: 'section-row' },
            testControl(n, testTarget('webhook', w.id), Boolean(w.id), 'Save the webhook first; tests use the saved settings.'), remove)));
      });
      if (!form.webhooks.length) webhooksBox.append(h('p', { class: 'muted' }, 'No webhooks yet.'));
    };

    const addWebhook = button('Add webhook', { size: 'sm', iconName: 'plus' });
    addWebhook.addEventListener('click', () => {
      if (form.webhooks.length >= MAX_WEBHOOKS) {
        errorBox.textContent = `At most ${MAX_WEBHOOKS} webhooks are allowed.`;
        errorBox.hidden = false;
        return;
      }
      errorBox.hidden = true;
      form.webhooks.push(emptyWebhook());
      drawWebhooks();
      sync();
    });

    const drawEmail = () => {
      clear(emailBox);
      const e = form.email;
      const enable = h('input', { type: 'checkbox', checked: e.enabled, 'aria-label': 'Send alerts by email' });
      enable.addEventListener('change', () => {
        e.enabled = enable.checked;
        if (e.enabled && !e.host && !e.from) Object.assign(e, { ...emptyEmail(), enabled: true });
        drawEmail();
        sync();
      });
      emailBox.append(h('label', { class: 'check-row' }, enable, h('span', {}, 'Send alerts by email')));
      if (!e.enabled) {
        if (savedEmail) emailBox.append(h('p', { class: 'hint' }, 'Saving with this off removes the stored email settings, including the saved password.'));
        return;
      }
      const tls = h('select', { class: 'select', 'aria-label': 'Email encryption' }, TLS_MODES.map((t) => h('option', { value: t.value }, t.label)));
      tls.value = e.tls;
      tls.addEventListener('change', () => {
        e.tls = tls.value;
        sync();
      });
      const password = secretInput('Email password', (v) => {
        e.password = v;
        sync();
      }, e.passwordSet ? 'Saved (leave empty to keep it)' : 'Password');
      const recipients = h('textarea', {
        class: 'textarea', rows: '3', 'aria-label': 'Recipients, one per line', autocomplete: 'off', spellcheck: 'false', placeholder: 'ops@example.com',
      });
      recipients.value = e.to;
      recipients.addEventListener('input', () => {
        e.to = recipients.value;
        sync();
      });
      emailBox.append(
        h('div', { class: 'inline-form' },
          field('Mail server', textInput('Mail server host', e.host, (v) => { e.host = v; sync(); }, { placeholder: 'smtp.example.com' })),
          field('Port', textInput('Mail server port', e.port, (v) => { e.port = v; sync(); }, { inputmode: 'numeric', maxlength: '5' })),
          field('Encryption', tls)),
        h('div', { class: 'inline-form' },
          field('User name', textInput('Email user name', e.username, (v) => { e.username = v; sync(); }, { autocomplete: 'username' })),
          field('Password', password, null)),
        h('p', { class: 'hint' }, ['Password ', pill(secretBadge(e.passwordSet), e.passwordSet ? 'ok' : 'muted'), ' It is write-only: it is never shown again after saving.']),
        field('From address', textInput('Email from address', e.from, (v) => { e.from = v; sync(); }, { type: 'email', placeholder: 'cite@example.com' })),
        field('Recipients', recipients, `One address per line, up to ${MAX_RECIPIENTS}.`),
        eventChecks('Email events', e.events, (value, on) => {
          e.events = toggleEvent(e.events, value, on);
          sync();
        }),
        testControl(n, testTarget('email'), savedEmail && e.enabled, 'Save the email settings first; tests use the saved settings.'));
    };

    const enableSwitch = toggle({
      checked: form.enabled,
      label: 'Alerts enabled',
      onChange: (on) => {
        form.enabled = on;
        sync();
      },
    });
    const cooldown = textInput('Cooldown in seconds', form.cooldown, (v) => {
      form.cooldown = v;
      sync();
    }, { inputmode: 'numeric', maxlength: '5' });

    save.addEventListener('click', async () => {
      errorBox.hidden = true;
      const { errors, settings: body } = settingsFromForm(form);
      if (errors.length) {
        errorBox.textContent = errors.join(' ');
        errorBox.hidden = false;
        return;
      }
      try {
        await withBusy(save, () => n.put('/alerts', body));
        toast('Alerts saved', 'success');
        again();
      } catch (ex) {
        errorBox.textContent = formatError(ex);
        errorBox.hidden = false;
      }
    });

    drawWebhooks();
    drawEmail();
    return h('div', { class: 'stack' },
      card({
        title: 'Alerts',
        subtitle: 'Tell someone when a site goes down, a build fails or a certificate is about to expire.',
        actions: [dirtyPill],
        body: h('div', { class: 'form' },
          h('div', { class: 'section-row' }, h('span', { class: 'field-label' }, 'Send alerts'), enableSwitch),
          field('Cooldown (seconds)', cooldown, 'The same alert is not repeated more often than this. 0 sends every one.')),
      }),
      card({
        title: 'Webhooks',
        subtitle: `Up to ${MAX_WEBHOOKS}. Discord and Slack get a message in their own format; generic webhooks get JSON.`,
        actions: [addWebhook],
        body: webhooksBox,
      }),
      card({ title: 'Email', subtitle: 'Sent through your own mail server.', body: emailBox }),
      errorBox,
      h('div', { class: 'form-actions' }, save));
  }, { skeleton: () => skeletonBlock(200) });
  return host;
}
