import { h } from '../dom.js';
import { nodeApi } from '../api.js';
import { button, openModal, toast } from '../ui.js';
import { hasFeature } from '../caplib.js';
import { deployFailureText } from '../historylib.js';

// A node that supports async deploys answers at once; an older node holds the request until health checks pass.
export async function startDeploy({ node, siteId, info, ref, note, targets }) {
  const path = `/sites/${encodeURIComponent(siteId)}/deploy`;
  const body = {};
  if (ref) body.git_ref = ref;
  if (note) body.note = note;
  if (targets) body.targets = targets;
  if (!targets && hasFeature(info, 'deployAsync')) {
    body.wait = false;
    const res = await nodeApi(node).post(path, body);
    return { async: true, id: (res && res.deployment_id) || '' };
  }
  await nodeApi(node).post(path, body);
  return { async: false, id: '' };
}

export async function deployWithToasts(args, { onAfter } = {}) {
  try {
    const res = await startDeploy(args);
    toast(res.async ? `Deploy started on ${args.node}. Follow it in the Status panel.` : `Deployed on ${args.node}.`, 'success');
    if (onAfter) onAfter(res);
    return true;
  } catch (ex) {
    toast(deployFailureText(ex), 'error', 15000);
    if (onAfter) onAfter({ failed: true, error: ex });
    return false;
  }
}

// Redeploying only ever touches the node whose page this is, so the dialog names it
export function askRebuild(labels, node) {
  return new Promise((resolve) => {
    let handle = null;
    const finish = (value) => {
      resolve(value);
      if (handle) handle.close();
    };
    const later = button('Later', { onClick: () => finish(false) });
    const now = button(node ? `Redeploy on ${node}` : 'Redeploy now', { kind: 'primary', iconName: 'rocket', onClick: () => finish(true) });
    handle = openModal({
      title: 'This change needs a rebuild',
      content: h('div', { class: 'stack-sm' },
        h('p', {}, `${labels.join(', ')} ${labels.length === 1 ? 'was' : 'were'} saved. ${labels.length === 1 ? 'It takes' : 'They take'} effect when the site is built again${node ? ` on ${node}` : ''}.`),
        h('p', { class: 'muted' }, 'The live site keeps serving until the new build passes.')),
      actions: [later, now],
      onClose: () => resolve(false),
    });
    now.focus();
  });
}
