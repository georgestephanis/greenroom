// The reference plugin: a "Confidential - prepared for {client}" banner on pages opened through a share
// link, filled in from the link's label. It rewrites the HTML as it is served; stored files never change.
// docs/writing-a-plugin.md walks through this file line by line.
import { definePlugin } from '../plugins.js';
import { esc } from '../util.js';

export default definePlugin({
  name: 'watermark',
  version: '1.0.0',
  description: 'Show a confidentiality banner, with the client name, on pages opened through a share link.',
  spaceSettings: {
    text: { type: 'string', default: 'Confidential — prepared for {client}', max: 200, label: 'Banner text ({client} is the link label)' },
    position: { type: 'enum', values: ['top', 'bottom'], default: 'top', label: 'Position' },
  },
  register(ctx) {
    ctx.transform(({ html, viewer, settings }) => {
      if (viewer.kind !== 'link') return; // team members and public visitors see the page untouched
      const text = esc(settings.text).replaceAll('{client}', () => esc(viewer.label || 'you'));
      const edge = settings.position === 'bottom' ? 'bottom' : 'top';
      const banner = `<div role="note" style="position:fixed;left:0;right:0;${edge}:0;z-index:2147483647;padding:6px 12px;background:#111;color:#fff;font:600 13px system-ui;text-align:center">${text}</div>`;
      return /<\/body>/i.test(html) ? html.replace(/<\/body>(?![\s\S]*<\/body>)/i, () => banner + '</body>') : html + banner;
    });
  },
});
