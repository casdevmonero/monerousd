// THE HTML-SINK CLASS (2026-10-05, ecosystem scanner row "HTML sink fed by an unescaped value"): a REAL DOM sanitizer for
// the sinks that take caller-built markup. Allowlisted tags only; every on* handler, srcdoc, javascript:/vbscript: URL and
// non-image data: URL is removed. Values that can carry outside text are still escaped at their source; this is the
// second layer at the sink, never a substitute for escaping.
const SANITIZE_SAFE_TAGS = new Set(['div', 'span', 'b', 'i', 'em', 'strong', 'p', 'br', 'h1', 'h2', 'h3', 'h4', 'h5', 'pre', 'code', 'button', 'a', 'img', 'small', 'ul', 'ol', 'li', 'table', 'thead', 'tbody', 'tr', 'td', 'th', 'label', 'input', 'select', 'option', 'textarea', 'section', 'article', 'header', 'footer', 'nav', 'hr', 'kbd', 'blockquote', 'details', 'summary', 'svg', 'path', 'circle', 'ellipse', 'rect', 'g', 'defs', 'lineargradient', 'radialgradient', 'stop', 'text', 'title', 'use', 'polygon', 'polyline', 'line', 'clippath', 'mask']);
export function sanitizeHtml(markup) {
  const doc = new DOMParser().parseFromString('<body>' + String(markup == null ? '' : markup) + '</body>', 'text/html');
  const walk = (node) => {
    for (const el of Array.from(node.children)) {
      if (!SANITIZE_SAFE_TAGS.has(el.tagName.toLowerCase())) { el.remove(); continue; }
      for (const a of Array.from(el.attributes)) {
        const n = a.name.toLowerCase(), v = String(a.value || '').trim().toLowerCase().replace(/\s+/g, '');
        const url = n === 'href' || n === 'src' || n === 'action' || n === 'xlink:href' || n === 'formaction';
        if (n.startsWith('on') || n === 'srcdoc' || (url && (v.startsWith('javascript:') || v.startsWith('vbscript:') || (v.startsWith('data:') && !v.startsWith('data:image/'))))) el.removeAttribute(a.name);
      }
      walk(el);
    }
  };
  walk(doc.body);
  return doc.body.innerHTML;
}
