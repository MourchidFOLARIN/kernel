/**
 * Markdown minimal (maison) : gras, italique, code inline, blocs ```, listes, liens.
 * Échappe tout HTML avant de réinjecter. Coloration basique (mots-clés) pour blocs de code.
 */
const KW = /\b(const|let|var|function|return|if|else|for|while|class|import|from|export|async|await|def|print|True|False|None|and|or|not)\b/g;

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function colorize(code) {
  return esc(code).replace(KW, '<span class="tok-kw">$1</span>')
    .replace(/(&quot;.*?&quot;|&#39;.*?&#39;)/g, '<span class="tok-str">$1</span>')
    .replace(/(^|\s)(#.*)$/gm, '$1<span class="tok-com">$2</span>');
}

export function renderMarkdown(src) {
  if (!src) return "";
  const fences = [];
  let text = String(src).replace(/```(\w*)\n([\s\S]*?)```/g, (_, lang, code) => {
    const i = fences.length;
    fences.push(`<pre class="md-code" data-lang="${esc(lang)}"><button type="button" class="copy-btn" data-copy="${i}">copier</button><code>${colorize(code.replace(/\n$/, ""))}</code></pre>`);
    return `\u0000F${i}\u0000`;
  });
  text = esc(text);
  text = text.replace(/`([^`]+)`/g, "<code class=\"md-inline\">$1</code>");
  text = text.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
  text = text.replace(/\*(.+?)\*/g, "<em>$1</em>");
  text = text.replace(/@([a-zA-Z0-9_.-]{2,32})/g, '<span class="mention">@$1</span>');
  text = text.replace(/\[([^\]]+)\]\((https?:\/\/[^)]+)\)/g, '<a href="$2" rel="noopener noreferrer" target="_blank">$1</a>');
  text = text.replace(/^[-*] (.+)$/gm, "<li>$1</li>");
  text = text.replace(/(?:<li>.*<\/li>\n?)+/g, (m) => `<ul>${m}</ul>`);
  text = text.replace(/\n/g, "<br>");
  text = text.replace(/\u0000F(\d+)\u0000/g, (_, i) => fences[Number(i)]);
  return text;
}

/** Attache les boutons « copier » après injection HTML. */
export function bindCopyButtons(root) {
  root.querySelectorAll("[data-copy]").forEach((btn) => {
    btn.onclick = () => {
      const code = btn.parentElement.querySelector("code")?.innerText || "";
      navigator.clipboard?.writeText(code);
      btn.textContent = "ok";
      setTimeout(() => { btn.textContent = "copier"; }, 1000);
    };
  });
}
