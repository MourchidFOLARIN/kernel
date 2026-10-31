"""Chargement des textes éditables (content/*.json, content/*.md) et mini-rendu Markdown sûr."""
import html
import json
import re
from functools import lru_cache

from markupsafe import Markup

from app.config import BASE_DIR

CONTENT_DIR = BASE_DIR / "content"


def load_json(name: str) -> dict:
    # Pas de cache : on peut éditer les textes à chaud sans redémarrer.
    return json.loads((CONTENT_DIR / f"{name}.json").read_text(encoding="utf-8"))


def _inline(text: str) -> str:
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"`(.+?)`", r"<code>\1</code>", text)
    return text


def render_markdown(name: str) -> Markup:
    """Markdown minimal (titres, gras, listes, citations). Le HTML brut est échappé d'abord."""
    lines = html.escape((CONTENT_DIR / f"{name}.md").read_text(encoding="utf-8")).splitlines()
    out, in_list = [], False
    for line in lines:
        s = line.strip()
        if s.startswith("- "):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{_inline(s[2:])}</li>")
            continue
        if in_list:
            out.append("</ul>")
            in_list = False
        if not s:
            continue
        m = re.match(r"^(#{1,3}) (.*)$", s)
        if m:
            lvl = len(m.group(1))
            out.append(f"<h{lvl}>{_inline(m.group(2))}</h{lvl}>")
        elif s.startswith("&gt; "):
            out.append(f'<blockquote class="notice">{_inline(s[5:])}</blockquote>')
        else:
            out.append(f"<p>{_inline(s)}</p>")
    if in_list:
        out.append("</ul>")
    return Markup("\n".join(out))
