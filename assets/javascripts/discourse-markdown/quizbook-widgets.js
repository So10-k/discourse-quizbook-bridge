// Markdown plugin: register [quizbook-X] shortcodes that expand to
// iframes pointing at the Quiz Book site's /embed/X routes.
//
// Discourse auto-discovers files under
// `assets/javascripts/discourse-markdown/*.js` and runs `setup` at
// post-cook time. We register two things:
//   1) An allow-list rule so iframes the plugin emits survive the
//      post HTML sanitizer.
//   2) A markdown-it inline rule that matches `[quizbook-bracket]`
//      etc. and emits `<iframe ...>` HTML.
//
// Available shortcodes:
//   [quizbook-bracket]    → live bracket
//   [quizbook-qotd]       → today's question card
//   [quizbook-standings]  → who's still in
//
// Trailing options (height, width) are not currently parsed; sized
// per widget by SHORTCODES below.

const QUIZ_BASE = "https://quiz.miaswebsites.art";

const SHORTCODES = {
  bracket: { path: "/embed/bracket", height: 540 },
  qotd: { path: "/embed/qotd", height: 320 },
  standings: { path: "/embed/standings", height: 480 },
};

function buildIframeToken(state, key) {
  const widget = SHORTCODES[key];
  if (!widget) return null;
  const src = QUIZ_BASE + widget.path;
  // Construct a tag chain (open / close) with a wrapping div so we
  // can attribute classes for theming.
  const open = state.push("html_inline", "", 0);
  open.content =
    `<div class="qb-widget qb-widget-${key}">` +
    `<iframe ` +
    `src="${src}" ` +
    `loading="lazy" ` +
    `frameborder="0" ` +
    `width="100%" ` +
    `height="${widget.height}" ` +
    `style="border:3px solid #1B2A4E;border-radius:18px;box-shadow:4px 4px 0 0 #1B2A4E;background:transparent;display:block;width:100%;"` +
    `></iframe>` +
    `</div>`;
  return open;
}

export function setup(helper) {
  // Allow the iframe + container div in the cooked HTML. Without this
  // the post sanitizer strips the iframe.
  helper.allowList([
    "div.qb-widget",
    "div.qb-widget-bracket",
    "div.qb-widget-qotd",
    "div.qb-widget-standings",
    "iframe[src]",
    "iframe[loading]",
    "iframe[frameborder]",
    "iframe[width]",
    "iframe[height]",
    "iframe[style]",
  ]);

  helper.registerPlugin((md) => {
    // Match `[quizbook-foo]` as a standalone token on its own line.
    // Inline rule keeps things simple — Discourse already handles
    // bracketed tokens via the linkify pipeline; we run earlier.
    md.inline.ruler.before(
      "emphasis",
      "quizbook_widget",
      function (state, silent) {
        if (silent) return false;
        const start = state.pos;
        const src = state.src;
        if (src[start] !== "[") return false;
        // Find closing bracket
        const close = src.indexOf("]", start + 1);
        if (close === -1) return false;
        const inside = src.slice(start + 1, close).trim();
        // Match "quizbook-<key>" with no spaces.
        const m = inside.match(/^quizbook-([a-z]+)$/);
        if (!m) return false;
        const key = m[1];
        if (!SHORTCODES[key]) return false;
        // Emit + advance.
        buildIframeToken(state, key);
        state.pos = close + 1;
        return true;
      }
    );
  });
}
