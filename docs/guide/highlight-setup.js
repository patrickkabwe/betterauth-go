((global) => {
    const SHIKI_URL = "https://esm.sh/shiki@2.5.0";
    const LANGS = [
        "go",
        "typescript",
        "javascript",
        "bash",
        "json",
        "yaml",
        "sql",
    ];
    const THEMES = ["github-light", "github-dark"];

    const LANG_ALIASES = {
        ts: "typescript",
        tsx: "typescript",
        js: "javascript",
        jsx: "javascript",
        sh: "bash",
        shell: "bash",
        zsh: "bash",
        yml: "yaml",
        md: "markdown",
        text: "plaintext",
        txt: "plaintext",
        golang: "go",
    };

    /** @type {import('shiki').Highlighter | null} */
    let highlighter = null;
    /** @type {Promise<import('shiki').Highlighter | null> | null} */
    let readyPromise = null;

    function normalizeLang(lang) {
        if (!lang) return null;
        const key = String(lang)
            .trim()
            .toLowerCase()
            .split(/[\s{:]/)[0];
        if (!key) return null;
        return LANG_ALIASES[key] || key;
    }

    function escapeHtml(text) {
        return String(text)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    function trimCodeSource(text) {
        return String(text).replace(/\n+$/, "");
    }

    function currentTheme() {
        return document.documentElement.classList.contains("dark")
            ? "github-dark"
            : "github-light";
    }

    function langFromBlock(block) {
        if (!block) return null;
        if (block.dataset.lang) {
            return normalizeLang(block.dataset.lang);
        }
        if (!block.className) return null;
        const match = block.className.match(/language-([\w-]+)/);
        return match ? normalizeLang(match[1]) : null;
    }

    function readBlockSource(pre) {
        if (pre.dataset.source) {
            return {
                source: pre.dataset.source,
                lang: normalizeLang(pre.dataset.lang),
            };
        }

        const code = pre.querySelector("code");
        if (!code) return null;

        return {
            source: code.textContent || "",
            lang: langFromBlock(code),
        };
    }

    function init() {
        if (readyPromise) return readyPromise;

        readyPromise = import(SHIKI_URL)
            .then(({ createHighlighter }) =>
                createHighlighter({
                    themes: THEMES,
                    langs: LANGS,
                }),
            )
            .then((instance) => {
                highlighter = instance;
                return instance;
            })
            .catch((err) => {
                console.warn("Shiki failed to load:", err);
                return null;
            });

        return readyPromise;
    }

    function whenReady() {
        return readyPromise || Promise.resolve(null);
    }

    function initMarkedHighlight() {
        if (typeof marked === "undefined") return;

        marked.use({
            gfm: true,
            breaks: false,
            renderer: {
                code(codeOrToken, lang) {
                    let text;
                    let language;

                    if (
                        codeOrToken &&
                        typeof codeOrToken === "object" &&
                        "text" in codeOrToken
                    ) {
                        text = codeOrToken.text;
                        language = codeOrToken.lang;
                    } else {
                        text = codeOrToken;
                        language = lang;
                    }

                    const normalized = normalizeLang(language);
                    const escaped = escapeHtml(trimCodeSource(text));
                    const cls = normalized ? `language-${normalized}` : "";
                    const langAttr = normalized
                        ? ` data-lang="${normalized}"`
                        : "";

                    return `<pre class="docs-code-block"><code class="${cls}"${langAttr}>${escaped}</code></pre>`;
                },
            },
        });
    }

    async function applyHighlightToPre(pre) {
        if (!pre) return;
        await whenReady();
        if (!highlighter) return;

        const info = readBlockSource(pre);
        if (!info || !info.lang) return;

        const { source, lang } = info;
        const loaded = highlighter.getLoadedLanguages();
        if (!loaded.includes(lang)) {
            try {
                await highlighter.loadLanguage(lang);
            } catch (_) {
                return;
            }
        }

        let html;
        try {
            html = highlighter.codeToHtml(source, {
                lang,
                theme: currentTheme(),
            });
        } catch (_) {
            return;
        }

        const template = document.createElement("div");
        template.innerHTML = html.trim();
        const newPre = template.firstElementChild;
        if (!newPre || newPre.tagName !== "PRE") return;

        const copyBtn = pre.querySelector(".copy-btn");
        newPre.classList.add("docs-code-block");
        newPre.dataset.source = source;
        newPre.dataset.lang = lang;
        if (copyBtn) newPre.appendChild(copyBtn);
        pre.replaceWith(newPre);
    }

    async function applyHighlightToBlock(block) {
        const pre = block.closest("pre");
        if (pre) await applyHighlightToPre(pre);
    }

    async function highlightAll(container) {
        if (!container) return;
        await whenReady();
        if (!highlighter) return;

        const pres = container.querySelectorAll(".prose pre");
        for (const pre of pres) {
            await applyHighlightToPre(pre);
        }
    }

    global.DocHighlight = {
        init,
        whenReady,
        initMarked: initMarkedHighlight,
        applyHighlightToPre,
        applyHighlightToBlock,
        highlightAll,
        langFromBlock,
        normalizeLang,
        currentTheme,
    };
})(window);
