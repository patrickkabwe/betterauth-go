(() => {
    const MD_BASE = "..";
    const DEFAULT_PAGE = "introduction";

    /** @type {{ title: string, items: { title: string, path: string }[] }[]} */
    let nav = [];
    /** @type {{ path: string, title: string, section: string }[]} */
    let flatNav = [];

    const sidebarNavEl = document.getElementById("sidebar-nav");
    const sidebarEl = document.getElementById("sidebar");
    const sidebarBackdrop = document.getElementById("sidebar-backdrop");
    const contentEl = document.getElementById("content");
    const tocNavEl = document.getElementById("toc-nav");
    const tocEmptyEl = document.getElementById("toc-empty");
    const docsVersionEl = document.getElementById("docs-version");
    const searchEl = document.getElementById("doc-search");
    const menuToggle = document.getElementById("menu-toggle");
    const themeToggle = document.getElementById("theme-toggle");
    const tocToggle = document.getElementById("toc-toggle");
    const tocMobile = document.getElementById("toc-mobile");
    const tocMobileNav = document.getElementById("toc-mobile-nav");
    const tocMobileBackdrop = document.getElementById("toc-mobile-backdrop");
    const tocMobileClose = document.getElementById("toc-mobile-close");

    let tocObserver = null;
    let loadToken = 0;
    const NAV_COLLAPSE_KEY = "ba-docs-nav-collapsed";
    const I = () => window.DocIcons;

    initTheme();
    initChrome();
    loadVersion();
    if (window.DocHighlight) {
        DocHighlight.init();
        DocHighlight.initMarked();
    }

    function initChrome() {
        const searchIcon = document.querySelector(".search-icon");
        if (searchIcon && I()) {
            searchIcon.innerHTML = I().icon("search", "search-icon-svg");
        }

        if (tocToggle) {
            tocToggle.addEventListener("click", openTocMobile);
        }
        if (tocMobileBackdrop) {
            tocMobileBackdrop.addEventListener("click", closeTocMobile);
        }
        if (tocMobileClose) {
            tocMobileClose.addEventListener("click", closeTocMobile);
        }
    }

    function openTocMobile() {
        if (!tocMobile || !tocMobileNav || !tocMobileNav.children.length)
            return;
        tocMobile.classList.add("open");
        tocMobile.setAttribute("aria-hidden", "false");
        document.body.classList.add("toc-mobile-open");
    }

    function closeTocMobile() {
        if (!tocMobile) return;
        tocMobile.classList.remove("open");
        tocMobile.setAttribute("aria-hidden", "true");
        document.body.classList.remove("toc-mobile-open");
    }

    function sectionSlug(title) {
        return title
            .toLowerCase()
            .replace(/[^\w]+/g, "-")
            .replace(/^-|-$/g, "");
    }

    function readCollapsedSections() {
        try {
            const raw = localStorage.getItem(NAV_COLLAPSE_KEY);
            return raw ? JSON.parse(raw) : {};
        } catch (_) {
            return {};
        }
    }

    function writeCollapsedSections(state) {
        try {
            localStorage.setItem(NAV_COLLAPSE_KEY, JSON.stringify(state));
        } catch (_) {}
    }

    function sectionContainsRoute(section, route) {
        return section.items.some((item) => item.path === route);
    }

    function isSectionCollapsed(
        slug,
        section,
        activeRoute,
        filtering,
        sectionIndex,
    ) {
        if (filtering) return false;
        const state = readCollapsedSections();
        if (Object.hasOwn(state, slug)) {
            return !!state[slug];
        }
        if (sectionContainsRoute(section, activeRoute)) return false;
        if (sectionIndex === 0) return false;
        return true;
    }

    function formatVersionLabel(version) {
        if (!version) return "";
        const value = String(version).trim();
        if (!value) return "";
        if (/^dev$/i.test(value)) return "Dev";
        if (/^v\d/i.test(value)) return value;
        if (/^v/i.test(value)) return value;
        return `v${value}`;
    }

    async function loadVersion() {
        if (!docsVersionEl) return;

        const paths = ["../version.json", "../../cmd/betterauth-go/main.go"];

        for (const path of paths) {
            try {
                const res = await fetch(path);
                if (!res.ok) continue;
                const text = await res.text();
                let version = null;
                if (path.endsWith(".json")) {
                    version = JSON.parse(text).version;
                } else {
                    const match = text.match(/var\s+version\s*=\s*"([^"]+)"/);
                    version = match && match[1];
                }
                const label = formatVersionLabel(version);
                if (label) {
                    docsVersionEl.textContent = label;
                    docsVersionEl.title = `betterauth CLI ${label}`;
                    return;
                }
            } catch (_) {}
        }

        docsVersionEl.textContent = "Dev";
        docsVersionEl.title = "betterauth CLI Dev";
    }

    function routeFromHash() {
        const raw = location.hash
            .replace(/^#\/?/, "")
            .split("#")[0]
            .replace(/\/$/, "");
        return raw || DEFAULT_PAGE;
    }

    function mdPath(route) {
        return `${MD_BASE}/${route}.md`;
    }

    function resolveMdLink(href, currentRoute) {
        if (!href || href.startsWith("http") || href.startsWith("#"))
            return href;

        const [pathPart, hash] = href.split("#");
        if (pathPart.startsWith("../ROADMAP")) return href;
        if (pathPart.startsWith("../README")) return href;

        let path = pathPart.replace(/\.md$/, "");
        const currentDir = currentRoute.includes("/")
            ? currentRoute.replace(/\/[^/]+$/, "")
            : "";

        if (path.startsWith("../")) {
            path = normalizePath(`${currentDir}/${path}`);
        } else if (!path.startsWith("/") && currentDir && !path.includes("/")) {
            path = `${currentDir}/${path.replace(/^\.\//, "")}`;
        } else {
            path = path.replace(/^\.\//, "");
        }

        if (flatNav.some((n) => n.path === path)) {
            return hash ? `#/${path}#${hash}` : `#/${path}`;
        }
        return href;
    }

    function normalizePath(p) {
        const parts = p.split("/").filter(Boolean);
        const out = [];
        for (const part of parts) {
            if (part === "..") out.pop();
            else if (part !== ".") out.push(part);
        }
        return out.join("/");
    }

    function initTheme() {
        let mode = "system";
        try {
            mode = localStorage.getItem("ba-docs-theme") || "system";
        } catch (_) {}

        if (mode === "system") {
            const prefersDark = window.matchMedia(
                "(prefers-color-scheme: dark)",
            ).matches;
            applyTheme(prefersDark ? "dark" : "light", false);
        } else {
            applyTheme(mode, false);
        }

        themeToggle.addEventListener("click", () => {
            const isDark = document.documentElement.classList.contains("dark");
            applyTheme(isDark ? "light" : "dark", true);
        });
    }

    function applyTheme(mode, persist) {
        const root = document.documentElement;
        root.classList.remove("light", "dark");
        root.classList.add(mode);

        if (persist) {
            try {
                localStorage.setItem("ba-docs-theme", mode);
            } catch (_) {}
        }

        void rehighlightCodeBlocks();
    }

    async function rehighlightCodeBlocks() {
        if (!window.DocHighlight) return;
        await DocHighlight.whenReady();
        await DocHighlight.highlightAll(contentEl);
    }

    async function loadNav() {
        const res = await fetch("nav.json");
        nav = await res.json();
        flatNav = [];
        for (const section of nav) {
            for (const item of section.items) {
                flatNav.push({
                    path: item.path,
                    title: item.title,
                    section: section.title,
                });
            }
        }
        renderSidebar(routeFromHash());
    }

    function renderSidebar(activeRoute, filter) {
        const q = (filter || "").trim().toLowerCase();
        const filtering = !!q;
        const collapsedState = readCollapsedSections();
        sidebarNavEl.innerHTML = "";

        for (let sectionIndex = 0; sectionIndex < nav.length; sectionIndex++) {
            const section = nav[sectionIndex];
            const slug = sectionSlug(section.title);
            let anyVisible = false;
            const linksWrap = document.createElement("div");
            linksWrap.className = "sidebar-section-links";
            const linksInner = document.createElement("div");
            linksInner.className = "sidebar-section-links-inner";

            for (const item of section.items) {
                const match =
                    !q ||
                    item.title.toLowerCase().includes(q) ||
                    item.path.toLowerCase().includes(q) ||
                    section.title.toLowerCase().includes(q);
                const a = document.createElement("a");
                a.className =
                    "sidebar-link" +
                    (item.path === activeRoute ? " active" : "");
                if (!match) a.classList.add("hidden");
                else anyVisible = true;
                a.href = `#/${item.path}`;
                a.textContent = item.title;
                a.addEventListener("click", () => closeSidebar());
                linksInner.appendChild(a);
            }

            linksWrap.appendChild(linksInner);

            if (!anyVisible && q) continue;

            const sec = document.createElement("div");
            sec.className = "sidebar-section";
            if (sectionContainsRoute(section, activeRoute)) {
                sec.classList.add("has-active");
            }
            sec.dataset.section = slug;

            const collapsed = isSectionCollapsed(
                slug,
                section,
                activeRoute,
                filtering,
                sectionIndex,
            );
            if (collapsed) sec.classList.add("collapsed");

            const toggle = document.createElement("button");
            toggle.type = "button";
            toggle.className = "sidebar-section-toggle";
            toggle.setAttribute("aria-expanded", collapsed ? "false" : "true");
            const sectionLabel = I()
                ? `${I().sectionIconSvg(section.title, "section-icon")}<span>${escapeHtml(section.title)}</span>`
                : `<span>${escapeHtml(section.title)}</span>`;
            toggle.innerHTML = `<span class="sidebar-section-label">${sectionLabel}</span><span class="section-chevron-wrap" aria-hidden="true"><svg class="section-chevron" width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M4 6l4 4 4-4"/></svg></span>`;
            toggle.addEventListener("click", () => {
                const nowCollapsed = sec.classList.toggle("collapsed");
                toggle.setAttribute(
                    "aria-expanded",
                    nowCollapsed ? "false" : "true",
                );
                toggle.blur();
                if (!filtering) {
                    collapsedState[slug] = nowCollapsed;
                    writeCollapsedSections(collapsedState);
                }
            });

            sec.appendChild(toggle);
            sec.appendChild(linksWrap);
            sidebarNavEl.appendChild(sec);
        }
    }

    function expandSectionForRoute(route) {
        sidebarNavEl.querySelectorAll(".sidebar-section").forEach((sec) => {
            const link = sec.querySelector(
                `.sidebar-link[href="#/${CSS.escape(route)}"]`,
            );
            if (!link) return;
            sec.classList.remove("collapsed");
            const toggle = sec.querySelector(".sidebar-section-toggle");
            if (toggle) toggle.setAttribute("aria-expanded", "true");
            const slug = sec.dataset.section;
            if (slug) {
                const state = readCollapsedSections();
                state[slug] = false;
                writeCollapsedSections(state);
            }
        });
    }

    function updateSidebarActive(activeRoute) {
        sidebarNavEl.querySelectorAll(".sidebar-link").forEach((a) => {
            const path = (a.getAttribute("href") || "").replace(/^#\/?/, "");
            a.classList.toggle("active", path === activeRoute);
        });
        sidebarNavEl.querySelectorAll(".sidebar-section").forEach((sec) => {
            const hasActive = !!sec.querySelector(
                `.sidebar-link[href="#/${CSS.escape(activeRoute)}"]`,
            );
            sec.classList.toggle("has-active", hasActive);
        });
        sidebarNavEl
            .querySelectorAll(".sidebar-section-toggle")
            .forEach((toggle) => toggle.blur());
    }

    function syncSidebar(activeRoute) {
        const q = searchEl ? searchEl.value.trim() : "";
        if (!sidebarNavEl.children.length || q) {
            renderSidebar(activeRoute, q);
        } else {
            updateSidebarActive(activeRoute);
            expandSectionForRoute(activeRoute);
        }
    }

    function openSidebar() {
        sidebarEl.classList.add("open");
        if (sidebarBackdrop) sidebarBackdrop.classList.add("visible");
    }

    function closeSidebar() {
        sidebarEl.classList.remove("open");
        if (sidebarBackdrop) sidebarBackdrop.classList.remove("visible");
    }

    function flatIndex(route) {
        return flatNav.findIndex((n) => n.path === route);
    }

    function renderPageNav(route) {
        const idx = flatIndex(route);
        if (idx < 0) return "";
        const prev = idx > 0 ? flatNav[idx - 1] : null;
        const next = idx < flatNav.length - 1 ? flatNav[idx + 1] : null;
        if (!prev && !next) return "";

        let html = '<div class="page-nav">';
        if (prev) {
            html += `<a class="prev" href="#/${prev.path}"><span class="page-nav-body"><span class="label">Previous</span><span class="title">${escapeHtml(prev.title)}</span></span></a>`;
        }
        if (next) {
            html += `<a class="next" href="#/${next.path}"><span class="page-nav-body"><span class="label">Next</span><span class="title">${escapeHtml(next.title)}</span></span></a>`;
        }
        html += "</div>";
        return html;
    }

    function collectHeadings(article) {
        return Array.from(article.querySelectorAll("h2, h3, h4")).filter((h) =>
            h.textContent.trim(),
        );
    }

    function ensureHeadingId(h) {
        if (!h.id) {
            h.id = h.textContent
                .trim()
                .toLowerCase()
                .replace(/[^\w]+/g, "-")
                .replace(/^-|-$/g, "");
        }
        return h.id;
    }

    function createTocLink(heading, route) {
        const id = ensureHeadingId(heading);
        const a = document.createElement("a");
        a.href = `#${id}`;
        a.dataset.target = id;
        a.classList.add(`toc-${heading.tagName.toLowerCase()}`);
        const label = document.createElement("span");
        label.className = "toc-link-text";
        label.textContent = heading.textContent.trim();
        a.appendChild(label);
        a.addEventListener("click", (e) => {
            e.preventDefault();
            heading.scrollIntoView({ behavior: "smooth", block: "start" });
            history.replaceState(null, "", `#/${route}#${id}`);
            setActiveTocLink(id);
            closeTocMobile();
        });
        return a;
    }

    function syncMobileToc() {
        if (!tocMobileNav || !tocNavEl) return;
        tocMobileNav.innerHTML = tocNavEl.innerHTML;
        tocMobileNav.querySelectorAll("a").forEach((a) => {
            a.addEventListener("click", () => closeTocMobile());
        });
        if (tocToggle) {
            tocToggle.disabled = tocNavEl.children.length === 0;
            tocToggle.classList.toggle(
                "hidden",
                tocNavEl.children.length === 0,
            );
        }
    }

    function renderInlineOutline(article, route) {
        const existing = article.querySelector(".page-inline-outline");
        if (existing) existing.remove();

        const headings = collectHeadings(article);
        if (!headings.length) return;

        const wrap = document.createElement("nav");
        wrap.className = "page-inline-outline";
        wrap.setAttribute("aria-label", "Page sections");

        const label = document.createElement("span");
        label.className = "page-inline-outline-label";
        label.textContent = "Sections";
        wrap.appendChild(label);

        const list = document.createElement("div");
        list.className = "page-inline-outline-list";

        headings.forEach((h) => {
            if (h.tagName === "H2") {
                list.appendChild(createTocLink(h, route));
            }
        });

        if (!list.children.length) {
            headings.slice(0, 6).forEach((h) => {
                list.appendChild(createTocLink(h, route));
            });
        }

        wrap.appendChild(list);

        const h1 = article.querySelector("h1");
        if (h1) h1.insertAdjacentElement("afterend", wrap);
        else article.prepend(wrap);
    }

    function buildToc(article, route) {
        if (tocObserver) {
            tocObserver.disconnect();
            tocObserver = null;
        }

        if (!tocNavEl) return;

        const headings = collectHeadings(article);
        tocNavEl.innerHTML = "";
        if (tocEmptyEl) {
            tocEmptyEl.classList.toggle("hidden", headings.length > 0);
        }
        if (!headings.length) {
            syncMobileToc();
            return;
        }

        const tocLinks = [];

        headings.forEach((h) => {
            const link = createTocLink(h, route);
            tocNavEl.appendChild(link);
            tocLinks.push({ el: h, link });
        });

        syncMobileToc();

        tocObserver = new IntersectionObserver(
            (entries) => {
                const visible = entries
                    .filter((e) => e.isIntersecting)
                    .sort((a, b) => b.intersectionRatio - a.intersectionRatio);
                if (visible[0]) setActiveTocLink(visible[0].target.id);
            },
            { rootMargin: "-15% 0px -65% 0px", threshold: [0, 0.15, 0.4, 1] },
        );
        tocLinks.forEach(({ el }) => tocObserver.observe(el));

        if (tocLinks[0]) setActiveTocLink(tocLinks[0].el.id);
    }

    function setActiveTocLink(id) {
        if (!id) return;
        document.querySelectorAll("[data-target]").forEach((a) => {
            a.classList.toggle("active", a.dataset.target === id);
        });
    }

    function escapeHtml(s) {
        return s
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/"/g, "&quot;");
    }

    function attachCopyButton(pre) {
        if (!pre || pre.querySelector(".copy-btn")) return;

        const btn = document.createElement("button");
        btn.className = "copy-btn";
        btn.type = "button";
        btn.textContent = "Copy";

        btn.addEventListener("click", () => {
            const text =
                pre.dataset.source ||
                pre.querySelector("code")?.textContent ||
                "";
            navigator.clipboard.writeText(text).then(() => {
                btn.textContent = "Copied";
                btn.classList.add("copied");
                setTimeout(() => {
                    btn.textContent = "Copy";
                    btn.classList.remove("copied");
                }, 1400);
            });
        });

        pre.appendChild(btn);
    }

    async function enhanceCodeBlocks(container) {
        if (window.DocHighlight) {
            await DocHighlight.whenReady();
            await DocHighlight.highlightAll(container);
        }

        container.querySelectorAll(".prose pre").forEach((pre) => {
            attachCopyButton(pre);
        });
    }
    
    function wireInternalLinks(container, currentRoute) {
        container.querySelectorAll("a").forEach((a) => {
            const href = a.getAttribute("href");
            if (!href || href.startsWith("http")) return;
            const resolved = resolveMdLink(href, currentRoute);
            if (resolved.startsWith("#/")) {
                a.setAttribute("href", resolved);
            }
        });
    }

    async function loadPage(route) {
        const token = ++loadToken;

        contentEl.innerHTML = '<p class="content-loading">Loading…</p>';
        if (tocNavEl) tocNavEl.innerHTML = "";
        if (tocMobileNav) tocMobileNav.innerHTML = "";
        if (tocEmptyEl) tocEmptyEl.classList.add("hidden");
        closeTocMobile();
        if (tocObserver) {
            tocObserver.disconnect();
            tocObserver = null;
        }
        document.title = "Documentation — better-auth.go";

        const url = mdPath(route);
        let text;
        try {
            const res = await fetch(url);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            text = await res.text();
        } catch (e) {
            if (token !== loadToken) return;
            contentEl.innerHTML = `<div class="content-error"><strong>Page not found</strong><p>Could not load <code>${escapeHtml(url)}</code>. <a href="#/${DEFAULT_PAGE}">Go to introduction</a>.</p></div>`;
            return;
        }

        if (token !== loadToken) return;

        const titleMatch = text.match(/^#\s+(.+)$/m);
        const pageTitle = titleMatch ? titleMatch[1].trim() : route;
        document.title = `${pageTitle} — better-auth.go`;

        const html = marked.parse(text);
        contentEl.innerHTML = `<article class="prose">${html}</article>${renderPageNav(route)}`;

        const article = contentEl.querySelector(".prose");
        wireInternalLinks(contentEl, route);
        await enhanceCodeBlocks(contentEl);
        renderInlineOutline(article, route);
        buildToc(article, route);
        syncSidebar(route);

        const pageHash = location.hash.includes("#")
            ? location.hash.split("#").slice(2).join("#")
            : "";
        history.replaceState(
            null,
            "",
            `#/${route}${pageHash ? "#" + pageHash : ""}`,
        );

        if (pageHash) {
            const target = document.getElementById(pageHash);
            if (target) {
                target.scrollIntoView();
                setActiveTocLink(pageHash);
            }
        } else {
            window.scrollTo(0, 0);
        }
    }

    function onRouteChange() {
        loadPage(routeFromHash());
    }

    menuToggle.addEventListener("click", () => {
        if (sidebarEl.classList.contains("open")) closeSidebar();
        else openSidebar();
    });

    if (sidebarBackdrop) {
        sidebarBackdrop.addEventListener("click", closeSidebar);
    }

    if (searchEl) {
        searchEl.addEventListener("input", () => {
            renderSidebar(routeFromHash(), searchEl.value);
        });
    }

    window.addEventListener("hashchange", onRouteChange);

    loadNav().then(onRouteChange);
})();
