(() => {
    const themeToggle = document.getElementById("theme-toggle");

    function applyTheme(mode, persist) {
        const root = document.documentElement;
        root.classList.remove("light", "dark");
        root.classList.add(mode);
        if (persist) {
            try {
                localStorage.setItem("ba-docs-theme", mode);
            } catch (_) {}
        }
    }

    function initTheme() {
        let mode = "system";
        try {
            mode = localStorage.getItem("ba-docs-theme") || "system";
        } catch (_) {}

        if (mode === "system") {
            applyTheme(
                window.matchMedia("(prefers-color-scheme: dark)").matches
                    ? "dark"
                    : "light",
                false,
            );
        } else {
            applyTheme(mode, false);
        }

        if (themeToggle) {
            themeToggle.addEventListener("click", () => {
                const isDark =
                    document.documentElement.classList.contains("dark");
                applyTheme(isDark ? "light" : "dark", true);
            });
        }
    }

    document.querySelectorAll(".copy-btn").forEach((btn) => {
        btn.addEventListener("click", () => {
            const sel = btn.getAttribute("data-copy");
            const el = document.querySelector(sel);
            if (!el) return;
            navigator.clipboard.writeText(el.innerText).then(() => {
                const prev = btn.textContent;
                btn.textContent = "Copied";
                setTimeout(() => {
                    btn.textContent = prev;
                }, 1400);
            });
        });
    });

    function initNavSpy() {
        const tabs = Array.from(
            document.querySelectorAll(".landing-page .topbar-tab[href^='#']"),
        );
        if (!tabs.length) return;

        const homeTab = document.querySelector(
            '.landing-page .topbar-tab[href="./"]',
        );

        function setActive(tab) {
            document
                .querySelectorAll(".landing-page .topbar-tab")
                .forEach((el) => el.classList.remove("active"));
            tab.classList.add("active");
        }

        const sections = tabs
            .map((tab) => {
                const id = tab.getAttribute("href").slice(1);
                return { tab, el: document.getElementById(id) };
            })
            .filter((entry) => entry.el);

        if (!sections.length) return;

        const observer = new IntersectionObserver(
            (entries) => {
                const visible = entries
                    .filter((e) => e.isIntersecting)
                    .sort((a, b) => b.intersectionRatio - a.intersectionRatio);
                if (visible[0]) {
                    const match = sections.find(
                        (s) => s.el === visible[0].target,
                    );
                    if (match) setActive(match.tab);
                    return;
                }
                if (window.scrollY < 120 && homeTab) setActive(homeTab);
            },
            { rootMargin: "-20% 0px -55% 0px", threshold: [0, 0.2, 0.5] },
        );

        sections.forEach(({ el }) => observer.observe(el));

        window.addEventListener(
            "scroll",
            () => {
                if (window.scrollY < 120 && homeTab) setActive(homeTab);
            },
            { passive: true },
        );
    }

    initTheme();
    initNavSpy();
})();
