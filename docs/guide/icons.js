(function (global) {
    const sectionPaths = {
        start:
            '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="2.5" fill="currentColor" stroke="none"/>',
        lock: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
        layers:
            '<path d="M12 3 3 8l9 5 9-5-9-5z"/><path d="M3 13l9 5 9-5"/><path d="M3 18l9 5 9-5"/>',
        grid: '<rect x="4" y="4" width="6.5" height="6.5" rx="1.5"/><rect x="13.5" y="4" width="6.5" height="6.5" rx="1.5"/><rect x="4" y="13.5" width="6.5" height="6.5" rx="1.5"/><rect x="13.5" y="13.5" width="6.5" height="6.5" rx="1.5"/>',
        share:
            '<circle cx="18" cy="5" r="2.5"/><circle cx="6" cy="12" r="2.5"/><circle cx="18" cy="19" r="2.5"/><path d="M8.4 13.2 15.6 17M15.6 7 8.4 10.8"/>',
        guide: '<path d="m4 20 16-8L4 4v6l10 2-10 2z"/>',
        ref: '<path d="M6 4h9l3 3v13H6z"/><path d="M15 4v4h4"/><path d="M9 12h6M9 16h4"/>',
    };

    const sectionIcons = {
        "Get started": "start",
        Authentication: "lock",
        Concepts: "layers",
        Plugins: "grid",
        Integrations: "share",
        Guides: "guide",
        Reference: "ref",
    };

    const utilityPaths = {
        search:
            '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
    };

    function sectionIcon(title) {
        return sectionIcons[title] || "ref";
    }

    function sectionIconSvg(title, className) {
        const name = sectionIcon(title);
        const d = sectionPaths[name] || sectionPaths.ref;
        const cls = className ? ` class="${className}"` : "";
        return `<svg${cls} width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${d}</svg>`;
    }

    function icon(name, className) {
        const d = utilityPaths[name] || "";
        const cls = className ? ` class="${className}"` : "";
        return `<svg${cls} width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${d}</svg>`;
    }

    global.DocIcons = { icon, sectionIconSvg, sectionIcon };
})(window);
