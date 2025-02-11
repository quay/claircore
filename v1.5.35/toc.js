// Populate the sidebar
//
// This is a script, and not included directly in the page, to control the total size of the book.
// The TOC contains an entry for each page, so if each page includes a copy of the TOC,
// the total size of the page becomes O(n**2).
class MDBookSidebarScrollbox extends HTMLElement {
    constructor() {
        super();
    }
    connectedCallback() {
        this.innerHTML = '<ol class="chapter"><li class="chapter-item expanded "><a href="introduction.html"><strong aria-hidden="true">1.</strong> Introduction</a></li><li class="chapter-item expanded "><a href="getting_started.html"><strong aria-hidden="true">2.</strong> Getting Started</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="getting_started/libindex_usage.html"><strong aria-hidden="true">2.1.</strong> Libindex Usage</a></li><li class="chapter-item expanded "><a href="getting_started/libvuln_usage.html"><strong aria-hidden="true">2.2.</strong> Libvuln Usage</a></li></ol></li><li class="chapter-item expanded "><a href="concepts.html"><strong aria-hidden="true">3.</strong> Concepts</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="concepts/vulnerability_matching.html"><strong aria-hidden="true">3.1.</strong> Vulnerability Matching</a></li><li class="chapter-item expanded "><a href="concepts/indexer_architecture.html"><strong aria-hidden="true">3.2.</strong> Indexer Architecture</a></li><li class="chapter-item expanded "><a href="concepts/matcher_architecture.html"><strong aria-hidden="true">3.3.</strong> Matching Architecture</a></li><li class="chapter-item expanded "><a href="concepts/severity_mapping.html"><strong aria-hidden="true">3.4.</strong> Severity Mapping</a></li><li class="chapter-item expanded "><a href="concepts/updater_defaults.html"><strong aria-hidden="true">3.5.</strong> Updater Defaults</a></li></ol></li><li class="chapter-item expanded "><a href="howto.html"><strong aria-hidden="true">4.</strong> How Tos</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="howto/add_dist.html"><strong aria-hidden="true">4.1.</strong> Adding Distribution Or Language Support</a></li></ol></li><li class="chapter-item expanded "><a href="reference.html"><strong aria-hidden="true">5.</strong> Reference</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="reference/coalescer.html"><strong aria-hidden="true">5.1.</strong> Coalescer</a></li><li class="chapter-item expanded "><a href="reference/configurable_scanner.html"><strong aria-hidden="true">5.2.</strong> Configurable Scanner</a></li><li class="chapter-item expanded "><a href="reference/distribution_scanner.html"><strong aria-hidden="true">5.3.</strong> Distribution Scanner</a></li><li class="chapter-item expanded "><a href="reference/ecosystem.html"><strong aria-hidden="true">5.4.</strong> Ecosystem</a></li><li class="chapter-item expanded "><a href="reference/index_report.html"><strong aria-hidden="true">5.5.</strong> Index Report</a></li><li class="chapter-item expanded "><a href="reference/indexer_store.html"><strong aria-hidden="true">5.6.</strong> Indexer Store</a></li><li class="chapter-item expanded "><a href="reference/matcher_store.html"><strong aria-hidden="true">5.7.</strong> Matcher Store</a></li><li class="chapter-item expanded "><a href="reference/manifest.html"><strong aria-hidden="true">5.8.</strong> Manifest</a></li><li class="chapter-item expanded "><a href="reference/matcher.html"><strong aria-hidden="true">5.9.</strong> Matcher</a></li><li class="chapter-item expanded "><a href="reference/package_scanner.html"><strong aria-hidden="true">5.10.</strong> Package Scanner</a></li><li class="chapter-item expanded "><a href="reference/remote_matcher.html"><strong aria-hidden="true">5.11.</strong> Remote Scanner</a></li><li class="chapter-item expanded "><a href="reference/repository_scanner.html"><strong aria-hidden="true">5.12.</strong> Repository Scanner</a></li><li class="chapter-item expanded "><a href="reference/resolver.html"><strong aria-hidden="true">5.13.</strong> Resolver</a></li><li class="chapter-item expanded "><a href="reference/rpcscanner.html"><strong aria-hidden="true">5.14.</strong> RPC Scanner</a></li><li class="chapter-item expanded "><a href="reference/updater.html"><strong aria-hidden="true">5.15.</strong> Updater</a></li><li class="chapter-item expanded "><a href="reference/updatersetfactory.html"><strong aria-hidden="true">5.16.</strong> Updater Set Factory</a></li><li class="chapter-item expanded "><a href="reference/version_filter.html"><strong aria-hidden="true">5.17.</strong> Version Filter</a></li><li class="chapter-item expanded "><a href="reference/versioned_scanner.html"><strong aria-hidden="true">5.18.</strong> Versioned Scanner</a></li><li class="chapter-item expanded "><a href="reference/vulnerability_report.html"><strong aria-hidden="true">5.19.</strong> Vulnerability Report</a></li></ol></li><li class="chapter-item expanded "><a href="contributor.html"><strong aria-hidden="true">6.</strong> Contributors</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="CONTRIBUTING.html"><strong aria-hidden="true">6.1.</strong> Guidelines</a></li><li class="chapter-item expanded "><a href="contributor/changelog.html"><strong aria-hidden="true">6.2.</strong> Changelog</a></li><li class="chapter-item expanded "><a href="contributor/commit-style.html"><strong aria-hidden="true">6.3.</strong> Commit Style</a></li><li class="chapter-item expanded "><a href="contributor/local-dev.html"><strong aria-hidden="true">6.4.</strong> Local Development</a></li><li class="chapter-item expanded "><a href="contributor/logging.html"><strong aria-hidden="true">6.5.</strong> Logging</a></li><li class="chapter-item expanded "><a href="contributor/misc.html"><strong aria-hidden="true">6.6.</strong> Misc</a></li><li class="chapter-item expanded "><a href="contributor/releases.html"><strong aria-hidden="true">6.7.</strong> Releases</a></li><li class="chapter-item expanded "><a href="contributor/tests.html"><strong aria-hidden="true">6.8.</strong> Tests</a></li><li class="chapter-item expanded "><a href="contributor/go_version.html"><strong aria-hidden="true">6.9.</strong> Go Version</a></li></ol></li></ol>';
        // Set the current, active page, and reveal it if it's hidden
        let current_page = document.location.href.toString().split("#")[0];
        if (current_page.endsWith("/")) {
            current_page += "index.html";
        }
        var links = Array.prototype.slice.call(this.querySelectorAll("a"));
        var l = links.length;
        for (var i = 0; i < l; ++i) {
            var link = links[i];
            var href = link.getAttribute("href");
            if (href && !href.startsWith("#") && !/^(?:[a-z+]+:)?\/\//.test(href)) {
                link.href = path_to_root + href;
            }
            // The "index" page is supposed to alias the first chapter in the book.
            if (link.href === current_page || (i === 0 && path_to_root === "" && current_page.endsWith("/index.html"))) {
                link.classList.add("active");
                var parent = link.parentElement;
                if (parent && parent.classList.contains("chapter-item")) {
                    parent.classList.add("expanded");
                }
                while (parent) {
                    if (parent.tagName === "LI" && parent.previousElementSibling) {
                        if (parent.previousElementSibling.classList.contains("chapter-item")) {
                            parent.previousElementSibling.classList.add("expanded");
                        }
                    }
                    parent = parent.parentElement;
                }
            }
        }
        // Track and set sidebar scroll position
        this.addEventListener('click', function(e) {
            if (e.target.tagName === 'A') {
                sessionStorage.setItem('sidebar-scroll', this.scrollTop);
            }
        }, { passive: true });
        var sidebarScrollTop = sessionStorage.getItem('sidebar-scroll');
        sessionStorage.removeItem('sidebar-scroll');
        if (sidebarScrollTop) {
            // preserve sidebar scroll position when navigating via links within sidebar
            this.scrollTop = sidebarScrollTop;
        } else {
            // scroll sidebar to current active section when navigating via "next/previous chapter" buttons
            var activeSection = document.querySelector('#sidebar .active');
            if (activeSection) {
                activeSection.scrollIntoView({ block: 'center' });
            }
        }
        // Toggle buttons
        var sidebarAnchorToggles = document.querySelectorAll('#sidebar a.toggle');
        function toggleSection(ev) {
            ev.currentTarget.parentElement.classList.toggle('expanded');
        }
        Array.from(sidebarAnchorToggles).forEach(function (el) {
            el.addEventListener('click', toggleSection);
        });
    }
}
window.customElements.define("mdbook-sidebar-scrollbox", MDBookSidebarScrollbox);
