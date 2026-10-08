(() => {
  "use strict";
  const navigation = document.querySelector("[data-manual-navigation]");
  const search = document.getElementById("manual-search");
  const status = document.querySelector("[data-search-status]");
  const toggle = document.querySelector("[data-nav-toggle]");
  const symbol = document.querySelector("[data-nav-symbol]");
  if (!navigation || !search || !status || !toggle) return;

  const mobile = window.matchMedia("(max-width: 760px)");
  const links = Array.from(navigation.querySelectorAll('a[href^="#"]'));
  const entries = links.map((link) => {
    const section = document.getElementById(link.hash.slice(1));
    return { link, text: `${link.textContent} ${section?.textContent || ""}`.toLocaleLowerCase() };
  });
  const groups = Array.from(navigation.querySelectorAll("details"));

  function setExpanded(expanded) {
    toggle.setAttribute("aria-expanded", String(expanded));
    navigation.dataset.collapsed = String(!expanded);
    if (symbol) symbol.textContent = expanded ? "−" : "+";
  }

  function filterNavigation() {
    const terms = search.value.trim().toLocaleLowerCase().split(/\s+/).filter(Boolean);
    let count = 0;
    for (const entry of entries) {
      const matches = terms.every((term) => entry.text.includes(term));
      entry.link.hidden = !matches;
      if (matches) count += 1;
    }
    for (const group of groups) {
      group.hidden = !Array.from(group.querySelectorAll("a")).some((link) => !link.hidden);
      if (terms.length) group.open = true;
    }
    status.textContent = terms.length ? `${count} matching ${count === 1 ? "section" : "sections"}${count ? "" : ". Try another word."}` : "";
    if (terms.length) setExpanded(true);
  }

  function markCurrent() {
    for (const link of links) {
      const current = link.hash === window.location.hash;
      link.classList.toggle("active", current);
      if (current) link.setAttribute("aria-current", "location");
      else link.removeAttribute("aria-current");
    }
  }

  toggle.hidden = false;
  document.body.dataset.navigationReady = "true";
  setExpanded(!mobile.matches);
  toggle.addEventListener("click", () => setExpanded(toggle.getAttribute("aria-expanded") !== "true"));
  search.addEventListener("input", filterNavigation);
  navigation.addEventListener("click", (event) => {
    const link = event.target.closest('a[href^="#"]');
    if (!link) return;
    if (mobile.matches) setExpanded(false);
    const heading = document.querySelector(`${link.hash} h2`);
    window.requestAnimationFrame(() => heading?.focus({ preventScroll: true }));
  });
  mobile.addEventListener("change", () => setExpanded(!mobile.matches || Boolean(search.value.trim())));
  window.addEventListener("hashchange", markCurrent);
  markCurrent();
})();
