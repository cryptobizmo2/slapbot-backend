/* SLAPBOT scam alert — add-on for index.html
   Watches whatever token the scanner is showing, asks the backend's risk engine
   for a verdict, and puts it at the top of the scan:
     DANGER / RISKY → flashing red "ALERT ALERT: RISKY", the screen pulses red,
                      the phone buzzes, and the Buy link is hidden
     CAUTION        → steady amber warning
     UNVERIFIED     → amber "can't verify — treat as risky"
     PASSED         → quiet green note (never "safe")
   Reads the page's `current` scan; changes nothing else. */
(function () {
  "use strict";
  var API = "https://slapbot-backend-production.up.railway.app";
  var reduce = window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches;
  var lastKey = "", verdict = null, busy = false;

  var css = document.createElement("style");
  css.textContent =
    "#riskBanner{border-radius:16px;padding:14px 15px;margin-bottom:11px;border:2px solid;font-size:12.5px;line-height:1.5;position:relative;z-index:2}" +
    "#riskBanner .rh{font-size:17px;font-weight:900;letter-spacing:.02em;margin-bottom:4px}" +
    "#riskBanner ul{margin:8px 0 0 0;padding:0;list-style:none}" +
    "#riskBanner li{padding:5px 0;border-top:1px solid rgba(255,255,255,.12)}" +
    "#riskBanner .rs{font-size:10.5px;opacity:.8;margin-top:8px}" +
    ".rk-danger{background:rgba(255,30,60,.16);border-color:#FF2D4A;color:#FFD0D8}" +
    ".rk-danger .rh{color:#FF4D64}" +
    ".rk-caution{background:rgba(242,169,59,.12);border-color:#F2A93B;color:#FFE3B0}" +
    ".rk-caution .rh{color:#F2A93B}" +
    ".rk-pass{background:rgba(61,220,151,.08);border-color:rgba(61,220,151,.45);color:#C8F5E1}" +
    ".rk-pass .rh{color:#3DDC97;font-size:14px}" +
    ".rk-flash{animation:rkFlash .9s ease-in-out infinite}" +
    "@keyframes rkFlash{0%,100%{box-shadow:0 0 0 0 rgba(255,45,74,.0);border-color:#FF2D4A}50%{box-shadow:0 0 26px 4px rgba(255,45,74,.75);border-color:#FFFFFF}}" +
    ".rk-blink{animation:rkBlink 1s steps(2) infinite}@keyframes rkBlink{50%{opacity:.25}}" +
    "#rkScreen{position:fixed;inset:0;z-index:998;pointer-events:none;background:rgba(255,20,50,.38);opacity:0}" +
    "#rkScreen.on{animation:rkScreen 1.5s ease-out 1}" +
    "@keyframes rkScreen{0%,40%,80%{opacity:1}20%,60%,100%{opacity:0}}" +
    "body.riskBlock #linkList a[href*='jup.ag'],body.riskBlock .fbuy.rk-hide{display:none!important}" +
    "@media(prefers-reduced-motion:reduce){.rk-flash,.rk-blink,#rkScreen.on{animation:none}}";
  document.head.appendChild(css);

  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; }); }
  function scan() { try { return typeof current !== "undefined" ? current : null; } catch (e) { return null; } }
  function screenFlash() {
    if (reduce) return;
    var s = document.getElementById("rkScreen");
    if (!s) { s = document.createElement("div"); s.id = "rkScreen"; document.body.appendChild(s); }
    s.classList.remove("on"); void s.offsetWidth; s.classList.add("on");
    if (navigator.vibrate) navigator.vibrate([200, 100, 200, 100, 300]);
  }

  function bannerHTML(v) {
    var flags = v.flags || [];
    var icon = { danger: "⛔", risk: "🚨", caution: "⚠️" };
    var list = flags.length ? "<ul>" + flags.map(function (f) { return "<li>" + (icon[f.level] || "•") + " " + esc(f.text) + "</li>"; }).join("") + "</ul>" : "";
    if (v.verdict === "DANGER")
      return { cls: "rk-danger rk-flash", html: '<div class="rh rk-blink">⚠️ ALERT ALERT: RISKY · DO NOT BUY</div>SLAPBOT found serious scam signs on this token. The Buy link is hidden for your protection.' + list + '<div class="rs">Score ' + v.score + "/100 · checked just now</div>" };
    if (v.verdict === "RISKY")
      return { cls: "rk-danger rk-flash", html: '<div class="rh rk-blink">⚠️ ALERT ALERT: RISKY</div>This token has real red flags. Most people should pass.' + list + '<div class="rs">Score ' + v.score + "/100 · checked just now</div>" };
    if (v.verdict === "UNVERIFIED")
      return { cls: "rk-caution", html: '<div class="rh">⚠️ Can\'t verify: treat as risky</div>SLAPBOT couldn\'t confirm this contract is safe.' + list };
    if (v.verdict === "CAUTION")
      return { cls: "rk-caution", html: '<div class="rh">⚠️ Caution</div>No scam signs, but a few things to know first.' + list + '<div class="rs">Score ' + v.score + "/100</div>" };
    return { cls: "rk-pass", html: '<div class="rh">✅ No scam signs found</div>Every check SLAPBOT can run came back clean. That lowers risk, it doesn\'t remove it.' };
  }

  function place() {
    var view = document.getElementById("tokenView");
    var c = scan();
    if (!view || !c || !verdict || verdict.key !== keyOf(c)) return;
    var b = document.getElementById("riskBanner");
    var out = bannerHTML(verdict.data);
    if (!b) { b = document.createElement("div"); b.id = "riskBanner"; view.insertBefore(b, view.firstChild); }
    else if (b.parentNode !== view || view.firstChild !== b) view.insertBefore(b, view.firstChild);
    if (b.getAttribute("data-k") !== verdict.key) { b.className = out.cls; b.innerHTML = out.html; b.setAttribute("data-k", verdict.key); }
    var block = verdict.data.verdict === "DANGER" || verdict.data.verdict === "RISKY";
    document.body.classList.toggle("riskBlock", block);
  }
  function keyOf(c) { return (c.chain || "solana") + ":" + c.addr; }

  function check() {
    var c = scan();
    if (!c || !c.addr) { document.body.classList.remove("riskBlock"); return; }
    var k = keyOf(c);
    if (k === lastKey) { place(); return; }
    if (busy) return;
    busy = true; lastKey = k; verdict = null;
    var old = document.getElementById("riskBanner"); if (old) old.remove();
    document.body.classList.remove("riskBlock");
    fetch(API + "/api/risk/" + encodeURIComponent(c.chain || "solana") + "/" + encodeURIComponent(c.addr), { cache: "no-store" })
      .then(function (r) { return r.json().then(function (j) { if (!r.ok) throw new Error(j.error || "scan failed"); return j; }); })
      .then(function (d) {
        if (keyOf(scan() || {}) !== k) return;           // user moved on to another token
        verdict = { key: k, data: d };
        place();
        if (d.verdict === "DANGER" || d.verdict === "RISKY") screenFlash();
      })
      .catch(function () { lastKey = ""; })                 // try again on the next tick
      .then(function () { busy = false; });
  }

  // $SLAPGOLD's home is the GitHub page now: re-point any old Tokly links on the scanner
  function fixGoldLinks() {
    var links = document.querySelectorAll('a[href*="slapitgold.tokly.io"]');
    for (var i = 0; i < links.length; i++) links[i].href = "https://cryptobizmo2.github.io/SLAPBOT/slapgold.html";
  }

  function start() {
    fixGoldLinks();
    var view = document.getElementById("tokenView");
    if (view && window.MutationObserver) new MutationObserver(function () { if (verdict) place(); }).observe(view, { childList: true });
    setInterval(check, 800);
    check();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
