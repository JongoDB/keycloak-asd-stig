/*
 * Standard Mandatory DoD Notice and Consent Banner (DTM-08-060 text, as quoted in ASD STIG V6R4 V-222434).
 * The banner is shown on every Keycloak login-theme page that renders a credential or confirmation form
 * and stays on screen until the user takes an explicit action ("OK"). Acknowledgement is held only for
 * the current browser tab session (sessionStorage), so a new login session shows the banner again.
 */
(function () {
  var TEXT = [
    "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.",
    "By using this IS (which includes any device attached to this IS), you consent to the following conditions:",
    "-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.",
    "-At any time, the USG may inspect and seize data stored on this IS.",
    "-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.",
    "-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.",
    "-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."
  ];
  var KEY = "dod-banner-ack";
  // Pages after a successful authentication (logout confirmation, info, error) do not need the gate.
  var GATED = /^login-(login|login-x509-info|login-username|login-password|login-otp|webauthn-authenticate|login-config-totp|login-update-password|select-authenticator)/;
  var root = document.documentElement;
  function pageId() { return (document.body && document.body.getAttribute("data-page-id")) || ""; }
  function acked() { try { return sessionStorage.getItem(KEY) === "1"; } catch (e) { return false; } }
  root.classList.add("dod-banner-pending");
  function show() {
    if (!GATED.test(pageId()) || acked()) { root.classList.remove("dod-banner-pending"); return; }
    var ov = document.createElement("div"); ov.id = "dod-banner-overlay";
    ov.setAttribute("role", "dialog"); ov.setAttribute("aria-modal", "true"); ov.setAttribute("aria-labelledby", "dod-banner-title");
    var box = document.createElement("div"); box.id = "dod-banner-box";
    var h = document.createElement("h1"); h.id = "dod-banner-title"; h.textContent = "Standard Mandatory DoD Notice and Consent";
    box.appendChild(h);
    TEXT.forEach(function (t) { var p = document.createElement("p"); p.textContent = t; box.appendChild(p); });
    var b = document.createElement("button"); b.id = "dod-banner-ack"; b.type = "button"; b.textContent = "OK";
    b.addEventListener("click", function () {
      try { sessionStorage.setItem(KEY, "1"); } catch (e) {}
      ov.remove(); root.classList.remove("dod-banner-pending");
      var f = document.querySelector("#kc-form-login input:not([type=hidden]), form input:not([type=hidden])"); if (f) f.focus();
    });
    box.appendChild(b); ov.appendChild(box); document.body.appendChild(ov); b.focus();
    // Keep keyboard focus inside the dialog until acknowledged.
    document.addEventListener("focusin", function (e) { if (document.getElementById("dod-banner-overlay") && !ov.contains(e.target)) b.focus(); });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", show); else show();
})();
