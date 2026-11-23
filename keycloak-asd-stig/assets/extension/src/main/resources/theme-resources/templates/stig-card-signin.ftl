<#-- stig-extensions X.509 step (STIG_CARD_PORT set, no certificate on this connection): "Sign in with CAC/PIV" goes to
     the CARD PORT (a new TLS handshake that asks for the certificate; same cookies, so the same sign-in); "Use another
     sign-in method" stays on this page's own origin, so a network that blocks the card port can always go on. -->
<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
    <#if section = "header">
        ${msg("stigCardSignInTitle")}
    <#elseif section = "form">
        <#if cardError?? && cardError?has_content>
            <div id="stig-card-error" class="${properties.kcAlertClass!} pf-m-danger" role="alert">
                <span class="${properties.kcAlertTitleClass!}">${msg(cardError)}</span>
            </div>
        </#if>
        <p id="stig-card-intro">${msg("stigCardSignInIntro")}</p>
        <#-- [hidden] must win over the theme's alert display (PatternFly sets display on .pf-*-c-alert, which beats the
             browser's own [hidden] rule: without this the "blocked" alert showed on every load) -->
        <style>
            #stig-card-blocked[hidden], #stig-card-wait[hidden] { display: none !important; }
            #stig-card-intro { margin: 0 0 24px; }
            #stig-card-blocked, #stig-card-wait { margin: 0 0 16px; }
            .stig-card-or { display: flex; align-items: center; gap: 12px; margin: 24px 0; font-size: 0.875rem; text-transform: lowercase; opacity: 0.75; }
            .stig-card-or::before, .stig-card-or::after { content: ""; flex: 1 1 0; border-top: 1px solid currentColor; opacity: 0.4; }
            #stig-card-idps { list-style: none; margin: 0; padding: 0; display: grid; gap: 16px; }
            #stig-card-idps li { margin: 0; }
            #stig-card-idps a { display: flex !important; justify-content: center !important; text-align: center; width: 100%; }
            #stig-card-idps a span { flex: 0 1 auto !important; text-align: center; }
            #stig-card-other { margin-top: 24px; text-align: center; }
            #kc-card-other { background: transparent; border-color: transparent; box-shadow: none; text-decoration: underline; width: auto; }
        </style>
        <div id="stig-card-blocked" class="${properties.kcAlertClass!} pf-m-warning" role="alert" hidden>
            <span class="${properties.kcAlertTitleClass!}">${msg("stigCardSignInBlocked")}</span>
        </div>
        <div id="stig-card-wait" class="${properties.kcAlertClass!} pf-m-info" role="status" hidden>
            <span class="${properties.kcAlertTitleClass!}">${msg("stigCardSignInStillWaiting")}</span>
        </div>
        <form id="stig-card-signin" action="${cardSignIn}" method="get" data-probe="${cardProbe}" data-waiting="${msg("stigPresentCardWaiting")}">
            <#list cardSignInParams as p>
                <input type="hidden" name="${p.name}" value="${p.value}"/>
            </#list>
            <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                   id="kc-card-signin" type="submit" value="${msg("stigCardSignInUse")}"/>
        </form>
        <#-- the realm's identity providers (e.g. Microsoft Entra ID), as the stock login page lists them, under their
             display names: a person who signs in with one goes straight there. FreeMarker auto-escapes. -->
        <#if social?? && social.providers?? && social.providers?has_content>
            <div id="stig-card-or" class="stig-card-or" role="separator"><span>${msg("stigCardSignInOr")}</span></div>
            <ul id="stig-card-idps" class="${properties.kcFormSocialAccountListClass!}">
                <#list social.providers as p>
                    <li>
                        <a id="social-${p.alias}" class="${properties.kcFormSocialAccountListButtonClass!} ${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                           type="button" href="${p.loginUrl}">
                            <span>${p.displayName!p.alias}</span>
                        </a>
                    </li>
                </#list>
            </ul>
        </#if>
        <#-- "Use another sign-in method" is secondary: a link-styled button below the others -->
        <#if cardOther>
        <form id="stig-card-other" action="${url.loginAction}" method="post">
            <input class="${properties.kcButtonClass!} pf-m-link"
                   name="cancel" id="kc-card-other" type="submit" value="${msg("stigCardSignInOther")}"/>
        </form>
        </#if>
        <script>
            (function () {
                var f = document.getElementById("stig-card-signin"), b = document.getElementById("stig-card-blocked");
                var w = document.getElementById("stig-card-wait");
                var btn = document.getElementById("kc-card-signin"), label = btn.value, sent = false, ac = null, t = null;
                var other = document.getElementById("stig-card-other");
                function reset() { if (t) { clearTimeout(t); t = null; } w.hidden = true; btn.disabled = false; btn.value = label; }
                if (other) other.addEventListener("submit", function () {
                    sent = true;
                    if (ac) ac.abort();
                });
                // back to this page from the browser's history: nothing pending, no message
                window.addEventListener("pageshow", function (ev) { if (ev.persisted) { sent = false; ac = null; reset(); b.hidden = true; } });
                f.addEventListener("submit", function (ev) {
                    if (sent) { ev.preventDefault(); return; }
                    if (!window.fetch || !window.AbortController) return;            // no script support: go directly
                    ev.preventDefault();
                    b.hidden = true; btn.disabled = true; btn.value = f.getAttribute("data-waiting");
                    ac = new AbortController();
                    // Reach the card port first: this is where the browser asks for the certificate (and the card its
                    // PIN), which can take a person any time - so there is NO timeout. After 10 s a note says what is
                    // going on; "blocked" is said only when the card port really cannot be reached (a network error).
                    t = setTimeout(function () { if (!sent) w.hidden = false; }, 10000);
                    fetch(f.getAttribute("data-probe"), {mode: "no-cors", credentials: "include", signal: ac.signal, cache: "no-store"})
                        .then(function () { if (sent) return; sent = true; f.submit(); })
                        .catch(function () {
                            if (sent) return; reset(); b.hidden = false;
                            if (document.getElementById("kc-card-other")) document.getElementById("kc-card-other").focus();
                        });
                });
            })();
        </script>
    </#if>
</@layout.registrationLayout>
