<#-- stig-extensions X.509 step (STIG_CARD_PORT set, no certificate on this connection): "Sign in with my CAC" goes to
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
        <div id="stig-card-blocked" class="${properties.kcAlertClass!} pf-m-warning" role="alert" hidden>
            <span class="${properties.kcAlertTitleClass!}">${msg("stigCardSignInBlocked")}</span>
        </div>
        <form id="stig-card-signin" action="${cardSignIn}" method="get" data-probe="${cardProbe}" data-waiting="${msg("stigPresentCardWaiting")}">
            <#list cardSignInParams as p>
                <input type="hidden" name="${p.name}" value="${p.value}"/>
            </#list>
            <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                   id="kc-card-signin" type="submit" value="${msg("stigCardSignInUse")}"/>
        </form>
        <#-- the realm's identity providers (e.g. Microsoft), as the stock login page lists them: a person who signs in
             with one goes straight there, without "Use another sign-in method" first. FreeMarker auto-escapes. -->
        <#if social?? && social.providers?? && social.providers?has_content>
            <ul id="stig-card-idps" class="${properties.kcFormSocialAccountListClass!}">
                <#list social.providers as p>
                    <li>
                        <a id="social-${p.alias}" class="${properties.kcFormSocialAccountListButtonClass!} ${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonBlockClass!}"
                           type="button" href="${p.loginUrl}">
                            <span>${p.displayName!p.alias}</span>
                        </a>
                    </li>
                </#list>
            </ul>
        </#if>
        <#if cardOther>
        <form id="stig-card-other" action="${url.loginAction}" method="post">
            <input class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                   name="cancel" id="kc-card-other" type="submit" value="${msg("stigCardSignInOther")}"/>
        </form>
        </#if>
        <script>
            (function () {
                var f = document.getElementById("stig-card-signin"), b = document.getElementById("stig-card-blocked");
                var btn = document.getElementById("kc-card-signin"), label = btn.value, sent = false, ac = null;
                var other = document.getElementById("stig-card-other");
                if (other) other.addEventListener("submit", function () {
                    sent = true;
                    if (ac) ac.abort();
                });
                f.addEventListener("submit", function (ev) {
                    if (sent) { ev.preventDefault(); return; }
                    if (!window.fetch || !window.AbortController) return;            // no script support: go directly
                    ev.preventDefault();
                    btn.disabled = true; btn.value = f.getAttribute("data-waiting");
                    ac = new AbortController();
                    var t = setTimeout(function () { ac.abort(); }, 10000);
                    // reach the card port first (where the browser asks for the certificate); unreachable within 10 s:
                    // the network blocks it - offer the other sign-in methods
                    fetch(f.getAttribute("data-probe"), {mode: "no-cors", credentials: "include", signal: ac.signal, cache: "no-store"})
                        .then(function () { clearTimeout(t); if (sent) return; sent = true; f.submit(); })
                        .catch(function () {
                            clearTimeout(t); if (sent) return; b.hidden = false; btn.disabled = false; btn.value = label;
                            if (document.getElementById("kc-card-other")) document.getElementById("kc-card-other").focus();
                        });
                });
            })();
        </script>
    </#if>
</@layout.registrationLayout>
