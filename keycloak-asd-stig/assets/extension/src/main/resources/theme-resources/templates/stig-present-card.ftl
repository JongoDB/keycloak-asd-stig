<#-- stig-extensions PresentCardRequiredAction: the card is presented on the CARD PORT (a new TLS handshake that asks for
     the certificate); "continue without" stays on this page's own origin, so a network that blocks the card port can
     always go on. -->
<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=true; section>
    <#if section = "header">
        ${msg("stigPresentCardTitle")}
    <#elseif section = "form">
        <#if cardError?? && cardError?has_content>
            <div id="stig-card-error" class="${properties.kcAlertClass!} pf-m-danger" role="alert">
                <span class="${properties.kcAlertTitleClass!}">${cardError}</span>
            </div>
        </#if>
        <p id="stig-card-intro">${msg("stigPresentCardIntro")}</p>
        <div id="stig-card-blocked" class="${properties.kcAlertClass!} pf-m-warning" role="alert" hidden>
            <span class="${properties.kcAlertTitleClass!}">${msg("stigPresentCardBlocked")}</span>
        </div>
        <form id="stig-card-form" action="${cardAction}" method="post" data-probe="${cardProbe}" data-waiting="${msg("stigPresentCardWaiting")}">
            <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                   name="login" id="kc-login" type="submit" value="${msg("stigPresentCardUse")}"/>
        </form>
        <form id="stig-card-ignore" action="${url.loginAction}" method="post">
            <input class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                   name="cancel" id="kc-cancel" type="submit" value="${msg("stigPresentCardIgnore")}"/>
        </form>
        <script>
            (function () {
                var f = document.getElementById("stig-card-form"), b = document.getElementById("stig-card-blocked");
                var btn = document.getElementById("kc-login"), label = btn.value, sent = false, ac = null;
                // "Continue without the card" wins: it stops a probe in flight, and a probe that resolves later can
                // no longer submit the card form over it
                document.getElementById("stig-card-ignore").addEventListener("submit", function () {
                    sent = true;
                    if (ac) ac.abort();
                });
                f.addEventListener("submit", function (ev) {
                    if (sent) { ev.preventDefault(); return; }                       // already on its way (either form)
                    if (!window.fetch || !window.AbortController) return;            // no script support: post directly
                    ev.preventDefault();
                    btn.disabled = true; btn.value = f.getAttribute("data-waiting");       // an attribute: escaped as HTML, read as text
                    ac = new AbortController();
                    var t = setTimeout(function () { ac.abort(); }, 10000);
                    // reach the card port first (this is where the browser asks for the certificate); if it cannot be
                    // reached within 10 s, the network blocks it: offer to continue without the card
                    fetch(f.getAttribute("data-probe"), {mode: "no-cors", credentials: "include", signal: ac.signal, cache: "no-store"})
                        .then(function () { clearTimeout(t); if (sent) return; sent = true; f.submit(); })
                        .catch(function () {
                            clearTimeout(t); if (sent) return; b.hidden = false; btn.disabled = false; btn.value = label;
                            document.getElementById("kc-cancel").focus();
                        });
                });
            })();
        </script>
    </#if>
</@layout.registrationLayout>
