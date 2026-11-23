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
        <#-- [hidden] must win over the theme's alert display (PatternFly sets display on its alert class, which beats the
             browser's own [hidden] rule: without this the "blocked" alert showed on every load) -->
        <style>
            #stig-card-blocked[hidden], #stig-card-wait[hidden] { display: none !important; }
            #stig-card-intro { margin: 0 0 24px; }
            #stig-card-blocked, #stig-card-wait { margin: 0 0 16px; }
            #stig-card-ignore { margin-top: 16px; }
        </style>
        <div id="stig-card-blocked" class="${properties.kcAlertClass!} pf-m-warning" role="alert" hidden>
            <span class="${properties.kcAlertTitleClass!}">${msg("stigPresentCardBlocked")}</span>
        </div>
        <div id="stig-card-wait" class="${properties.kcAlertClass!} pf-m-info" role="status" hidden>
            <span class="${properties.kcAlertTitleClass!}">${msg("stigPresentCardStillWaiting")}</span>
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
                var w = document.getElementById("stig-card-wait");
                var btn = document.getElementById("kc-login"), label = btn.value, sent = false, ac = null, t = null;
                function reset() { if (t) { clearTimeout(t); t = null; } w.hidden = true; btn.disabled = false; btn.value = label; }
                window.addEventListener("pageshow", function (ev) { if (ev.persisted) { sent = false; ac = null; reset(); b.hidden = true; } });
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
                    b.hidden = true; btn.disabled = true; btn.value = f.getAttribute("data-waiting");   // an attribute: escaped as HTML, read as text
                    ac = new AbortController();
                    // Reach the card port first: this is where the browser asks for the certificate (and the card its
                    // PIN), which can take a person any time - so there is NO timeout. After 10 s a note says what is
                    // going on; "blocked" is said only when the card port really cannot be reached (a network error).
                    t = setTimeout(function () { if (!sent) w.hidden = false; }, 10000);
                    fetch(f.getAttribute("data-probe"), {mode: "no-cors", credentials: "include", signal: ac.signal, cache: "no-store"})
                        .then(function () { if (sent) return; sent = true; f.submit(); })
                        .catch(function () {
                            if (sent) return; reset(); b.hidden = false;
                            document.getElementById("kc-cancel").focus();
                        });
                });
            })();
        </script>
    </#if>
</@layout.registrationLayout>
