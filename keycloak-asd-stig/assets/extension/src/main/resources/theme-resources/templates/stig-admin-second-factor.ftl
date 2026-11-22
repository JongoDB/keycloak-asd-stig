<#-- stig-extensions AdminSecondFactorRequired, after an identity-provider sign-in: a POLICY refusal (not a wrong
     credential, so it never counts toward lockout), saying what to do instead. -->
<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
    <#if section = "header">
        ${msg("stigAdminSecondFactorTitle")}
    <#elseif section = "form">
        <div id="stig-admin-second-factor" class="${properties.kcAlertClass!} pf-m-danger" role="alert">
            <span class="${properties.kcAlertTitleClass!}">${msg("stigAdminSecondFactor")}</span>
        </div>
        <p><a id="stig-admin-cac" class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!}"
              href="${cacSignIn}">${msg("stigAdminSecondFactorCac")}</a></p>
    </#if>
</@layout.registrationLayout>
