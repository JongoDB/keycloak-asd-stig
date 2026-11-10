package mil.stig.keycloak;

import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

/** Condition: the user is an administrator (holds any realm-management role, effectively). Unlike "Condition - user
 *  role", which names one role, this matches every administrator whatever subset of realm-management they hold. */
public class ConditionalAdministratorAuthenticatorFactory implements ConditionalAuthenticator, ConditionalAuthenticatorFactory {

    public static final String ID = "conditional-stig-administrator";

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        return StigAdministrators.isAdministrator(context.getRealm(), context.getUser());
    }

    @Override public void action(AuthenticationFlowContext context) { }
    @Override public boolean requiresUser() { return true; }
    @Override public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) { }
    @Override public void close() { }

    @Override public ConditionalAuthenticator getSingleton() { return this; }
    @Override public void init(Config.Scope config) { }
    @Override public void postInit(KeycloakSessionFactory factory) { }
    @Override public String getId() { return ID; }
    @Override public String getDisplayType() { return "Condition - user is an administrator"; }
    @Override public String getReferenceCategory() { return null; }
    @Override public boolean isConfigurable() { return false; }
    @Override public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.DISABLED};
    }
    @Override public boolean isUserSetupAllowed() { return false; }
    @Override public String getHelpText() { return "Matches a user holding any realm-management role (directly, by composite or by group)."; }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return List.of(); }
}
