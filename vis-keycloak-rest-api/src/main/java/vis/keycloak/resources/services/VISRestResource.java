package vis.keycloak.resources.services;

import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.Response.Status;

import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.RealmManager;
import org.keycloak.authentication.actiontoken.execactions.ExecuteActionsActionToken;
import org.keycloak.common.util.Time;
import org.keycloak.models.ClientModel;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.protocol.oidc.utils.RedirectUtils;

import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

public class VISRestResource{
    private KeycloakSession session;
    private HttpHeaders headers;
    private UserModel user = null;
    private RealmModel realm = null;

    public VISRestResource(HttpHeaders headers, KeycloakSession session){
        this.headers = headers;
        this.session = session;
    }

    public void VerifyToken(){
        AppAuthManager authManager = new AppAuthManager();
        String tokenString = authManager.extractAuthorizationHeaderToken(headers);

        if (tokenString == null) {
            throw new NotAuthorizedException("Bearer");
        }

        AccessToken token;

        try {
            JWSInput input = new JWSInput(tokenString);
            token = input.readJsonContent(AccessToken.class);
        } catch (Exception e) {
            throw new NotAuthorizedException("Bearer token format error");
        }

        String realmName = token.getIssuer().substring(token.getIssuer().lastIndexOf('/') + 1);
        RealmManager realmManager = new RealmManager(session);
        RealmModel realm = realmManager.getRealmByName(realmName);

        if (realm == null) {
            throw new NotAuthorizedException("Unknown realm in token");
        }
    }

    public void GetUser(String userId){
        RealmModel realm = session.getContext().getRealm();
        UserModel user = session.users().getUserById(realm, userId);

        if (Objects.isNull(user)) {
            user = session.users().getUserByUsername(realm ,userId);
        }
        if (Objects.isNull(user)) {
            user = session.users().getUserByEmail(realm, userId);
        }
        if (Objects.isNull(user)) {
            user = session.users().getServiceAccount(realm.getClientById(userId));
        }

        this.realm = realm;
        this.user = user;
    }

    public String GenerateVerificationLink(String redirectUri, String clientId){
        List<String> actions = new LinkedList<>();
        actions.add(UserModel.RequiredAction.VERIFY_EMAIL.name());
        actions.add(UserModel.RequiredAction.UPDATE_PASSWORD.name());

        if (user == null) {
            throw new WebApplicationException(
                ErrorResponse.error("User undefined", Status.BAD_REQUEST));
        }

        if (!user.isEnabled()) {
            throw new WebApplicationException(
                ErrorResponse.error("User is disabled", Status.BAD_REQUEST));
        }

        if (redirectUri != null && clientId == null) {
            throw new WebApplicationException(
                ErrorResponse.error("Client id missing", Status.BAD_REQUEST));
        }

        ClientModel client = realm.getClientByClientId(clientId);
        if (client == null) {
            throw new WebApplicationException(
                ErrorResponse.error("Client doesn't exist", Status.BAD_REQUEST));
        }
        if (!client.isEnabled()) {
            throw new WebApplicationException(
                    ErrorResponse.error("Client is not enabled", Status.BAD_REQUEST));
        }

        String redirect;
        if (redirectUri != null) {
            redirect = RedirectUtils.verifyRedirectUri(session, redirectUri, client);
            if (redirect == null) {
                throw new WebApplicationException(
                    ErrorResponse.error("Invalid redirect uri.", Status.BAD_REQUEST));
            }
        }
        
        try {
            ExecuteActionsActionToken token = new ExecuteActionsActionToken(user.getId(), user.getEmail(), (Time.currentTime() + realm.getActionTokenGeneratedByAdminLifespan()), actions, redirectUri, clientId);

            UriBuilder builder = LoginActionsService.actionTokenProcessor(session.getContext().getUri());
            builder.queryParam("key", token.serialize(session, realm, session.getContext().getUri()));

            String link = builder.build(realm.getName()).toString();
            
            return link;
        } catch (Exception e) {
            throw new WebApplicationException(
                    ErrorResponse.error(e.getMessage(), Status.BAD_REQUEST));  
        }
    }
}