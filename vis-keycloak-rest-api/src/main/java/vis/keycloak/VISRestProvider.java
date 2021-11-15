package vis.keycloak;

import org.keycloak.authentication.actiontoken.execactions.ExecuteActionsActionToken;
import org.keycloak.common.util.Time;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.utils.RedirectUtils;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;
import org.keycloak.services.resource.RealmResourceProvider;

import javax.ws.rs.GET;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.Response.Status;

import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

/**
 * Resource for managing user verification
 *
 * @resource UserVerification
 * @author <a href="mailto:nzd@vis-performance.dk">Nikolas Zdralic</a>
 * @version $Revision: 1 $
 */

public class VISRestProvider implements RealmResourceProvider {
    private final KeycloakSession session;
   // private final AuthResult auth;
    private UserModel user = null;
    private RealmModel realm = null;

    public VISRestProvider(KeycloakSession session) {
        this.session = session;
        //this.auth = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
    }

    public void close() {

    }

    public Object getResource() {
        return this;
    }

    @GET
    @Path("get-verify-link/{userId}")
    @Produces("text/plain; charset=utf-8")
    public String get(final @PathParam("userId") String userId, 
                            @QueryParam(OIDCLoginProtocol.REDIRECT_URI_PARAM) String redirectUri, 
                            @QueryParam(OIDCLoginProtocol.CLIENT_ID_PARAM) String clientId) {
        // if (this.auth == null || this.auth.getToken() == null) {
        //     throw new NotAuthorizedException("Bearer");
        // }
        
        getUser(userId);

        String generatedLink = generateVerificationLink(redirectUri, clientId);

        if (generatedLink != null){
            return generatedLink;
        }
        else{
            throw new WebApplicationException(
                    ErrorResponse.error("Link not generated", Status.BAD_REQUEST));
        }
    }

    private void getUser(String userId){
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

    private String generateVerificationLink(String redirectUri, String clientId){
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
