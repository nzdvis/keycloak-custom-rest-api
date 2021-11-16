package vis.keycloak;

import org.keycloak.models.KeycloakSession;

import vis.keycloak.resources.services.VISRestResource;

import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.resource.RealmResourceProvider;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response.Status;

/**
 * Resource for managing user verification
 *
 * @resource UserVerification
 * @author <a href="mailto:nzd@vis-performance.dk">Nikolas Zdralic</a>
 * @version $Revision: 1 $
 */

public class VISRestProvider implements RealmResourceProvider{
    private VISRestResource visRestResource;

    public VISRestProvider(KeycloakSession session) {
        visRestResource = new VISRestResource(session.getContext().getRequestHeaders(), session);
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
        visRestResource.VerifyToken();
        visRestResource.GetUser(userId);

        String generatedLink = visRestResource.GenerateVerificationLink(redirectUri, clientId);

        if (generatedLink != null){
            return generatedLink;
        }
        else{
            throw new WebApplicationException(
                    ErrorResponse.error("Link not generated", Status.BAD_REQUEST));
        }
    }
}
