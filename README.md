# VIS Keycloak Custom Rest API

**vis-keycloak-rest-api** is sample app to create custom rest api for keycloak.

At the moment the app only contains one custom rest call, that will generate and return the verify user link by userId.

## Run and test
To execute build the jar by running mvn install and copy the jar to keycloak's `standalone/deployments` folder.

The API call takes `UserId` as **PathParam** and `redirectUri/clientId` as **QueryParam**.
`curl -s -X GET "http://localhost:8080/auth/realms/{RealmName}/vis-rest/get-verify-link/{UserId}?redirect_uri={RedirectURI}&client_id={ClientId}"`