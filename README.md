# Backstage DCR PoC

This repo tries to experiemnt with the suggested dynamic client registration feature implementation for Backstage. PR can be found here: https://github.com/backstage/backstage/pull/30606

## How it works

This script runs a full `OAuth 2.0` flow against a local Backstage backend instance, build from [backstage#300606](https://github.com/backstage/backstage/pull/30606) which implements the Dynamic Client Registration (DCR) protocol. More specifically:

### Overview

1. **Discovers** the auth server endpoints by using the `/.well-known/openid-configuration`.
2. **Registers** a new OAuth client (DCR) to get a `client_id` and `client_secret`.
3. Fetches the **authorization code** (following the [PKCE protocol](https://www.rfc-editor.org/rfc/rfc7636)).It starts by buidling the authorization url, then captures the session id, and then approves it as a Guest Backstage user. Finally it extracts the `code` from the redirect url that the `/token` endpoint returns, and exchanges it for JWT tokens.
4. It finally dumps the credentials locally in order to have all the information of this run in place.

> **NOTE**: It's a PoC and it uses a guest token. Don't use this code in production.
> **NOTE**: As the frontend plugin for [backstage#300606](https://github.com/backstage/backstage/pull/30606) is not yet implemented, we have by-passed the UI implementation to deal with the authorization and the approval of the session.

### Flow

![`main.py` flow](images/flow.png)

#### Discovery

- **Endpoint:** `GET {BACKSTAGE_BASE_URL}/.well-known/openid-configuration`
- **Purpose:** Discovers all the necessary endpoints.
- **Expected fields:** `authorization_endpoint`, `token_endpoint`, `registration_endpoint` (+ optionally `issuer`, `jwks_uri`).
- **Specs:** Uses metadata as defined in [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) and in [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)

#### Dynamic Client Registration (DCR)

- **Endpoint:** `POST /{discovery.registration_endpoint}`
- **Body:** Is the `CLIENT_METADATA` which contains:

```python
# CLIENT_METADATA: The metadata required requried for the registration
# endpoint
CLIENT_METADATA: "dict[str, Any]" = {
    "client_name": "local dev",
    "redirect_uris": [
        "http://localhost:8080/auth/callback",
        "http://localhost:8080/auth/backstage/callback",
    ],
    "grant_types": ["authorization_code"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "client_secret_basic",
    "scope": "openid profile email",
    "software_id": "lightspeed-stack-local",
    "software_version": "0.1.0",
}
```

- **Response:** `client_id`, often `client_secret`, timestamps, and echoed metadata
- **Specs:** OAuth 2.0 Dynamic Client Registration as defined in [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591).

#### Authorization Code + PKCE

> **NOTE**: Here in order to tackle the absence of frontend UI where the user can authorize the session that the client registration creates we have implemented an alternative flow.

1. **Create PKCE and state**

   - `code_verifier`: high-entropy URL-safe string
   - `code_challenge = BASE64URL(SHA256(code_verifier))`
   - **Spec:** Inspired by: https://www.stefaanlippens.net/oauth-code-flow-pkce.html.

2. **Build the authorization URL**

   - We need to build the authorization URL so we can have a link where we can authorize the registered client.

3. **Get Session Id for Approval**

   - `GET {authorization_endpoint}?...` with `allow_redirects=False`
   - We have added this because we need to get the redirect url so we can extract the session id and then use the `/approve` endpoint.

4. **Approve Session**

   - Get a guest JWT: `GET /guest/refresh`
   - This is important as the `/approve` endpoint requires authentication.
   - Approve session: `POST /v1/sessions/{session_id}/approve` with header `Authorization: Bearer <token>` and body `{"userEntityRef": BACKSTAGE_USER}`
   - Response contains `{ redirectUrl: "http://.../auth/callback?code=...&state=..." }` which can be used to validate `auth_code` and `state`.

5. **Exchange code to get tokens**

   - **Endpoint:** `POST {discovery.token_endpoint}`
   - **Body:**:

   ```python
    BODY = {
       "grant_type": "authorization_code",
       "code": auth_code,
       "redirect_uri": redirect_uri,
       "code_verifier": code_verifier,
       "client_id": client_id,
       "client_secret": client_secret
    }
   ```

   - **Specs:** From OAuth 2.0 [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) and the [OIDC Core 1.0 — Token Request](https://openid.net/specs/openid-connect-core-1_0.html#TokenRequest)

## Usage

This project requires some steps to be taken prior running the script.

- First we need to run the [backstage branch](https://github.com/backstage/backstage/tree/blam/oidc-auth/3) related to the implementation PR:

```bash
# clone the repo locally
git clone https://github.com/backstage/backstage.git
cd backstage
git checkout blam/oidc-auth/3
```

- Then you need to run the backend app. First you need to remove [this line](https://github.com/backstage/backstage/blob/blam/oidc-auth/3/packages/backend/src/index.ts#L36):

```ts
backend.add(import("@backstage/plugin-app-backend"));
```

- Finally inside the `backstage/packages/backend` you need to run:

```bash
yarn install
yarn start
```

- Now you have started the backstage API so you are able to interact locally with the backstage backend. All it remains is to run the script.

```bash
pip install .
python3 run main.py
```

### Env vars

The following env vars can be configured

- `BACKSTAGE_BASE_URL`: The base url of backstage (default `http://localhost:7007/api/auth`)
- `OUTPUT_FILE`: The path to save the creds locally (default `oauth_credentials.json`)
- `HTTP_TIMEOUT`: The default request timeout (default `10`)
