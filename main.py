#!/usr/bin/env python3

# The current script is a very simple implementation
# that stands as a PoC for LSCore and the suggested
# new Dynamic Client Registration feature for backstage

# The backstage feature has been suggested here:

# https://github.com/backstage/backstage/pull/30606

# NOTE [IMPORTANT]: This script is only meant for
# testing, do not try this with Backstage instances
# used for production as there is a risk of leaking
# sensitive data.

import asyncio
import base64
import hashlib
import json
import logging
import os
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlparse

import requests
from fastmcp import Client
from fastmcp.client.auth import BearerAuth
from fastmcp.client.auth.oauth import OAuth
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.tools import Tool

# DEFAULT_BACKEND_BASE: Default base for backstage urls
DEFAULT_BACKEND_BASE = os.getenv("BACKSTAGE_BASE_URL", "http://localhost:7007").rstrip(
    "/"
)

# SKIP_DCR: Skips the DCR handler process and tries auth
# directly from the fastmcp client.
SKIP_DCR = bool(os.getenv("SKIP_DCR", False))

# DEFAULT_BACKEND_AUTH_BASE: Default base for auth endpoints
DEFAULT_BACKEND_AUTH_BASE = os.getenv(
    "BACKSTAGE_BASE_URL", "http://localhost:7007/api/auth"
).rstrip("/")

# OUTPUT_FILE: The path we are going to save the credentials
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "oauth_credentials.json")

# TIMEOUT: The timeout value for the backstage requests
TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "10"))

# CLIENT_METADATA: The metadata required requried for the registration
# endpoint
CLIENT_METADATA: "dict[str, Any]" = {
    "client_name": "lightspeed-stack (local dev)",
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

# BACKSTAGE_USER: The ref of the user we want to authenticate
# default value is the guest user
BACKSTAGE_USER = "user:default/guest"

# RUN_AUTH_CODE_FLOW: Flag to run the authorization code generation
RUN_AUTH_CODE_FLOW: "bool" = bool(os.getenv("RUN_AUTH_CODE_FLOW", 1))

# Logger configuration
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("dcr")


class BackstageEndpoints:
    DISCOVERY = "{base_url}/.well-known/openid-configuration"
    APPROVE = "{base_url}/v1/sessions/{session_id}/approve"
    REFRESH = "{base_url}/guest/refresh"
    MCP_ACTIONS = "{base_url}/api/mcp-actions/v1"


def get_key_or_raise_error(d: "dict[str, Any]", key: "str") -> "Any":
    if key not in d or not d[key]:
        raise ValueError(f"main:: discovery document missing required key: {key}")
    return d[key]


@dataclass
class RequestHandler:
    """
    RequestHandler takes care of all the requests logic required
    during the experiments with backstage backend
    """

    timeout: "float" = TIMEOUT

    def get(
        self,
        url: "str",
        headers: "dict[str, Any] | None" = None,
        allow_redirects: "bool" = True,
    ) -> "requests.Response":
        """
        sends a GET request to the given url with the given headers
        """
        logger.debug(f"RquestHandler:: GET url {url}")
        res = requests.get(
            url,
            headers=headers or {},
            timeout=self.timeout,
            allow_redirects=allow_redirects,
        )
        return res

    def post(
        self,
        url: "str",
        payload: "dict[str, Any]",
        auth: "tuple[str, str] | None" = None,
        headers: "dict[str, str] | None" = None,
    ) -> "requests.Response":
        """
        sends a POST request to the given url with the given headers
        """
        logger.debug(
            f"RequestHandler:: POST {url} payload={json.dumps(payload, separators=(',', ':'))}"
        )

        if auth:
            res = requests.post(
                url,
                data=payload,
                headers=headers,
                timeout=self.timeout,
                auth=auth,
            )
        else:
            res = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=self.timeout,
            )
        return res


@dataclass
class Discovery:
    """
    discovery is an abstracton used to handle the results we get from
    endpoint discovery
    """

    authorization_endpoint: "str"
    token_endpoint: "str"
    registration_endpoint: "str"
    raw: "dict[str, Any]"
    issuer: "str | None"
    jwks_uri: "str | None"

    @classmethod
    def from_dict(cls, discovery_dict: "dict[str, Any]") -> "Discovery":
        """
        creates a Discovery instance from a given dict
        """
        # According to RFC8414 registration endpoint is optional
        # https://datatracker.ietf.org/doc/html/rfc8414
        if "registration_endpoint" not in discovery_dict:
            raise ValueError(
                "Discovery:: no registration_endpoint in discovery; server may not support DCR"
            )
        return cls(
            issuer=discovery_dict.get("issuer"),
            authorization_endpoint=get_key_or_raise_error(
                discovery_dict, "authorization_endpoint"
            ),
            token_endpoint=get_key_or_raise_error(discovery_dict, "token_endpoint"),
            jwks_uri=discovery_dict.get("jwks_uri"),
            registration_endpoint=get_key_or_raise_error(
                discovery_dict, "registration_endpoint"
            ),
            raw=discovery_dict,
        )


@dataclass
class BackstageDCRHandler:
    """
    BackstageDCRHandler is the main class handling the discovery and
    client registration
    """

    user_entity_ref = BACKSTAGE_USER
    request_handler = RequestHandler()
    base_url = DEFAULT_BACKEND_AUTH_BASE

    def discover(self) -> "Discovery":
        """
        attempts to discover endpoints for auth
        """
        url = BackstageEndpoints.DISCOVERY.format(base_url=self.base_url)
        try:
            res = self.request_handler.get(url)
            logger.info(f"DiscoveryHandler:: discovered metadata from: {url}")

            return Discovery.from_dict(res.json())
        except Exception as e:
            raise RuntimeError(f"DiscoveryHandler:: discovery failed: {str(e)}")

    def register(self, disc: "Discovery", headers: "dict[str, str]") -> "dict[str, Any]":
        """
        registers a client in backstage
        """
        res = self.request_handler.post(
            disc.registration_endpoint,
            CLIENT_METADATA,
            headers=headers,
        )
        return res.json()

    def get_token(self) -> "str":
        """
        gets a guest JWT token from /refresh
        """
        res = self.request_handler.get(
            BackstageEndpoints.REFRESH.format(base_url=self.base_url),
            headers={"Content": "application/json"},
        )
        res.raise_for_status()

        res_dict = res.json()
        return res_dict["backstageIdentity"]["token"]

    def save(self, disc: "Discovery", res: "dict[str, Any]") -> "None":
        """
        saves your credentials locally
        """
        out = {
            "discovery": {
                "issuer": disc.issuer,
                "authorization_endpoint": disc.authorization_endpoint,
                "token_endpoint": disc.token_endpoint,
                "jwks_uri": disc.jwks_uri,
                "registration_endpoint": disc.registration_endpoint,
            },
            "client": {
                "client_id": res.get("client_id"),
                "client_secret": res.get("client_secret"),
                "client_id_issued_at": res.get("client_id_issued_at"),
                "client_secret_expires_at": res.get("client_secret_expires_at"),
                "registration_client_uri": res.get("registration_client_uri"),
                "registration_access_token": res.get("registration_access_token"),
                "metadata_submitted": CLIENT_METADATA,
                "metadata_returned": res,
            },
            "saved_at": int(time.time()),
        }

        with open(OUTPUT_FILE, "w") as f:
            json.dump(out, f, indent=2, sort_keys=False)

        logger.info(f"main:: Creds saved at {OUTPUT_FILE}")

    def _urlsafe_random(self, nbytes: "int" = 64) -> "str":
        "creates a random string"
        return base64.urlsafe_b64encode(os.urandom(nbytes)).decode("ascii").rstrip("=")

    def _b64url_sha256(self, data: "bytes") -> "str":
        "encodes the given data using its hash"
        return (
            base64.urlsafe_b64encode(hashlib.sha256(data).digest())
            .decode("ascii")
            .rstrip("=")
        )

    def build_authorization_url(
        self,
        disc: "Discovery",
        client_id: "str",
        redirect_uri: "str",
        scope: "str",
        state: "str",
        code_challenge: "str",
    ) -> "str":
        """
        builds an authorization url for /authorize endpoint
        https://www.oauth.com/oauth2-servers/authorization/the-authorization-request
        """
        qs = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        return f"{disc.authorization_endpoint}?{urllib.parse.urlencode(qs)}"

    def _extract_session_id(self, res: "requests.Response") -> "str":
        """
        extracts the authorization session id to tackle the missing
        frontend plugin to authorize clients
        """
        loc1 = res.headers.get("location")
        if not loc1:
            raise RuntimeError(
                "BackstageDCRHandler:: /authorize without Location header"
            )
        path = urllib.parse.urlparse(loc1).path
        return [p for p in path.split("/") if p][-1]

    def _update_creds(
        self, redirect_uri: "str", state: "str", res: "dict[str, Any]"
    ) -> "None":
        "updates the credentials output file with the final creds"
        try:
            with open(OUTPUT_FILE, "r") as f:
                current = json.load(f)
        except Exception:
            current = {}

        current.setdefault("auth_test", {})
        current["auth_test"]["pkce"] = {
            "used_redirect_uri": redirect_uri,
            "state": state,
            "token_response": res,
        }

        with open(OUTPUT_FILE, "w") as f:
            json.dump(current, f, indent=2)

    def _parse_qs(self, q: "str", redirect_uri: "str") -> "str":
        return parse_qs(urlparse(redirect_uri).query).get(q, [None])[0]

    def approve(self, session_id: "str", user_entity_ref: "str") -> "tuple[str, str]":
        url = BackstageEndpoints.APPROVE.format(
            session_id=session_id, base_url=self.base_url
        )
        token = self.get_token()
        payload = {"userEntityRef": user_entity_ref}
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        }
        res = self.request_handler.post(url, payload=payload, headers=headers)
        try:
            if res.status_code not in (200, 204):
                res.raise_for_status()
        except Exception as e:
            raise RuntimeError(
                f"BackstageDCRHandler:: approve failed ({res.status_code}): {e} :: {res.text}"
            )

        data = res.json()
        auth_code = self._parse_qs("code", data["redirectUrl"])
        returned_state = self._parse_qs("state", data["redirectUrl"])
        return (auth_code, returned_state)

    def pkce_authorize(
        self,
        disc: "Discovery",
        client: "dict[str, Any]",
        redirect_uri: "str",
    ) -> "str":
        """
        runs the pkce authorization flow:
        - prints an authorization URL
        - peads ?code= from stdin
        - exchanges code for tokens at token_endpoint
        """
        client_id = client.get("client_id")
        client_secret = client.get("client_secret")
        scope = CLIENT_METADATA.get("scope", "openid profile email")

        # creates the PKCE (Proof Key for Code Exchange)
        # https://www.stefaanlippens.net/oauth-code-flow-pkce.html
        code_verifier = self._urlsafe_random(64)
        code_challenge = self._b64url_sha256(code_verifier.encode("ascii"))
        state = self._urlsafe_random(16)

        # NOTE: This is not implemented yet on the backstage side:
        # see https://github.com/backstage/backstage/pull/30606#issue-3248826365
        # That said redirection will give 404.
        authz_url = self.build_authorization_url(
            disc=disc,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            code_challenge=code_challenge,
        )

        # We disable redirects to get the redirect url that the authorization
        # front end will be returning to the user
        redirect_res = self.request_handler.get(authz_url, allow_redirects=False)
        if redirect_res.status_code not in (302, 303):
            raise RuntimeError(
                f"BackstageDCRHandler:: expected 302 from /authorize, got {redirect_res.status_code}"
            )

        # extract the session id from the redirect url
        session_id = self._extract_session_id(redirect_res)
        if not session_id:
            raise RuntimeError(
                "BackstageDCRHandler:: failed to parse session id from Location"
            )

        logger.info(
            f"BackstageDCRHandler:: captured authorization session id: {session_id}"
        )

        auth_code, returned_state = self.approve(session_id, self.user_entity_ref)

        if not auth_code:
            raise RuntimeError(
                "BackstageDCRHandler:: redirect did not include an authorization code"
            )

        if returned_state != state:
            logger.warning(
                f"BackstageDCRHandler:: state mismatch: expected {state} got {returned_state}"
            )

        # exchange tokens with the auth_code
        token_payload = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
            "client_id": client_id,
            "client_secret": client_secret,
        }

        token_response = self.request_handler.post(
            disc.token_endpoint,
            payload=token_payload,
            auth=(client_id, client_secret),
        )

        token_res_dict = token_response.json()
        _ = self._update_creds(redirect_uri, state, token_res_dict)
        logger.info(
            "main:: Auth Code + PKCE (no-UI) succeeded; tokens saved under 'auth_test.pkce'"
        )
        return token_res_dict["access_token"]


@dataclass
class BackstageMCPClient:
    access_token: "str"
    exclude_dcr_handler: "bool"
    base_url = DEFAULT_BACKEND_BASE

    @property
    def transport(self) -> "StreamableHttpTransport":
        # NOTE: enabling exclude_dcr_handler won't work
        # as the frontend side of https://github.com/backstage/backstage/issues/30069
        # is not implemented yet
        if self.exclude_dcr_handler:
            return StreamableHttpTransport(
                url=BackstageEndpoints.MCP_ACTIONS.format(base_url=self.base_url),
                auth=OAuth(mcp_url="http://localhost:7007/api/mcp-actions/v1"),
            )
        # default approach we are passing the DCR handler's token.
        return StreamableHttpTransport(
            url=BackstageEndpoints.MCP_ACTIONS.format(base_url=self.base_url),
            auth=BearerAuth(token=self.access_token),
            headers={"Accept": "application/json, text/event-stream"},
        )

    def get_client(self) -> "Client":
        return Client(self.transport)

    def _output_tools(self, tools: "list[Tool]") -> "None":
        """
        outputs the list of tools fetched from backstage
        """
        if len(tools) == 0:
            logger.info("BackstageMCPClient:: No tools found")
            return

        logger.info(f"BackstageMCPClient:: Found {len(tools)}")
        for tool in tools:
            logger.info(f"Tool: {tool.name}")

    async def get_backstage_tools(self, verbose=True) -> "list":
        client = self.get_client()

        async with client:
            await client.ping()
            tools = await client.list_tools()
            if verbose:
                self._output_tools(tools)
            return tools


def main() -> "int":
    logger.info(f"main:: Backend base: {DEFAULT_BACKEND_BASE}")
    logger.info(f"main:: Backend auth base: {DEFAULT_BACKEND_AUTH_BASE}")
    token = ""

    if SKIP_DCR is False:
        dcr_handler = BackstageDCRHandler()
        disc = dcr_handler.discover()

        logger.info("main:: Discovered: \n")
        logger.info("main:: authorization_endpoint: %s", disc.authorization_endpoint)
        logger.info("main:: token_endpoint:        %s", disc.token_endpoint)
        logger.info("main:: jwks_uri:              %s", disc.jwks_uri)
        logger.info("main:: registration_endpoint: %s", disc.registration_endpoint)

        res = dcr_handler.register(disc, {})
        dcr_handler.save(disc, res)
        redirect_uri = CLIENT_METADATA["redirect_uris"][0]
        token = dcr_handler.pkce_authorize(
            disc=disc,
            client={
                "client_id": res.get("client_id"),
                "client_secret": res.get("client_secret"),
            },
            redirect_uri=redirect_uri,
        )
    mcp_client = BackstageMCPClient(access_token=token, exclude_dcr_handler=SKIP_DCR)
    asyncio.run(mcp_client.get_backstage_tools())
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        logger.error("main:: FAILED: %s", e)
        raise
