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

import base64
import hashlib
import json
import logging
import os
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any

import requests

# DEFAULT_BACKEND_BASE: Default base for auth endpoints
DEFAULT_BACKEND_BASE = os.getenv(
    "BACKSTAGE_BASE_URL", "http://localhost:7007/api/auth"
).rstrip("/")

# INITIAL_ACCESS_TOKEN [OPTIONAL]: any already existing
# bearer token
INITIAL_ACCESS_TOKEN = os.getenv("INITIAL_ACCESS_TOKEN")

# OUTPUT_FILE: The path we are going to save the credentials
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "oauth_credentials.json")

# TIMEOUT: The timeout value for the backstage requests
TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "10"))

# CLIENT_METADATA: The medata required for lightspeed stack
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

# RUN_AUTH_CODE_FLOW: Flag to run the authorization code generation
RUN_AUTH_CODE_FLOW: "bool" = bool(os.getenv("RUN_AUTH_CODE_FLOW", 1))

# Logger configuration
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("dcr")


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

    def http_get_json(
        self, url: "str", headers: "dict[str, Any] | None" = None
    ) -> "dict[str, Any]":
        """
        sends a GET request to the given url with the given headers
        """
        logger.debug(f"RquestHandler:: GET url {url}")
        r = requests.get(url, headers=headers or {}, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def http_post_json(
        self,
        url: "str",
        payload: "dict[str, Any]",
        auth: "tuple[str, str] | None" = None,
        extra_headers: "dict[str, str] | None" = None,
    ) -> "dict[str, Any]":
        """
        sends a POST request to the given url with the given headers
        """
        _headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if auth:
            _headers["Content-Type"] = "application/x-www-form-urlencoded"

        if extra_headers:
            _headers.update(extra_headers)

        logger.debug(
            f"RequestHandler:: POST {url} payload={json.dumps(payload, separators=(',', ':'))}"
        )

        if auth:
            res = requests.post(
                url,
                data=payload,
                headers=_headers,
                timeout=self.timeout,
                auth=auth,
            )
        else:
            res = requests.post(
                url,
                json=payload,
                headers=_headers,
                timeout=self.timeout,
            )

        ctype = res.headers.get("content-type", "")
        if not res.ok and "application/json" in ctype:
            try:
                err = res.json()
                raise requests.HTTPError(
                    f"{res.status_code} {res.reason} {json.dumps(err)}"
                )
            except Exception:
                pass
            res.raise_for_status()
        return res.json()


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

    oauth_discovery: "str" = (
        f"{DEFAULT_BACKEND_BASE}/.well-known/oauth-authorization-server"
    )
    oidc_discovery: "str" = f"{DEFAULT_BACKEND_BASE}/.well-known/openid-configuration"
    request_handler = RequestHandler()

    def discover(self) -> "Discovery":
        """
        attempts to discover endpoints for auth
        """
        errors = []
        for url in (self.oauth_discovery, self.oidc_discovery):
            try:
                doc = self.request_handler.http_get_json(url)
                logger.info(f"DiscoveryHandler:: discovered metadata from: {url}")

                if url.endswith("oauth-authorization-server"):
                    logger.debug(
                        "DiscoveryHandler:: found OAuth authorization server metadata)."
                    )
                else:
                    logger.debug(
                        "DiscoveryHandler:: looks like OpenID connect discovery 1.0."
                    )

                return Discovery.from_dict(doc)
            except Exception as e:
                errors.append(f"{url}: {e}")

        raise RuntimeError(
            "DiscoveryHandler:: failed at both endpoints:\n  - " + "\n  - ".join(errors)
        )

    def register(self, disc: "Discovery", headers: "dict[str, str]") -> "dict[str, Any]":
        """
        registers a client in backstage
        """
        return self.request_handler.http_post_json(
            disc.registration_endpoint,
            CLIENT_METADATA,
            extra_headers=headers,
        )

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

    def run_auth_code_pkce(
        self,
        disc: "Discovery",
        client: "dict[str, Any]",
        redirect_uri: "str",
    ) -> "dict[str, Any]":
        """
        runs the browser Authorization Code - PKCE flow:
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

        logger.info("BackstageDCRHandler:: === Authorization URL (open in browser) ===")
        logger.info(f"BackstageDCRHandler:: authorization url {authz_url}")
        logger.info(
            "BackstageDCRHandler::After approving, paste the 'code' query param here."
        )
        code = input("BackstageDCRHandler:: Enter the code = ").strip()
        if not code:
            raise ValueError("BackstageDCRHandler:: No authorization code provided")

        # exchange tokens
        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        }

        token_response = self.request_handler.http_post_json(
            disc.token_endpoint,
            payload=payload,
            auth=(client_id, client_secret),
        )

        # update creds file
        try:
            with open(OUTPUT_FILE, "r") as f:
                current = json.load(f)
        except Exception:
            current = {}

        current.setdefault("auth_test", {})
        current["auth_test"]["pkce"] = {
            "used_redirect_uri": redirect_uri,
            "state": state,
            "token_response": token_response,
        }

        with open(OUTPUT_FILE, "w") as f:
            json.dump(current, f, indent=2)
        logger.info(
            "main:: Auth Code  PKCE succeeded; tokens saved under 'auth_test.pkce'"
        )
        return token_response


def main() -> "int":
    logger.info(f"main:: Backend base: {DEFAULT_BACKEND_BASE}")

    dcr_handler = BackstageDCRHandler()
    disc = dcr_handler.discover()

    logger.info("main:: Discovered: \n")
    logger.info("main:: authorization_endpoint: %s", disc.authorization_endpoint)
    logger.info("main:: token_endpoint:        %s", disc.token_endpoint)
    logger.info("main:: jwks_uri:              %s", disc.jwks_uri)
    logger.info("main:: registration_endpoint: %s", disc.registration_endpoint)

    headers = {}
    if INITIAL_ACCESS_TOKEN:
        headers["Authorization"] = f"Bearer {INITIAL_ACCESS_TOKEN}"

    res = dcr_handler.register(disc, headers)

    dcr_handler.save(disc, res)

    if RUN_AUTH_CODE_FLOW:
        redirect_uri = CLIENT_METADATA["redirect_uris"][0]
        dcr_handler.run_auth_code_pkce(
            disc=disc,
            client={
                "client_id": res.get("client_id"),
                "client_secret": res.get("client_secret"),
            },
            redirect_uri=redirect_uri,
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        logger.error("main:: FAILED: %s", e)
        raise
