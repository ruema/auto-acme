import base64
import datetime
import hashlib
import json
import logging
import ssl
import threading
import time
from pathlib import Path

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)

ACME_IDENTIFIER = x509.ObjectIdentifier("1.3.6.1.5.5.7.1.31")
SSL3_RT_HANDSHAKE = 22


def base64url_encode(payload):
    if not isinstance(payload, bytes):
        payload = payload.encode("utf-8")
    encode = base64.urlsafe_b64encode(payload)
    return encode.decode("utf-8").rstrip("=")


def encode_int(n):
    return base64url_encode(n.to_bytes(32, "big"))


def json_encode(header):
    return json.dumps(
        header,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def jwk_dict(private_key):
    numbers = private_key.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": encode_int(numbers.x),
        "y": encode_int(numbers.y),
    }


def jwk_thumbprint(key):
    payload = json_encode(jwk_dict(key))
    digest = hashlib.sha256(payload).digest()
    return base64url_encode(digest)


def generate_signed_request(private_key, kid, url, nonce, payload):
    protected = {
        "alg": "ES256",
        "nonce": nonce,
        "url": url,
    }
    if kid is None:
        protected["jwk"] = jwk_dict(private_key)
    else:
        protected["kid"] = kid
    encoded_protected = base64url_encode(json_encode(protected))
    if payload is None:
        encoded_payload = ""
    else:
        encoded_payload = base64url_encode(json_encode(payload))
    signature = private_key.sign(
        f"{encoded_protected}.{encoded_payload}".encode("utf8"),
        ec.ECDSA(hashes.SHA256()),
    )
    r, s = decode_dss_signature(signature)
    return json_encode(
        {
            "protected": encoded_protected,
            "payload": encoded_payload,
            "signature": base64url_encode(
                r.to_bytes(32, "big") + s.to_bytes(32, "big")
            ),
        }
    )


def generate_alpn_certificate(hostname, challenge_token, key):
    """
    Generates an ALPN certificate for the given hostname and challenge token.

    The certificate is self signed and contains an acme identfiert
    derived from challange_token and key.

    Args:
        hostname: The hostname for which the certificate is being generated.
        challenge_token: The token provided by ACME server.
        key: the JWK key of the ACME account.

    Returns:
        The bytes of private_key_pem and certificate_pem.
    """
    logger.info("Generating ALPN certificate for %s", hostname)
    thumbprint = jwk_thumbprint(key)
    challenge = f"{challenge_token}.{thumbprint}".encode()
    digest = b"\x04\x20" + hashlib.sha256(challenge).digest()
    ext = x509.UnrecognizedExtension(ACME_IDENTIFIER, value=digest)

    now = datetime.datetime.now(datetime.timezone.utc)
    private_key = ec.generate_private_key(ec.SECP256R1())

    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(x509.Name([]))
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .public_key(private_key.public_key())
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]),
            critical=False,
        )
        .add_extension(ext, critical=True)
        .sign(private_key, hashes.SHA256())
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)
    return private_pem + certificate_pem


def generate_csr(
    common_name: str,
    country=None,
    state=None,
    locality=None,
    organization=None,
    organizational_unit=None,
    email=None,
    key_size=4096,
) -> tuple[bytes, bytes]:
    """
    Generates a Certificate Signing Request (CSR) and private key.

    Args:
        common_name: Common Name (CN) for the CSR (e.g., domain name or server name).
        country: Country Name (C).
        state: State or Province Name (ST).
        locality: Locality Name (L).
        organization: Organization Name (O).
        organizational_unit: Organizational Unit Name (OU).
        email: Email address.
        key_size: Size of the RSA key in bits.

    Returns:
        A tuple of (private_key_pem, csr_pem).
    """
    logger.info("Generating CSR for %s", common_name)
    # Generate private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    # Build subject
    subject = x509.Name(
        [
            x509.NameAttribute(oid, value)
            for oid, value in [
                (NameOID.COUNTRY_NAME, country),
                (NameOID.STATE_OR_PROVINCE_NAME, state),
                (NameOID.LOCALITY_NAME, locality),
                (NameOID.ORGANIZATION_NAME, organization),
                (NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit),
                (NameOID.COMMON_NAME, common_name),
                (NameOID.EMAIL_ADDRESS, email),
            ]
            if value is not None
        ]
    )

    # Generate CSR
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    csr_der = csr.public_bytes(serialization.Encoding.DER)

    return private_key_pem, csr_der


def generate_acme_key():
    """Generate a new JWK key pair for ACME account."""
    return ec.generate_private_key(ec.SECP256R1())


class AcmeClient:
    def __init__(self, acme_directory_url, private_key):
        """
        Initializes the ACME client.

        Args:
            acme_directory_url: The URL to the ACME directory (e.g., "https://acme-v02.api.letsencrypt.org/directory").
            private_key: The private key for the ACME account.
        """
        self.acme_directory_url = acme_directory_url
        self.private_key = private_key
        self.account_id = None
        self._acme_directory = None
        self._nonce = None

    @property
    def acme_directory(self):
        if self._acme_directory is None:
            self._acme_directory = self._fetch_acme_directory()
        return self._acme_directory

    @property
    def nonce(self):
        if self._nonce is None:
            self._nonce = self.fetch_nonce()
        return self._nonce

    def _fetch_acme_directory(self):
        """
        Fetches the ACME directory from the given URL.

        Args:
            directory_url: The URL to the ACME directory (e.g., "https://acme-v02.api.letsencrypt.org/directory").

        Returns:
            A dictionary containing the ACME directory.

        Raises:
            requests.exceptions.RequestException: If the request fails.
        """
        try:
            response = requests.get(self.acme_directory_url)
            response.raise_for_status()  # Raises an HTTPError for bad responses
            return response.json()
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to fetch ACME directory: {e}")

    def fetch_nonce(self) -> str:
        """Fetches a fresh nonce from the ACME server."""
        new_nonce_url = self.acme_directory["newNonce"]
        response = requests.head(new_nonce_url)
        if response.status_code != 200:
            response = requests.get(new_nonce_url)
        return response.headers["Replay-Nonce"]

    def _post_request(self, url, payload):
        signed_request = generate_signed_request(
            self.private_key, self.account_id, url, self.nonce, payload
        )

        # Send the request
        response = requests.post(
            url,
            data=signed_request,
            headers={"Content-Type": "application/jose+json"},
        )
        self._nonce = response.headers.get("Replay-Nonce")
        if response.status_code >= 400:
            raise Exception(
                f"ACME server error: {response.status_code} - {response.text}"
            )
        return response

    def post_request(self, url, payload=None):
        response = self._post_request(url, payload)
        return response.json()

    def create_account(
        self,
        contact: list = None,
        agree_tos: bool = False,
    ):
        """
        Creates a new ACME account by sending a signed JWS request to the newAccount URL.

        Args:
            contact: List of contact URLs (e.g., ["mailto:admin@example.com"]).
            agree_tos: Whether the user agrees to the ToS.

        Returns:
            The response from the ACME server (dict).
        """
        logger.info("Creating ACME account")
        new_account_url = self.acme_directory["newAccount"]
        payload = {
            "termsOfServiceAgreed": agree_tos,
        }
        if contact:
            payload["contact"] = contact
        self.account_id = None
        response = self._post_request(new_account_url, payload)
        self.account_id = response.headers["Location"]
        return response.json()

    def create_order(
        self,
        identifiers: list[dict],
    ) -> dict:
        """
        Creates a new ACME order for the given identifiers (domains).

        Args:
            identifiers: List of identifiers (e.g., [{"type": "dns", "value": "example.com"}]).

        Returns:
            The order response from the ACME server (dict).
        """
        logger.info("Creating ACME order")
        new_order_url = self.acme_directory["newOrder"]
        payload = {
            "identifiers": identifiers,
        }
        response = self._post_request(new_order_url, payload)
        return response.json(), response.headers["Location"]

    def wait_for_valid(self, url, pending_statuses=["pending"]):
        start_time = time.monotonic()
        while time.monotonic() - start_time < 600:
            response = self.post_request(url)
            if response["status"] not in pending_statuses:
                return response
            time.sleep(1)
        raise RuntimeError("timeout")


class AcmeContext:
    def __init__(
        self, certificate_path, acme_url, hostname, contact=None, agree_tos=False
    ):
        """
        Initializes the AcmeContext for managing automatic certificate renewal.

        Args:
            certificate_path: The directory path where certificates and keys will be stored.
            acme_url: The URL of the ACME directory.
            hostname: The domain name for which the certificate is managed.
            contact: A list of contact strings (e.g., email addresses) for the ACME account.
            agree_tos: A boolean indicating whether to agree to the ACME Terms of Service.

        """
        self.acme_url = acme_url
        self.hostname = hostname
        self.contact = contact
        self.agree_tos = agree_tos
        self.certificate_path = Path(certificate_path).expanduser()
        self.socket = None
        self.renewal_date = datetime.datetime.now(datetime.timezone.utc)
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.load_cert_chain()
        self.alpn_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.alpn_context._msg_callback = self.msg_callback
        self.acme_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.acme_context.set_alpn_protocols(["acme-tls/1"])

    @property
    def _certificate_path(self):
        return self.certificate_path / f"{self.hostname}.pem"

    @property
    def _account_key_path(self):
        return self.certificate_path / "account.key"

    @property
    def _alpn_path(self):
        return self.certificate_path / "alpn.pem"

    def load_cert_chain(self):
        certificate_path = self._certificate_path
        try:
            data = certificate_path.read_bytes()
        except FileNotFoundError:
            return
        cert = x509.load_pem_x509_certificate(data)
        duration = cert.not_valid_after_utc - cert.not_valid_before_utc
        self.renewal_date = cert.not_valid_before_utc + duration * (2 / 3)
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certificate_path)
        self.ssl_context = ssl_context
        if self.socket is not None:
            self.socket._context = self.ssl_context

    def load_acme_key(self):
        try:
            data = self._account_key_path.read_bytes()
            return serialization.load_pem_private_key(data, None)
        except FileNotFoundError:
            return generate_acme_key()

    def save_acme_key(self, acme_key):
        private_pem = acme_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self._account_key_path.write_bytes(private_pem)

    def wrap_socket(
        self,
        sock,
        server_side=False,
        do_handshake_on_connect=True,
        suppress_ragged_eofs=True,
        server_hostname=None,
        session=None,
    ):
        self.socket = self.ssl_context.wrap_socket(
            sock,
            server_side,
            do_handshake_on_connect,
            suppress_ragged_eofs,
            server_hostname,
            session,
        )
        threading.Thread(target=self.renewal_loop).start()
        return self.socket

    def msg_callback(self, conn, direction, version, content_type, msg_type, data):
        if direction == "read" and content_type == SSL3_RT_HANDSHAKE:
            if b"\x0aacme-tls/1\x00" in data:
                conn.context = self.acme_context
            else:
                conn.context = self.ssl_context

    def renewal_loop(self):
        while True:
            if datetime.datetime.now(datetime.timezone.utc) > self.renewal_date:
                self.renew_certificate()
            time.sleep(3600)

    def renew_certificate(self):
        self.certificate_path.mkdir(parents=True, exist_ok=True)
        acme_key = self.load_acme_key()
        acme_client = AcmeClient(self.acme_url, acme_key)
        account = acme_client.create_account(self.contact, self.agree_tos)
        if account["status"] != "valid":
            raise RuntimeError()
        self.save_acme_key(acme_key)

        order, order_url = acme_client.create_order(
            [{"type": "dns", "value": self.hostname}]
        )
        for auth_url in order["authorizations"]:
            auth = acme_client.post_request(auth_url)
            # skip if already valid
            if auth["status"] == "valid":
                logger.info("Already verified.")
                continue
            challenge = next(
                challenge
                for challenge in auth["challenges"]
                if challenge["type"] == "tls-alpn-01"
            )
            hostname = auth["identifier"]["value"]
            token = challenge["token"]
            url = challenge["url"]

            alpn_certificate = generate_alpn_certificate(hostname, token, acme_key)
            self._alpn_path.write_bytes(alpn_certificate)
            self.acme_context.load_cert_chain(self._alpn_path)
            self.socket._context = self.alpn_context
            _response = acme_client.post_request(url, {})
            response = acme_client.wait_for_valid(auth_url)
            if response["status"] != "valid":
                raise RuntimeError()
            self._alpn_path.unlink()

        private_key_pem, csr_der = generate_csr(self.hostname)
        csr = base64.urlsafe_b64encode(csr_der).strip(b"=")
        finalize = acme_client.post_request(order["finalize"], {"csr": csr.decode()})
        response = acme_client.wait_for_valid(
            order_url, pending_statuses=["pending", "processing"]
        )
        if response["status"] != "valid":
            raise RuntimeError()

        resp = requests.get(finalize["certificate"])
        resp.raise_for_status()
        self._certificate_path.write_bytes(private_key_pem + resp.content)
        self.load_cert_chain()
