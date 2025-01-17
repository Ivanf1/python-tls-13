from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from src.messages.certificate_message import CertificateMessage
from src.messages.certificate_message_builder import CertificateMessageBuilder
from src.messages.client_hello_message import ClientHelloMessage
from src.messages.client_hello_message_builder import ClientHelloMessageBuilder
from src.messages.server_hello_message import ServerHelloMessage
from src.messages.server_hello_message_builder import ServerHelloMessageBuilder
from src.record_manager import RecordManager
from src.tls_crypto import get_X25519_private_key, get_X25519_public_key, get_early_secret, get_derived_secret, \
    get_shared_secret, get_handshake_secret, get_records_hash_sha256, get_client_secret_handshake, \
    get_client_handshake_key
from src.tls_fsm import TlsFsm, TlsFsmEvent
from src.utils import TLSVersion, RecordHeaderType, HandshakeMessageType


class TlsSession:
    def __init__(self, server_name):
        self.server_name = server_name
        self.private_key = get_X25519_private_key()
        self.public_key = get_X25519_public_key(self.private_key)

        self.derived_secret = None

        self.client_hello: ClientHelloMessage or None = None
        self.server_hello: ServerHelloMessage or None = None
        self.certificate_message: CertificateMessage or None = None

        self.tls_fsm = TlsFsm(
            on_session_begin_transaction_cb=self._on_session_begin_fsm_transaction,
            on_server_hello_received_cb=self._on_server_hello_received_fsm_transaction,
            on_certificate_received_cb=self._on_certificate_received_fsm_transaction,
            on_certificate_verify_received_cb=self._on_certificate_verify_received_fsm_transaction,
            on_finished_received_cb=self._on_finished_received_fsm_transaction
        )

    def start(self) -> bytes:
        self.client_hello = ClientHelloMessageBuilder(
            self.server_name,
            self.public_key
        ).build_client_hello_message()

        self.tls_fsm.transition(TlsFsmEvent.SESSION_BEGIN)

        return RecordManager.build_unencrypted_record(
            tls_version=TLSVersion.V1_0,
            record_type=RecordHeaderType.HANDSHAKE,
            message=self.client_hello.to_bytes()
        )

    def on_record_received(self, record):
        message_type = RecordManager.get_handshake_message_type(record)

        match message_type:
            case HandshakeMessageType.SERVER_HELLO:
                event = TlsFsmEvent.SERVER_HELLO_RECEIVED
            case HandshakeMessageType.CERTIFICATE:
                event = TlsFsmEvent.CERTIFICATE_RECEIVED
            case _:
                event = None

        self.tls_fsm.transition(event, record)

    def _on_session_begin_fsm_transaction(self, _):
        early_secret = get_early_secret()
        self.derived_secret = get_derived_secret(early_secret)
        return True

    def _on_server_hello_received_fsm_transaction(self, ctx):
        self.server_hello = ServerHelloMessageBuilder.build_from_bytes(ctx[5:])
        self.server_public_key = X25519PublicKey.from_public_bytes(self.server_hello.get_public_key())

        shared_secret = get_shared_secret(self.private_key, self.server_public_key)
        handshake_secret = get_handshake_secret(shared_secret, self.derived_secret)

        hello_hash = get_records_hash_sha256(self.client_hello.to_bytes(), self.server_hello.to_bytes())

        client_secret = get_client_secret_handshake(handshake_secret, hello_hash)
        self.client_handshake_key = get_client_handshake_key(client_secret)

    def _on_certificate_received_fsm_transaction(self, ctx):
        # TODO: validate the certificate
        self.certificate_message = CertificateMessageBuilder.build_from_bytes(ctx)
        return True

    def _on_certificate_verify_received_fsm_transaction(self, ctx):
        pass

    def _on_finished_received_fsm_transaction(self, ctx):
        pass