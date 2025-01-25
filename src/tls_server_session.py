import binascii
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.backends import default_backend
from cryptography import x509

from src.messages.certificate_message import CertificateMessage
from src.messages.certificate_message_builder import CertificateMessageBuilder
from src.messages.certificate_verify_message_builder import CertificateVerifyMessageBuilder
from src.messages.client_hello_message import ClientHelloMessage
from src.messages.client_hello_message_builder import ClientHelloMessageBuilder
from src.messages.encrypted_extensions_message import EncryptedExtensionsMessage
from src.messages.encrypted_extensions_message_builder import EncryptedExtensionsMessageBuilder
from src.messages.server_hello_message import ServerHelloMessage
from src.messages.server_hello_message_builder import ServerHelloMessageBuilder
from src.record_manager import RecordManager
from src.tls_crypto import get_X25519_private_key, get_X25519_public_key, get_early_secret, get_derived_secret, \
    get_shared_secret, get_handshake_secret, get_records_hash_sha256, get_client_secret_handshake, \
    get_client_handshake_key, get_client_handshake_iv, get_server_secret_handshake, get_server_handshake_key, \
    get_server_handshake_iv, compute_new_nonce
from src.tls_server_fsm import TlsServerFsm, TlsServerFsmEvent
from src.utils import HandshakeMessageType, TLSVersion, RecordHeaderType


class TlsServerSession:
    def __init__(self, on_data_to_send, certificate_path, certificate_private_key_path, on_connected):
        self.private_key = get_X25519_private_key()
        self.public_key = get_X25519_public_key(self.private_key)
        self.on_data_to_send = on_data_to_send
        self.certificate_path = certificate_path
        self.certificate_private_key_path = certificate_private_key_path
        self.on_connected = on_connected

        self.derived_secret: bytes = b''
        self.client_handshake_key: bytes = b''
        self.client_handshake_iv: bytes = b''
        self.server_handshake_key: bytes = b''
        self.server_handshake_iv: bytes = b''

        self.client_hello: Optional[ClientHelloMessage] = None
        self.server_hello: Optional[ServerHelloMessage] = None
        self.encrypted_extensions: Optional[EncryptedExtensionsMessage] = None
        self.certificate_message: Optional[CertificateMessage] = None

        self.handshake_messages_sent = 0

        self.tls_fsm = TlsServerFsm(
            on_session_begin_transaction_cb=self._on_session_begin_fsm_transaction,
            on_client_hello_received_transaction_cb=self._on_client_hello_received_fsm_transaction,
            on_finished_received_cb=self._on_finished_received_fsm_transaction
        )

    def start(self):
        self.tls_fsm.transition(TlsServerFsmEvent.SESSION_BEGIN)

    def on_record_received(self, record):
        self._on_handshake_message_received(record)

    def _on_handshake_message_received(self, record):
        message_type = RecordManager.get_handshake_message_type(record)

        match message_type:
            case HandshakeMessageType.CLIENT_HELLO:
                event = TlsServerFsmEvent.CLIENT_HELLO_RECEIVED
            case _:
                event = None

        self.tls_fsm.transition(event, record)

    def _on_session_begin_fsm_transaction(self, _):
        early_secret = get_early_secret()
        self.derived_secret = get_derived_secret(early_secret)
        return True

    def _on_client_hello_received_fsm_transaction(self, ctx):
        self.client_hello = ClientHelloMessageBuilder.build_from_bytes(ctx[5:])
        self.server_hello = ServerHelloMessageBuilder(self.public_key).build_server_hello_message()

        self.on_data_to_send(self.server_hello.to_bytes())

        self.client_public_key = X25519PublicKey.from_public_bytes(self.client_hello.get_public_key())

        self._compute_handshake_keys()
        encrypted_extension_record = self._build_encrypted_extensions_message()
        self.on_data_to_send(encrypted_extension_record)
        self.handshake_messages_sent += 1

        certificate_record = self._build_certificate_message()
        self.on_data_to_send(certificate_record)
        self.handshake_messages_sent += 1

        self._build_certificate_verify_message()

        return True

    def _on_finished_received_fsm_transaction(self, ctx):
        return True

    def _compute_handshake_keys(self):
        shared_secret = get_shared_secret(self.private_key, self.client_public_key)
        self.handshake_secret = get_handshake_secret(shared_secret, self.derived_secret)

        hello_hash = get_records_hash_sha256(self.client_hello.to_bytes(), self.server_hello.to_bytes())

        client_secret = get_client_secret_handshake(self.handshake_secret, hello_hash)
        self.client_handshake_key = get_client_handshake_key(client_secret)
        self.client_handshake_iv = get_client_handshake_iv(client_secret)

        server_secret = get_server_secret_handshake(self.handshake_secret, hello_hash)
        self.server_handshake_key = get_server_handshake_key(server_secret)
        self.server_handshake_iv = get_server_handshake_iv(server_secret)

    def _build_encrypted_extensions_message(self):
        self.encrypted_extensions = EncryptedExtensionsMessageBuilder.get_encrypted_extensions_message()
        return RecordManager.build_encrypted_record(
            TLSVersion.V1_2,
            RecordHeaderType.APPLICATION_DATA,
            RecordHeaderType.HANDSHAKE,
            self.encrypted_extensions.to_bytes(),
            self.server_handshake_key,
            self.server_handshake_iv
        )

    def _build_certificate_message(self):
        with open(self.certificate_path, "rb") as cert_file:
            certificate = x509.load_der_x509_certificate(cert_file.read(), default_backend())

        certificate_bytes = certificate.public_bytes(encoding=Encoding.DER)
        self.certificate_message = CertificateMessageBuilder(certificate_bytes).get_certificate_message()
        nonce = compute_new_nonce(self.server_handshake_iv, self.handshake_messages_sent)

        return RecordManager.build_encrypted_record(
            TLSVersion.V1_2,
            RecordHeaderType.APPLICATION_DATA,
            RecordHeaderType.HANDSHAKE,
            self.certificate_message.to_bytes(),
            self.server_handshake_key,
            nonce
        )

    def _build_certificate_verify_message(self):
        handshake_hash = get_records_hash_sha256(
            self.client_hello.to_bytes(),
            self.server_hello.to_bytes(),
            self.encrypted_extensions.to_bytes(),
            self.certificate_message.to_bytes(),
        )

        self.certificate_verify = CertificateVerifyMessageBuilder(
            self.certificate_private_key_path).get_certificate_verify_message(handshake_hash)
        nonce = compute_new_nonce(self.server_handshake_iv, self.handshake_messages_sent)

        return RecordManager.build_encrypted_record(
            TLSVersion.V1_2,
            RecordHeaderType.APPLICATION_DATA,
            RecordHeaderType.HANDSHAKE,
            self.certificate_verify.to_bytes(),
            self.server_handshake_key,
            nonce
        )

