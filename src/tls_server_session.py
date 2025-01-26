import binascii
from time import sleep
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.backends import default_backend
from cryptography import x509

from src.messages.certificate_message import CertificateMessage
from src.messages.certificate_message_builder import CertificateMessageBuilder
from src.messages.certificate_request_message import CertificateRequestMessage
from src.messages.certificate_request_message_builder import CertificateRequestMessageBuilder
from src.messages.certificate_verify_message_builder import CertificateVerifyMessageBuilder
from src.messages.client_hello_message import ClientHelloMessage
from src.messages.client_hello_message_builder import ClientHelloMessageBuilder
from src.messages.encrypted_extensions_message import EncryptedExtensionsMessage
from src.messages.encrypted_extensions_message_builder import EncryptedExtensionsMessageBuilder
from src.messages.handshake_finished_message_builder import HandshakeFinishedMessageBuilder
from src.messages.server_hello_message import ServerHelloMessage
from src.messages.server_hello_message_builder import ServerHelloMessageBuilder
from src.record_manager import RecordManager
from src.tls_crypto import get_X25519_private_key, get_X25519_public_key, get_early_secret, get_derived_secret, \
    get_shared_secret, get_handshake_secret, get_records_hash_sha256, get_client_secret_handshake, \
    get_client_handshake_key, get_client_handshake_iv, get_server_secret_handshake, get_server_handshake_key, \
    get_server_handshake_iv, compute_new_nonce, get_finished_secret, get_master_secret, get_client_secret_application, \
    get_server_secret_application, get_client_application_key, get_client_application_iv, get_server_application_key, \
    get_server_application_iv
from src.tls_server_fsm import TlsServerFsm, TlsServerFsmEvent, TlsServerFsmState
from src.utils import HandshakeMessageType, TLSVersion, RecordHeaderType


class TlsServerSession:
    derived_secret: bytes = b''
    client_handshake_key: bytes = b''
    client_handshake_iv: bytes = b''
    server_handshake_key: bytes = b''
    server_handshake_iv: bytes = b''

    client_application_key: bytes = b''
    client_application_iv: bytes = b''
    server_application_key: bytes = b''
    server_application_iv: bytes = b''

    def __init__(
            self,
            on_data_to_send,
            certificate_path,
            certificate_private_key_path,
            on_connected,
            on_application_data,
            client_authentication=False
    ):
        self.private_key = get_X25519_private_key()
        self.public_key = get_X25519_public_key(self.private_key)
        self.on_data_to_send = on_data_to_send
        self.certificate_path = certificate_path
        self.certificate_private_key_path = certificate_private_key_path
        self.on_connected = on_connected
        self.on_application_data = on_application_data
        self.client_authentication = client_authentication
        self.trusted_root_certificate_path = None

        self.client_hello: Optional[ClientHelloMessage] = None
        self.server_hello: Optional[ServerHelloMessage] = None
        self.encrypted_extensions: Optional[EncryptedExtensionsMessage] = None
        self.certificate_request: Optional[CertificateRequestMessage] = None
        self.certificate_message: Optional[CertificateMessage] = None

        self.handshake_messages_for_hash = []

        self.hello_hash: bytes = b''
        self.handshake_hash: bytes = b''

        self.handshake_messages_received = 0
        self.handshake_messages_sent = 0
        self.application_messages_received = 0
        self.application_messages_sent = 0

        self.tls_fsm = TlsServerFsm(
            on_session_begin_transaction_cb=self._on_session_begin_fsm_transaction,
            on_client_hello_received_transaction_cb=self._on_client_hello_received_fsm_transaction,
            on_client_certificate_received_transaction_cb=self._on_client_certificate_received_transaction_cb,
            on_client_certificate_verify_received_transaction_cb=self._on_client_certificate_verify_received_transaction_cb,
            on_finished_received_cb=self._on_finished_received_fsm_transaction
        )

    def start(self):
        self.tls_fsm.transition(TlsServerFsmEvent.SESSION_BEGIN)

    def on_record_received(self, record):
        record_type = RecordManager.get_record_type(record)

        encrypted_handshake_states = [
            TlsServerFsmState.WAIT_CLIENT_HELLO,
            TlsServerFsmState.WAIT_FINISHED,
        ]

        if record_type == RecordHeaderType.APPLICATION_DATA:
            # The record needs to be decrypted.
            # Based on the current state of the TLS FSM machine
            # we know which key to use to decrypt the record.
            if self.tls_fsm.get_current_state() in encrypted_handshake_states:
                # Every time a new encrypted message is received, we need to xor the iv (nonce)
                # with the number of messages received.
                # https://datatracker.ietf.org/doc/html/rfc8446#section-5.3

                nonce = compute_new_nonce(self.client_handshake_iv, self.handshake_messages_received)
                self.handshake_messages_received += 1

                # Use handshake key
                header = RecordManager.get_record_header(record)
                record = header + RecordManager.get_decrypted_record_payload(
                    record,
                    self.client_handshake_key,
                    nonce,
                )

                self._on_handshake_message_received(record)
            else:
                nonce = compute_new_nonce(self.client_application_iv, self.application_messages_received)
                self.application_messages_received += 1

                # Use application key
                record = RecordManager.get_decrypted_record_payload(
                    record,
                    self.client_application_key,
                    nonce,
                )

                self.on_application_data(record)
        else:
            self._on_handshake_message_received(record)

    def build_application_message(self, payload):
        nonce = compute_new_nonce(self.server_application_iv, self.application_messages_sent)
        self.application_messages_sent += 1

        return RecordManager.build_encrypted_record(
            TLSVersion.V1_2,
            RecordHeaderType.APPLICATION_DATA,
            RecordHeaderType.APPLICATION_DATA,
            payload,
            self.server_application_key,
            nonce
        )

    def _on_handshake_message_received(self, record):
        message_type = RecordManager.get_handshake_message_type(record)

        match message_type:
            case HandshakeMessageType.CLIENT_HELLO:
                event = TlsServerFsmEvent.CLIENT_HELLO_RECEIVED
            case HandshakeMessageType.FINISHED:
                event = TlsServerFsmEvent.FINISHED_RECEIVED
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
        self.handshake_messages_for_hash.append(self.client_hello.to_bytes())
        self.handshake_messages_for_hash.append(self.server_hello.to_bytes())

        server_hello_record = RecordManager.build_unencrypted_record(
            TLSVersion.V1_2,
            RecordHeaderType.HANDSHAKE,
            self.server_hello.to_bytes()
        )

        self.on_data_to_send(server_hello_record)

        self.client_public_key = X25519PublicKey.from_public_bytes(self.client_hello.get_public_key())

        self._compute_handshake_keys()
        encrypted_extension_record = self._build_encrypted_extensions_message()
        self.handshake_messages_for_hash.append(self.encrypted_extensions.to_bytes())
        self.on_data_to_send(encrypted_extension_record)
        self.handshake_messages_sent += 1

        if self.client_authentication:
            certificate_request_record = self._build_certificate_request_message()
            self.handshake_messages_for_hash.append(self.certificate_request.to_bytes())
            self.on_data_to_send(certificate_request_record)
            self.handshake_messages_sent += 1

        certificate_record = self._build_certificate_message()
        self.handshake_messages_for_hash.append(self.certificate_message.to_bytes())
        self.on_data_to_send(certificate_record)
        self.handshake_messages_sent += 1

        certificate_verify_record = self._build_certificate_verify_message()
        self.handshake_messages_for_hash.append(self.certificate_verify.to_bytes())
        self.on_data_to_send(certificate_verify_record)
        self.handshake_messages_sent += 1

        server_handshake_finished_record = self._build_handshake_finished_message()
        self.handshake_messages_for_hash.append(self.server_handshake_finished.to_bytes())
        self.on_data_to_send(server_handshake_finished_record)
        self.handshake_messages_sent += 1

        return True

    def _on_client_certificate_received_transaction_cb(self):
        return True

    def _on_client_certificate_verify_received_transaction_cb(self):
        return True

    def _on_finished_received_fsm_transaction(self, ctx):
        self.client_handshake_finished = HandshakeFinishedMessageBuilder.build_from_bytes(ctx[5:])

        self._compute_application_key()
        self.on_connected()
        return True

    def _compute_handshake_keys(self):
        shared_secret = get_shared_secret(self.private_key, self.client_public_key)
        self.handshake_secret = get_handshake_secret(shared_secret, self.derived_secret)

        self.hello_hash = get_records_hash_sha256(self.client_hello.to_bytes(), self.server_hello.to_bytes())

        self.client_secret_handshake = get_client_secret_handshake(self.handshake_secret, self.hello_hash)
        self.client_handshake_key = get_client_handshake_key(self.client_secret_handshake)
        self.client_handshake_iv = get_client_handshake_iv(self.client_secret_handshake)

        self.server_secret_handshake = get_server_secret_handshake(self.handshake_secret, self.hello_hash)
        self.server_handshake_key = get_server_handshake_key(self.server_secret_handshake)
        self.server_handshake_iv = get_server_handshake_iv(self.server_secret_handshake)

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

    def _build_certificate_request_message(self):
        self.certificate_request = CertificateRequestMessageBuilder().get_certificate_request_message()
        nonce = compute_new_nonce(self.server_handshake_iv, self.handshake_messages_sent)

        return RecordManager.build_encrypted_record(
            TLSVersion.V1_2,
            RecordHeaderType.APPLICATION_DATA,
            RecordHeaderType.HANDSHAKE,
            self.certificate_request.to_bytes(),
            self.server_handshake_key,
            nonce
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
        self.handshake_hash = get_records_hash_sha256(*self.handshake_messages_for_hash)

        self.certificate_verify = CertificateVerifyMessageBuilder(
            self.certificate_private_key_path).get_certificate_verify_message(self.handshake_hash)
        nonce = compute_new_nonce(self.server_handshake_iv, self.handshake_messages_sent)

        return RecordManager.build_encrypted_record(
            TLSVersion.V1_2,
            RecordHeaderType.APPLICATION_DATA,
            RecordHeaderType.HANDSHAKE,
            self.certificate_verify.to_bytes(),
            self.server_handshake_key,
            nonce
        )

    def _build_handshake_finished_message(self):
        finished_key = get_finished_secret(self.server_secret_handshake)

        self.server_handshake_finished = HandshakeFinishedMessageBuilder().get_handshake_finished(finished_key, self.handshake_hash)
        nonce = compute_new_nonce(self.server_handshake_iv, self.handshake_messages_sent)

        return RecordManager.build_encrypted_record(
            TLSVersion.V1_2,
            RecordHeaderType.APPLICATION_DATA,
            RecordHeaderType.HANDSHAKE,
            self.server_handshake_finished.to_bytes(),
            self.server_handshake_key,
            nonce
        )

    def _compute_application_key(self):
        derived_secret = get_derived_secret(self.handshake_secret)
        master_secret = get_master_secret(derived_secret)

        self.handshake_hash = get_records_hash_sha256(*self.handshake_messages_for_hash)

        client_secret = get_client_secret_application(master_secret, self.handshake_hash)
        server_secret = get_server_secret_application(master_secret, self.handshake_hash)

        self.client_application_key = get_client_application_key(client_secret)
        self.client_application_iv = get_client_application_iv(client_secret)
        self.server_application_key = get_server_application_key(server_secret)
        self.server_application_iv = get_server_application_iv(server_secret)
