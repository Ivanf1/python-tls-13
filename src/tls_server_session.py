from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from src.messages.certificate_message_builder import CertificateMessageBuilder
from src.messages.certificate_verify_message_builder import CertificateVerifyMessageBuilder
from src.messages.client_hello_message import ClientHelloMessage
from src.messages.client_hello_message_builder import ClientHelloMessageBuilder
from src.messages.encrypted_extensions_message_builder import EncryptedExtensionsMessageBuilder
from src.messages.handshake_finished_message_builder import HandshakeFinishedMessageBuilder
from src.messages.server_hello_message import ServerHelloMessage
from src.messages.server_hello_message_builder import ServerHelloMessageBuilder
from src.record_manager import RecordManager
from src.tls_crypto import get_X25519_private_key, get_X25519_public_key, get_shared_secret, get_handshake_secret, \
    get_early_secret, get_derived_secret, get_records_hash_sha256, get_client_secret_handshake, \
    get_client_handshake_key, get_client_handshake_iv, get_server_secret_handshake, get_server_handshake_key, \
    get_server_handshake_iv, compute_new_nonce, get_finished_secret, get_master_secret, get_client_secret_application, \
    get_server_secret_application, get_client_application_key, get_client_application_iv, get_server_application_key, \
    get_server_application_iv
from src.tls_server_fsm import TlsServerFsm, TlsServerFsmEvent, TlsServerFsmState
from src.utils import HandshakeMessageType, TLSVersion, RecordHeaderType


class TlsServerSession:
    def __init__(self, on_data_to_send, certificate_path, certificate_private_key_path, on_connected):
        self.private_key = get_X25519_private_key()
        self.public_key = get_X25519_public_key(self.private_key)
        self.on_data_to_send = on_data_to_send
        self.certificate_path = certificate_path
        self.certificate_private_key_path = certificate_private_key_path
        self.on_connected = on_connected

        self.client_hello: ClientHelloMessage or None = None
        self.server_hello: ServerHelloMessage or None = None

        self.handshake_messages_sent = 0
        self.handshake_messages_received = 0
        self.application_messages_sent = 0
        self.application_messages_received = 0
        self.on_application_record_callbacks = []

        self.tls_fsm = TlsServerFsm(
            on_session_begin_transaction_cb=self._on_session_begin_fsm_transaction,
            on_client_hello_received_transaction_cb=self._on_client_hello_received_fsm_transaction,
            on_finished_received_cb=self._on_finished_received_fsm_transaction
        )

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
                header = RecordManager.get_record_header(record)
                record = header + RecordManager.get_decrypted_record_payload(
                    record,
                    self.client_application_key,
                    nonce,
                )

                for cb in self.on_application_record_callbacks:
                    cb(record)
        else:
            self._on_handshake_message_received(record)

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

    def register_on_application_record_callback(self, callback):
        self.on_application_record_callbacks.append(callback)

    def start(self):
        self.tls_fsm.transition(TlsServerFsmEvent.SESSION_BEGIN)

    def _on_session_begin_fsm_transaction(self, ctx):
        early_secret = get_early_secret()
        self.derived_secret = get_derived_secret(early_secret)
        return True

    def _on_client_hello_received_fsm_transaction(self, ctx):
        self.client_hello = ClientHelloMessageBuilder.build_from_bytes(ctx[5:])
        self.server_hello = self._build_server_hello()

        self.on_data_to_send(self.server_hello)
        self.client_public_key = X25519PublicKey.from_public_bytes(self.client_hello.get_public_key())

        shared_secret = get_shared_secret(self.private_key, self.client_public_key)
        self.handshake_secret = get_handshake_secret(shared_secret, self.derived_secret)

        hello_hash = get_records_hash_sha256(self.client_hello.to_bytes(), self.server_hello.to_bytes())

        client_secret = get_client_secret_handshake(self.handshake_secret, hello_hash)
        self.client_handshake_key = get_client_handshake_key(client_secret)
        self.client_handshake_iv = get_client_handshake_iv(client_secret)

        server_secret = get_server_secret_handshake(self.handshake_secret, hello_hash)
        self.server_handshake_key = get_server_handshake_key(server_secret)
        self.server_handshake_iv = get_server_handshake_iv(server_secret)

        self.encrypted_extensions = EncryptedExtensionsMessageBuilder.get_encrypted_extensions_message()
        encrypted_extensions_record = RecordManager.build_encrypted_record(
            TLSVersion.V1_2,
            RecordHeaderType.APPLICATION_DATA,
            RecordHeaderType.HANDSHAKE,
            self.encrypted_extensions.to_bytes(),
            self.server_handshake_key,
            self.server_handshake_iv
        )
        self.on_data_to_send(encrypted_extensions_record)
        self.handshake_messages_sent += 1

        with open(self.certificate_path, "rb") as cert_file:
            certificate = x509.load_der_x509_certificate(cert_file.read(), default_backend())

        certificate_bytes = certificate.public_bytes(encoding=Encoding.DER)
        self.certificate_message = CertificateMessageBuilder(certificate_bytes).get_certificate_message()
        nonce = compute_new_nonce(self.server_handshake_iv, self.handshake_messages_sent)
        certificate_record = RecordManager.build_encrypted_record(
            TLSVersion.V1_2,
            RecordHeaderType.APPLICATION_DATA,
            RecordHeaderType.HANDSHAKE,
            self.certificate_message.to_bytes(),
            self.server_handshake_key,
            nonce
        )
        self.on_data_to_send(certificate_record)
        self.handshake_messages_sent += 1

        handshake_hash = get_records_hash_sha256(
            self.client_hello.to_bytes(),
            self.server_hello.to_bytes(),
            self.encrypted_extensions.to_bytes(),
            self.certificate_message.to_bytes(),
        )

        self.certificate_verify = CertificateVerifyMessageBuilder(self.certificate_private_key_path).get_certificate_verify_message(handshake_hash)
        nonce = compute_new_nonce(self.server_handshake_iv, self.handshake_messages_sent)
        certificate_verify_record = RecordManager.build_encrypted_record(
            TLSVersion.V1_2,
            RecordHeaderType.APPLICATION_DATA,
            RecordHeaderType.HANDSHAKE,
            self.certificate_verify.to_bytes(),
            self.server_handshake_key,
            nonce
        )
        self.on_data_to_send(certificate_verify_record)
        self.handshake_messages_sent += 1

        derived_secret = get_derived_secret(self.handshake_secret)
        master_secret = get_master_secret(derived_secret)

        handshake_hash = get_records_hash_sha256(
            self.client_hello.to_bytes(),
            self.server_hello.to_bytes(),
            self.encrypted_extensions.to_bytes(),
            self.certificate_message.to_bytes(),
            self.certificate_verify.to_bytes(),
        )

        self.client_secret = get_client_secret_application(master_secret, handshake_hash)
        self.server_secret = get_server_secret_application(master_secret, handshake_hash)

        self.client_application_key = get_client_application_key(self.client_secret)
        self.client_application_iv = get_client_application_iv(self.client_secret)
        self.server_application_key = get_server_application_key(server_secret)
        self.server_application_iv = get_server_application_iv(server_secret)

        finished_key = get_finished_secret(self.client_secret)

        self.server_handshake_finished = HandshakeFinishedMessageBuilder().get_handshake_finished(finished_key, handshake_hash)
        nonce = compute_new_nonce(self.server_handshake_iv, self.handshake_messages_sent)
        server_finished_record = RecordManager.build_encrypted_record(
            TLSVersion.V1_2,
            RecordHeaderType.APPLICATION_DATA,
            RecordHeaderType.HANDSHAKE,
            self.server_handshake_finished.to_bytes(),
            finished_key,
            nonce
        )
        self.on_data_to_send(server_finished_record)
        self.handshake_messages_sent += 1

        return True

    def _on_finished_received_fsm_transaction(self, ctx):
        self.client_handshake_finished = HandshakeFinishedMessageBuilder.build_from_bytes(ctx[5:])
        self.on_connected()
        return True

    def _build_server_hello(self):
        return ServerHelloMessageBuilder(self.public_key).build_server_hello_message()