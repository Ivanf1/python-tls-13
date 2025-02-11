from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.backends import default_backend
from cryptography import x509

from src.messages.certificate_message import CertificateMessage
from src.messages.certificate_message_builder import CertificateMessageBuilder
from src.messages.certificate_request_message import CertificateRequestMessage
from src.messages.certificate_request_message_builder import CertificateRequestMessageBuilder
from src.messages.certificate_verify_message import CertificateVerifyMessage
from src.messages.certificate_verify_message_builder import CertificateVerifyMessageBuilder
from src.messages.client_hello_message import ClientHelloMessage
from src.messages.client_hello_message_builder import ClientHelloMessageBuilder
from src.messages.encrypted_extensions_message import EncryptedExtensionsMessage
from src.messages.encrypted_extensions_message_builder import EncryptedExtensionsMessageBuilder
from src.messages.handshake_finished_message import HandshakeFinishedMessage
from src.messages.handshake_finished_message_builder import HandshakeFinishedMessageBuilder
from src.messages.server_hello_message import ServerHelloMessage
from src.messages.server_hello_message_builder import ServerHelloMessageBuilder
from src.record_manager import RecordManager
from src.tls_crypto import get_X25519_private_key, get_X25519_public_key, get_early_secret, get_derived_secret, \
    get_shared_secret, get_handshake_secret, get_records_hash_sha256, get_client_secret_handshake, \
    get_client_handshake_key, get_client_handshake_iv, get_server_secret_handshake, get_server_handshake_key, \
    get_server_handshake_iv, compute_new_nonce, get_master_secret, get_client_secret_application, \
    get_server_secret_application, get_client_application_key, get_client_application_iv, get_server_application_key, \
    get_server_application_iv, validate_certificate_verify_signature, get_finished_secret, get_hmac_sha256
from src.tls_client_fsm import TlsClientFsm, TlsClientFsmEvent, TlsClientFsmState
from src.utils import TLSVersion, RecordHeaderType, HandshakeMessageType


class TlsClientSession:
    client_secret: bytes = b''

    client_handshake_key: bytes = b''
    client_handshake_iv: bytes = b''
    server_handshake_key: bytes = b''
    server_handshake_iv: bytes = b''

    client_application_key: bytes = b''
    client_application_iv: bytes = b''
    server_application_key: bytes = b''
    server_application_iv: bytes = b''

    client_hello: Optional[ClientHelloMessage] = None
    server_hello: Optional[ServerHelloMessage] = None
    encrypted_extensions: Optional[EncryptedExtensionsMessage] = None
    certificate_request: Optional[CertificateRequestMessage] = None
    server_certificate_message: Optional[CertificateMessage] = None
    server_certificate_verify_message: Optional[CertificateVerifyMessage] = None
    server_finished_message: Optional[HandshakeFinishedMessage] = None
    client_certificate_message: Optional[CertificateMessage] = None

    server_certificate = None

    def __init__(
            self,
            server_name: str,
            on_connected,
            trusted_root_certificate_path: str,
            on_data_to_send,
            on_application_data,
            certificate_path=None,
            certificate_private_key_path=None

    ):
        """
        Initializes a TLS 1.3 Client session.

        :param server_name: The name of the server that this session should connect to
        :param on_connected: Callback to call when the handshake is finished and a connection is established
        :param trusted_root_certificate_path: The root certificate to use to validate the server certificate
        :param on_data_to_send: Callback to call when the session requires data to be sent
        :param on_application_data: Callback to call when application data is received
        :param certificate_path: [Optional] The path of the certificate to use for this session for client authentication
        :param certificate_private_key_path: [Optional] The path of the private key of the certificate
        """
        self.should_end = False

        self.server_name = server_name
        self.on_connected = on_connected
        self.private_key = get_X25519_private_key()
        self.public_key = get_X25519_public_key(self.private_key)
        self.trusted_root_certificate_path = trusted_root_certificate_path
        self.on_data_to_send = on_data_to_send
        self.on_application_data = on_application_data
        self.certificate_path = certificate_path
        self.certificate_private_key_path = certificate_private_key_path

        self.handshake_messages_for_hash = []

        self.derived_secret: bytes = b''
        self.handshake_secret: bytes = b''

        self.handshake_messages_received = 0
        self.handshake_messages_sent = 0
        self.application_messages_received = 0
        self.application_messages_sent = 0

        self.tls_fsm = TlsClientFsm(
            on_session_begin_transaction_cb=self._on_session_begin_fsm_transaction,
            on_server_hello_received_cb=self._on_server_hello_received_fsm_transaction,
            on_encrypted_extensions_received_cb=self._on_encrypted_extensions_fsm_transaction,
            on_certificate_request_received_cb=self._on_certificate_request_fsm_transaction,
            on_certificate_received_cb=self._on_certificate_received_fsm_transaction,
            on_certificate_verify_received_cb=self._on_certificate_verify_received_fsm_transaction,
            on_finished_received_cb=self._on_finished_received_fsm_transaction
        )

    def start(self):
        """
        Starts the session.

        """
        self.client_hello = ClientHelloMessageBuilder(
            self.server_name,
            self.public_key
        ).build_client_hello_message()

        self.handshake_messages_for_hash.append(self.client_hello.to_bytes())

        self.tls_fsm.transition(TlsClientFsmEvent.SESSION_BEGIN)

        client_hello_record = RecordManager.build_unencrypted_record(
            tls_version=TLSVersion.V1_0,
            record_type=RecordHeaderType.HANDSHAKE,
            message=self.client_hello.to_bytes()
        )

        self.on_data_to_send(client_hello_record)

    def end(self):
        """
        Ends the session.

        """
        pass

    def on_record_received(self, record):
        """
        Call this function when a message needs to be processed by the session.

        :param record: The message
        """
        record_type = RecordManager.get_record_type(record)

        encrypted_handshake_states = [
            TlsClientFsmState.WAIT_ENCRYPTED_EXTENSIONS,
            TlsClientFsmState.WAIT_CERTIFICATE_OR_CERTIFICATE_REQUEST,
            TlsClientFsmState.WAIT_CERTIFICATE,
            TlsClientFsmState.WAIT_CERTIFICATE_VERIFY,
            TlsClientFsmState.WAIT_FINISHED,
        ]

        if record_type == RecordHeaderType.APPLICATION_DATA:
            # The record needs to be decrypted.
            # Based on the current state of the TLS FSM machine
            # we know which key to use to decrypt the record.
            if self.tls_fsm.get_current_state() in encrypted_handshake_states:
                # Every time a new encrypted message is received, we need to xor the iv (nonce)
                # with the number of messages received.
                # https://datatracker.ietf.org/doc/html/rfc8446#section-5.3

                nonce = compute_new_nonce(self.server_handshake_iv, self.handshake_messages_received)
                self.handshake_messages_received += 1

                # Use handshake key
                header = RecordManager.get_record_header(record)
                record = header + RecordManager.get_decrypted_record_payload(
                    record,
                    self.server_handshake_key,
                    nonce,
                )

                self._on_handshake_message_received(record)
            else:
                nonce = compute_new_nonce(self.server_application_iv, self.application_messages_received)
                self.application_messages_received += 1

                # Use application key
                record = RecordManager.get_decrypted_record_payload(
                    record,
                    self.server_application_key,
                    nonce,
                )

                self.on_application_data(record)
        else:
            self._on_handshake_message_received(record)

    def build_application_message(self, payload):
        """
        Builds an encrypted message.

        :param payload: The payload of the message
        :return: Encrypted message
        """
        nonce = compute_new_nonce(self.client_application_iv, self.application_messages_sent)
        self.application_messages_sent += 1

        return RecordManager.build_encrypted_record(
            TLSVersion.V1_2,
            RecordHeaderType.APPLICATION_DATA,
            RecordHeaderType.APPLICATION_DATA,
            payload,
            self.client_application_key,
            nonce
        )

    def _on_handshake_message_received(self, record):
        message_type = RecordManager.get_handshake_message_type(record)

        match message_type:
            case HandshakeMessageType.SERVER_HELLO:
                event = TlsClientFsmEvent.SERVER_HELLO_RECEIVED
            case HandshakeMessageType.ENCRYPTED_EXTENSIONS:
                event = TlsClientFsmEvent.ENCRYPTED_EXTENSIONS_RECEIVED
            case HandshakeMessageType.CERTIFICATE_REQUEST:
                event = TlsClientFsmEvent.CERTIFICATE_REQUEST_RECEIVED
            case HandshakeMessageType.CERTIFICATE:
                event = TlsClientFsmEvent.CERTIFICATE_RECEIVED
            case HandshakeMessageType.CERTIFICATE_VERIFY:
                event = TlsClientFsmEvent.CERTIFICATE_VERIFY_RECEIVED
            case HandshakeMessageType.FINISHED:
                event = TlsClientFsmEvent.FINISHED_RECEIVED
            case _:
                event = None

        self.tls_fsm.transition(event, record)

    def _on_session_begin_fsm_transaction(self, _):
        early_secret = get_early_secret()
        self.derived_secret = get_derived_secret(early_secret)
        return True

    def _on_server_hello_received_fsm_transaction(self, ctx):
        self.server_hello = ServerHelloMessageBuilder.build_from_bytes(ctx[5:])
        self.handshake_messages_for_hash.append(self.server_hello.to_bytes())

        self.server_public_key = X25519PublicKey.from_public_bytes(self.server_hello.get_public_key())

        shared_secret = get_shared_secret(self.private_key, self.server_public_key)
        self.handshake_secret = get_handshake_secret(shared_secret, self.derived_secret)

        hello_hash = get_records_hash_sha256(*self.handshake_messages_for_hash)

        client_secret = get_client_secret_handshake(self.handshake_secret, hello_hash)
        self.client_handshake_key = get_client_handshake_key(client_secret)
        self.client_handshake_iv = get_client_handshake_iv(client_secret)

        server_secret = get_server_secret_handshake(self.handshake_secret, hello_hash)
        self.server_handshake_key = get_server_handshake_key(server_secret)
        self.server_handshake_iv = get_server_handshake_iv(server_secret)
        return True

    def _on_encrypted_extensions_fsm_transaction(self, ctx):
        self.encrypted_extensions = EncryptedExtensionsMessageBuilder.build_from_bytes(ctx[5:])
        self.handshake_messages_for_hash.append(self.encrypted_extensions.to_bytes())
        return True

    def _on_certificate_request_fsm_transaction(self, ctx):
        self.certificate_request = CertificateRequestMessageBuilder.build_from_bytes(ctx[5:])
        self.handshake_messages_for_hash.append(self.certificate_request.to_bytes())
        return True

    def _on_certificate_received_fsm_transaction(self, ctx):
        self.server_certificate_message = CertificateMessageBuilder.build_from_bytes(ctx[5:])
        self.handshake_messages_for_hash.append(self.server_certificate_message.to_bytes())

        with open(self.trusted_root_certificate_path, "rb") as cert_file:
            trusted_root_certificate = x509.load_der_x509_certificate(cert_file.read(), default_backend())

        self.server_certificate = x509.load_der_x509_certificate(self.server_certificate_message.certificate, default_backend())

        try:
            self.server_certificate.verify_directly_issued_by(trusted_root_certificate)
            # TODO: validate the certificate validity period
            return True
        except:
            return False

    def _on_certificate_verify_received_fsm_transaction(self, ctx):
        self.server_certificate_verify_message = CertificateVerifyMessageBuilder.build_from_bytes(ctx[5:])

        public_key = self.server_certificate.public_key()

        handshake_hash = get_records_hash_sha256(*self.handshake_messages_for_hash)

        valid = validate_certificate_verify_signature(handshake_hash, public_key, self.server_certificate_verify_message.signature)
        self.handshake_messages_for_hash.append(self.server_certificate_verify_message.to_bytes())
        return valid

    def _on_finished_received_fsm_transaction(self, ctx):
        self.server_finished_message = HandshakeFinishedMessageBuilder.build_from_bytes(ctx[5:])
        self.handshake_messages_for_hash.append(self.server_finished_message.to_bytes())

        derived_secret = get_derived_secret(self.handshake_secret)
        master_secret = get_master_secret(derived_secret)

        if self.certificate_request is not None:
            # build and send client certificate
            certificate_record = self._build_certificate_message()
            self.on_data_to_send(certificate_record)
            self.handshake_messages_sent += 1

            # build and send client certificate verify
            certificate_verify_record = self._build_certificate_verify_message()
            self.on_data_to_send(certificate_verify_record)
            self.handshake_messages_sent += 1

        handshake_hash = get_records_hash_sha256(*self.handshake_messages_for_hash)

        self.client_secret = get_client_secret_application(master_secret, handshake_hash)
        server_secret = get_server_secret_application(master_secret, handshake_hash)

        self.client_application_key = get_client_application_key(self.client_secret)
        self.client_application_iv = get_client_application_iv(self.client_secret)
        self.server_application_key = get_server_application_key(server_secret)
        self.server_application_iv = get_server_application_iv(server_secret)

        client_finished_record = self._build_client_handshake_finished(handshake_hash)

        self.on_data_to_send(client_finished_record)

        self.on_connected()
        return True

    def _build_certificate_message(self):
        with open(self.certificate_path, "rb") as cert_file:
            certificate = x509.load_der_x509_certificate(cert_file.read(), default_backend())

        certificate_bytes = certificate.public_bytes(encoding=Encoding.DER)
        self.client_certificate_message = CertificateMessageBuilder(certificate_bytes).get_certificate_message()
        nonce = compute_new_nonce(self.client_handshake_iv, self.handshake_messages_sent)

        self.handshake_messages_for_hash.append(self.client_certificate_message.to_bytes())

        return RecordManager.build_encrypted_record(
            TLSVersion.V1_2,
            RecordHeaderType.APPLICATION_DATA,
            RecordHeaderType.HANDSHAKE,
            self.client_certificate_message.to_bytes(),
            self.client_handshake_key,
            nonce
        )

    def _build_certificate_verify_message(self):
        self.handshake_hash = get_records_hash_sha256(*self.handshake_messages_for_hash)

        self.certificate_verify = CertificateVerifyMessageBuilder(
            self.certificate_private_key_path).get_certificate_verify_message(self.handshake_hash)
        self.handshake_messages_for_hash.append(self.certificate_verify.to_bytes())

        nonce = compute_new_nonce(self.client_handshake_iv, self.handshake_messages_sent)

        return RecordManager.build_encrypted_record(
            TLSVersion.V1_2,
            RecordHeaderType.APPLICATION_DATA,
            RecordHeaderType.HANDSHAKE,
            self.certificate_verify.to_bytes(),
            self.client_handshake_key,
            nonce
        )

    def _build_client_handshake_finished(self, finished_hash):
        finished_key = get_finished_secret(self.client_secret)
        client_finished = HandshakeFinishedMessageBuilder().get_handshake_finished(finished_key, finished_hash)
        nonce = compute_new_nonce(self.client_handshake_iv, self.handshake_messages_sent)
        client_finished_record = RecordManager.build_encrypted_record(
            TLSVersion.V1_2,
            RecordHeaderType.APPLICATION_DATA,
            RecordHeaderType.HANDSHAKE,
            client_finished.to_bytes(),
            self.client_handshake_key,
            nonce
        )
        return client_finished_record
