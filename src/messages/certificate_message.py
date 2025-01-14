class CertificateMessage:
    def __init__(self, certificate):
        self.HANDSHAKE_MESSAGE_TYPE_CERTIFICATE = b'\x0b'
        self.REQUEST_CONTEXT = b'\x00'
        self.certificate = certificate

    def get_certificate_payload(self):
        """
        The certificate payload includes:\n
        - Request Context \n
        - Certificates Length \n
        - Certificate Length \n
        - Certificate \n
        - Certificate Extensions \n

        :return: certificate payload
        """

        certificate_len = len(self.certificate).to_bytes(3)
        certificate_extensions = b'\x00\x00'

        certificates_len = (len(certificate_len) + len(self.certificate) + len(certificate_extensions)).to_bytes(3)

        return self.REQUEST_CONTEXT + \
            certificates_len + \
            certificate_len + \
            self.certificate + \
            certificate_extensions

    def get_certificate_message(self):
        certificate_payload = self.get_certificate_payload()
        certificate_payload_len = len(certificate_payload).to_bytes(3)

        return self.HANDSHAKE_MESSAGE_TYPE_CERTIFICATE + \
            certificate_payload_len + \
            certificate_payload