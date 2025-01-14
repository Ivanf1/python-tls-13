class CertificateMessage:
    def __init__(self, certificate):
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

