import unittest

from src.record_manager import RecordManager, RecordHeaderType


class TestRecordManager(unittest.TestCase):
    # https://datatracker.ietf.org/doc/html/rfc8448#page-4
    # section: {client}  construct a ClientHello handshake message
    def test_should_return_message_header_for_handshake_message(self):
        message = bytes.fromhex("""01 00 00 c0 03 03 cb 34 ec b1 e7 81 63
         ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83
         02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b
         00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00
         12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23
         00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2
         3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a
         af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03
         02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06
         02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01""")
        message_header = RecordManager.get_message_header(RecordHeaderType.HANDSHAKE, message)
        expected_message_header = bytes.fromhex("""16 03 01 00 c4""")
        self.assertEqual(message_header, expected_message_header)

    # https://datatracker.ietf.org/doc/html/rfc8448#page-4
    # section: {client}  construct a ClientHello handshake message
    def test_should_return_message_header_for_application_data_message(self):
        message = bytes.fromhex("""01 00 00 c0 03 03 cb 34 ec b1 e7 81 63
         ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83
         02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b
         00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00
         12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23
         00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2
         3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a
         af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03
         02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06
         02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01""")
        message_header = RecordManager.get_message_header(RecordHeaderType.APPLICATION_DATA, message)
        expected_message_header = bytes.fromhex("""17 03 01 00 c4""")
        self.assertEqual(message_header, expected_message_header)
