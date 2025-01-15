import unittest

from src.messages.handshake_finished_message import HandshakeFinishedMessage


class TestHandshakeFinishedMessage(unittest.TestCase):
    def setUp(self):
        handshake_message_type = bytes.fromhex("14")
        bytes_of_handshake_data = bytes.fromhex("00 00 20")
        verify_data = bytes.fromhex("""9b 9b 14 1d 90 63 37 fb d2 cb dc e7 1d f4
                de da 4a b4 2c 30 95 72 cb 7f ff ee 54 54 b7 8f 07 18""")

        self.handshake_finished_message = HandshakeFinishedMessage(
            handshake_message_type,
            bytes_of_handshake_data,
            verify_data
        )

    def test_should_return_handshake_finished_message_bytes(self):
        handshake_finished_message = self.handshake_finished_message.to_bytes()
        expected_handshake_finished_message = bytes.fromhex("""14 00 00 20 9b 9b 14 1d 90 63 37 fb d2 cb dc e7 1d f4
                de da 4a b4 2c 30 95 72 cb 7f ff ee 54 54 b7 8f 07 18""")
        self.assertEqual(handshake_finished_message, expected_handshake_finished_message)