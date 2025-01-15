import unittest

from src.messages.handshake_finished_message_builder import HandshakeFinishedMessageBuilder


class TestHandshakeFinished(unittest.TestCase):
    def test_should_return_verify_data(self):
        handshake_finished = HandshakeFinishedMessageBuilder()
        finished_key = bytes.fromhex("""00 8d 3b 66 f8 16 ea 55 9f 96 b5 37 e8 85
                    c3 1f c0 68 bf 49 2c 65 2f 01 f2 88 a1 d8 cd c1 9f c8""")
        finished_hash = bytes.fromhex("""edb7725fa7a3473b031ec8ef65a2485493900138a2b91291407d7951a06110ed""")
        verify_data =  handshake_finished.get_verify_data(finished_key, finished_hash)
        expected_verify_data = bytes.fromhex("""9b 9b 14 1d 90 63 37 fb d2 cb dc e7 1d f4
                de da 4a b4 2c 30 95 72 cb 7f ff ee 54 54 b7 8f 07 18""")
        self.assertEqual(verify_data, expected_verify_data)

    def test_should_return_handshake_finished(self):
        handshake_finished = HandshakeFinishedMessageBuilder()
        finished_key = bytes.fromhex("""00 8d 3b 66 f8 16 ea 55 9f 96 b5 37 e8 85
                    c3 1f c0 68 bf 49 2c 65 2f 01 f2 88 a1 d8 cd c1 9f c8""")
        finished_hash = bytes.fromhex("""edb7725fa7a3473b031ec8ef65a2485493900138a2b91291407d7951a06110ed""")
        finished = handshake_finished.get_handshake_finished(finished_key, finished_hash)
        expected_finished = bytes.fromhex("""14 00 00 20 9b 9b 14 1d 90 63 37 fb d2 cb dc e7 1d f4
                de da 4a b4 2c 30 95 72 cb 7f ff ee 54 54 b7 8f 07 18""")
        self.assertEqual(finished, expected_finished)

