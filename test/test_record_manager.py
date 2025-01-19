import unittest

from src.record_manager import RecordManager, RecordHeaderType
from src.utils import TLSVersion, HandshakeMessageType


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
        message_header = RecordManager.build_record_header(RecordHeaderType.HANDSHAKE, message, TLSVersion.V1_0)
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
        message_header = RecordManager.build_record_header(RecordHeaderType.HANDSHAKE, message, TLSVersion.V1_0)
        expected_message_header = bytes.fromhex("""16 03 01 00 c4""")
        self.assertEqual(message_header, expected_message_header)

    def test_should_return_encrypted_record(self):
        # server handshake key
        key = bytes.fromhex("""9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f""")
        # server handshake iv
        nonce = bytes.fromhex("""9563bc8b590f671f488d2da3""")
        # encrypted extensions
        data = bytes.fromhex("""08 00 00 02 00 00""")
        encrypted_record = RecordManager.build_encrypted_record(TLSVersion.V1_2, RecordHeaderType.APPLICATION_DATA, RecordHeaderType.HANDSHAKE, data, key, nonce)
        expected_encrypted_record = bytes.fromhex("""17 03 03 00 17 6b e0 2f 9d a7 c2 dc 9d de f5 6f 24 68 b9 0a df a2 51 01 ab 03 44 ae""")
        self.assertEqual(encrypted_record, expected_encrypted_record)

    def test_should_return_decrypted_record(self):
        key = bytes.fromhex("""3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e e4 03 bc""")
        nonce = bytes.fromhex("""5d 31 3e b2 67 12 76 ee 13 00 0b 30""")
        record = bytes.fromhex("""17 03 03 02 a2 d1 ff 33 4a 56 f5 bf
         f6 59 4a 07 cc 87 b5 80 23 3f 50 0f 45 e4 89 e7 f3 3a f3 5e df
         78 69 fc f4 0a a4 0a a2 b8 ea 73 f8 48 a7 ca 07 61 2e f9 f9 45
         cb 96 0b 40 68 90 51 23 ea 78 b1 11 b4 29 ba 91 91 cd 05 d2 a3
         89 28 0f 52 61 34 aa dc 7f c7 8c 4b 72 9d f8 28 b5 ec f7 b1 3b
         d9 ae fb 0e 57 f2 71 58 5b 8e a9 bb 35 5c 7c 79 02 07 16 cf b9
         b1 18 3e f3 ab 20 e3 7d 57 a6 b9 d7 47 76 09 ae e6 e1 22 a4 cf
         51 42 73 25 25 0c 7d 0e 50 92 89 44 4c 9b 3a 64 8f 1d 71 03 5d
         2e d6 5b 0e 3c dd 0c ba e8 bf 2d 0b 22 78 12 cb b3 60 98 72 55
         cc 74 41 10 c4 53 ba a4 fc d6 10 92 8d 80 98 10 e4 b7 ed 1a 8f
         d9 91 f0 6a a6 24 82 04 79 7e 36 a6 a7 3b 70 a2 55 9c 09 ea d6
         86 94 5b a2 46 ab 66 e5 ed d8 04 4b 4c 6d e3 fc f2 a8 94 41 ac
         66 27 2f d8 fb 33 0e f8 19 05 79 b3 68 45 96 c9 60 bd 59 6e ea
         52 0a 56 a8 d6 50 f5 63 aa d2 74 09 96 0d ca 63 d3 e6 88 61 1e
         a5 e2 2f 44 15 cf 95 38 d5 1a 20 0c 27 03 42 72 96 8a 26 4e d6
         54 0c 84 83 8d 89 f7 2c 24 46 1a ad 6d 26 f5 9e ca ba 9a cb bb
         31 7b 66 d9 02 f4 f2 92 a3 6a c1 b6 39 c6 37 ce 34 31 17 b6 59
         62 22 45 31 7b 49 ee da 0c 62 58 f1 00 d7 d9 61 ff b1 38 64 7e
         92 ea 33 0f ae ea 6d fa 31 c7 a8 4d c3 bd 7e 1b 7a 6c 71 78 af
         36 87 90 18 e3 f2 52 10 7f 24 3d 24 3d c7 33 9d 56 84 c8 b0 37
         8b f3 02 44 da 8c 87 c8 43 f5 e5 6e b4 c5 e8 28 0a 2b 48 05 2c
         f9 3b 16 49 9a 66 db 7c ca 71 e4 59 94 26 f7 d4 61 e6 6f 99 88
         2b d8 9f c5 08 00 be cc a6 2d 6c 74 11 6d bd 29 72 fd a1 fa 80
         f8 5d f8 81 ed be 5a 37 66 89 36 b3 35 58 3b 59 91 86 dc 5c 69
         18 a3 96 fa 48 a1 81 d6 b6 fa 4f 9d 62 d5 13 af bb 99 2f 2b 99
         2f 67 f8 af e6 7f 76 91 3f a3 88 cb 56 30 c8 ca 01 e0 c6 5d 11
         c6 6a 1e 2a c4 c8 59 77 b7 c7 a6 99 9b bf 10 dc 35 ae 69 f5 51
         56 14 63 6c 0b 9b 68 c1 9e d2 e3 1c 0b 3b 66 76 30 38 eb ba 42
         f3 b3 8e dc 03 99 f3 a9 f2 3f aa 63 97 8c 31 7f c9 fa 66 a7 3f
         60 f0 50 4d e9 3b 5b 84 5e 27 55 92 c1 23 35 ee 34 0b bc 4f dd
         d5 02 78 40 16 e4 b3 be 7e f0 4d da 49 f4 b4 40 a3 0c b5 d2 af
         93 98 28 fd 4a e3 79 4e 44 f9 4d f5 a6 31 ed e4 2c 17 19 bf da
         bf 02 53 fe 51 75 be 89 8e 75 0e dc 53 37 0d 2b""")
        decrypted_record = RecordManager.get_decrypted_record_payload(record, key, nonce)
        expected_decrypted_record = bytes.fromhex("""08 00 00 24 00 22 00 0a 00 14 00 12 00 1d
         00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 1c 00 02 40
         01 00 00 00 00 0b 00 01 b9 00 00 01 b5 00 01 b0 30 82 01 ac 30
         82 01 15 a0 03 02 01 02 02 01 02 30 0d 06 09 2a 86 48 86 f7 0d
         01 01 0b 05 00 30 0e 31 0c 30 0a 06 03 55 04 03 13 03 72 73 61
         30 1e 17 0d 31 36 30 37 33 30 30 31 32 33 35 39 5a 17 0d 32 36
         30 37 33 30 30 31 32 33 35 39 5a 30 0e 31 0c 30 0a 06 03 55 04
         03 13 03 72 73 61 30 81 9f 30 0d 06 09 2a 86 48 86 f7 0d 01 01
         01 05 00 03 81 8d 00 30 81 89 02 81 81 00 b4 bb 49 8f 82 79 30
         3d 98 08 36 39 9b 36 c6 98 8c 0c 68 de 55 e1 bd b8 26 d3 90 1a
         24 61 ea fd 2d e4 9a 91 d0 15 ab bc 9a 95 13 7a ce 6c 1a f1 9e
         aa 6a f9 8c 7c ed 43 12 09 98 e1 87 a8 0e e0 cc b0 52 4b 1b 01
         8c 3e 0b 63 26 4d 44 9a 6d 38 e2 2a 5f da 43 08 46 74 80 30 53
         0e f0 46 1c 8c a9 d9 ef bf ae 8e a6 d1 d0 3e 2b d1 93 ef f0 ab
         9a 80 02 c4 74 28 a6 d3 5a 8d 88 d7 9f 7f 1e 3f 02 03 01 00 01
         a3 1a 30 18 30 09 06 03 55 1d 13 04 02 30 00 30 0b 06 03 55 1d
         0f 04 04 03 02 05 a0 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05
         00 03 81 81 00 85 aa d2 a0 e5 b9 27 6b 90 8c 65 f7 3a 72 67 17
         06 18 a5 4c 5f 8a 7b 33 7d 2d f7 a5 94 36 54 17 f2 ea e8 f8 a5
         8c 8f 81 72 f9 31 9c f3 6b 7f d6 c5 5b 80 f2 1a 03 01 51 56 72
         60 96 fd 33 5e 5e 67 f2 db f1 02 70 2e 60 8c ca e6 be c1 fc 63
         a4 2a 99 be 5c 3e b7 10 7c 3c 54 e9 b9 eb 2b d5 20 3b 1c 3b 84
         e0 a8 b2 f7 59 40 9b a3 ea c9 d9 1d 40 2d cc 0c c8 f8 96 12 29
         ac 91 87 b4 2b 4d e1 00 00 0f 00 00 84 08 04 00 80 5a 74 7c 5d
         88 fa 9b d2 e5 5a b0 85 a6 10 15 b7 21 1f 82 4c d4 84 14 5a b3
         ff 52 f1 fd a8 47 7b 0b 7a bc 90 db 78 e2 d3 3a 5c 14 1a 07 86
         53 fa 6b ef 78 0c 5e a2 48 ee aa a7 85 c4 f3 94 ca b6 d3 0b be
         8d 48 59 ee 51 1f 60 29 57 b1 54 11 ac 02 76 71 45 9e 46 44 5c
         9e a5 8c 18 1e 81 8e 95 b8 c3 fb 0b f3 27 84 09 d3 be 15 2a 3d
         a5 04 3e 06 3d da 65 cd f5 ae a2 0d 53 df ac d4 2f 74 f3 14 00
         00 20 9b 9b 14 1d 90 63 37 fb d2 cb dc e7 1d f4 de da 4a b4 2c
         30 95 72 cb 7f ff ee 54 54 b7 8f 07 18 16""")
        self.assertEqual(decrypted_record, expected_decrypted_record)

    def test_should_return_decrypted_application_record_client(self):
        key = bytes.fromhex("de2f4c7672723a692319873e5c227606691a32d1c59d8b9f51dbb9352e9ca9cc")
        nonce = bytes.fromhex("""bb007956f474b25de902432f""")
        record = bytes.fromhex("""17 03 03 00 15 82 81 39 cb 7b 73 aa ab f5 b8 2f bf 9a 29 61 bc de 10 03 8a 32""")
        decrypted_record = RecordManager.get_decrypted_record_payload(record, key, nonce)
        expected_decrypted_record = bytes.fromhex("""70 69 6e 67 17""")
        self.assertEqual(decrypted_record, expected_decrypted_record)

    def test_should_return_decrypted_application_record_server(self):
        key = bytes.fromhex("01f78623f17e3edcc09e944027ba3218d57c8e0db93cd3ac419309274700ac27")
        nonce = bytes.fromhex("""196a750b0c5049c0cc51a541""")
        record = bytes.fromhex("""17 03 03 00 ea 38 2d 8c 19 a4 7f 4e 8d 9b 0c 51 0b c3 48 db 2c c9 9b 24 1c d0 d1 8b 
        31 d0 ca 1a c1 2d c1 e3 03 c5 8d 0c 7e 9e 27 29 4c 6b 0e 31 98 f7 d3 19 eb 14 62 2e c4 8b 6a c8 f8 66 d7 49 4f 
        a7 75 c8 80 ff 43 ad 4b 1a f5 3a 03 ca 19 77 95 77 8f ff 2f fe 1d 3b 99 b3 4d e7 82 a7 6a bf a8 40 e6 36 6c d7 
        34 9d 9b cf f6 41 f5 e0 df f9 5e 40 d7 2e 09 ef fe 18 ee 64 67 2c b9 60 05 40 44 88 ad 18 96 c4 4a 5f d1 74 99 
        8e 9b 00 94 d8 e6 d8 4d 29 29 b7 88 3d c9 a3 c3 c7 31 3a 87 29 3f 31 b6 1d 24 d9 90 97 c8 85 3b fb eb 95 d1 d0 
        1f 99 ca 05 b0 50 18 59 cf 63 40 e8 37 70 75 97 01 52 fa 94 f5 f5 be 29 06 e7 2a 15 e4 08 36 a4 1f 4c d3 db e7 
        d5 13 c1 6e 88 61 1d 3e ae 93 38 d9 db 1f 91 ca 3d 58 42 60 2a 61 0b 43 a4 63""")
        decrypted_record = RecordManager.get_decrypted_record_payload(record, key, nonce)
        expected_decrypted_record = bytes.fromhex("""04 00 00 d5 00 00 1c 20 00 00 00 00 08 00 00 00 00 00 00 00 00 00 
        c0 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 00 49 56 44 41 54 41 49 56 44 41 54 41 00 41 45 53 cb 11 9d 4d 
        bd 2a 21 ec c2 26 a6 09 0e e8 ca 58 df 09 03 9b 35 96 f4 de 79 98 0e a3 25 d5 14 62 5c 0c 21 c5 0f 03 26 1d c4 
        2c e7 c5 97 0c 4c 01 ea 33 1c ff c8 99 66 ef 54 8b e4 df 9a 8b a4 38 5b eb 86 80 fd 0b 78 df b8 e9 8e fc 8f cc 
        d8 14 fe cd 1d 9b ce 89 ca 05 dc 28 c2 49 e5 bd 61 d0 3a 56 8f 9a 0a 46 fb fd 05 30 2d b6 b2 f7 a3 13 e3 32 67 
        bf 0b cb dc ec fb 04 a4 d8 2f 5a 69 45 1f 56 7a b5 19 9b b2 6c 5c f2 00 72 f0 45 03 73 02 8f e0 71 d4 f4 1d 8f 
        61 ae 02 4d 69 bb ae 4c 00 00 16""")
        self.assertEqual(decrypted_record, expected_decrypted_record)

    def test_should_return_decrypted_application_record_server_nonce_xor(self):
        key = bytes.fromhex("01f78623f17e3edcc09e944027ba3218d57c8e0db93cd3ac419309274700ac27")
        nonce = bytes.fromhex("""196a750b0c5049c0cc51a540""")
        record = bytes.fromhex("""17 03 03 00 ea 38 ad fb 1d 01 fd 95 a6 03 85 e8 bb f1 fd 8d cb 46 70 98 97 e7 d6 74 
        c2 f7 37 0e c1 1d 8e 33 eb 4f 4f e7 f5 4b f4 dc 0b 92 fa e7 42 1c 33 c6 45 3c eb c0 73 15 96 10 a0 97 40 ab 2d 
        05 6f 8d 51 cf a2 62 00 7d 40 12 36 da fc 2f 72 92 ff 0c c8 86 a4 ef 38 9f 2c ed 12 26 c6 b4 dc f6 9d 99 4f f9 
        14 8e f9 69 bc 77 d9 43 3a b1 d3 a9 32 54 21 82 82 9f 88 9a d9 5f 04 c7 52 f9 4a ce 57 14 6a 5d 84 b0 42 bf b3 
        48 5a 64 e7 e9 57 b0 89 80 cd 08 ba f9 69 8b 89 29 98 6d 11 74 d4 aa 6d d7 a7 e8 c0 86 05 2c 3c 76 d8 19 34 bd 
        f5 9b 96 6e 39 20 31 f3 47 1a de bd dd db e8 4f cf 1f f4 08 84 6a e9 b2 8c a4 a9 e7 28 84 4a 49 3d 80 45 5d 6e 
        af f2 05 b4 0a 1e f1 85 74 ef c0 b9 6a d3 83 af bd 8d fc 86 f8 08 7c 1f 7d c8""")
        decrypted_record = RecordManager.get_decrypted_record_payload(record, key, nonce)
        expected_decrypted_record = bytes.fromhex("""04 00 00 d5 00 00 1c 20 00 00 00 00 08 00 00 00 00 00 00 00 01 00 
        c0 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 00 49 56 44 41 54 41 49 56 44 41 54 41 00 41 45 53 cb 11 9d 4d 
        bd 2a 21 ec c2 26 a6 09 0e e8 ca 58 df 09 03 9b 35 96 f4 de 79 98 0e a3 25 d5 14 62 5c 0c 21 c5 0f 03 26 1d c4 
        2c e7 c5 97 0c 4c 01 16 06 fb 99 8a 86 c3 fa 30 e5 5e ea 91 f1 ff f3 18 fc 7b d5 88 31 bf 49 c8 8d 7b 59 05 91 
        a6 5c 7d e8 cf c6 77 46 8a 54 fd be c0 d8 53 be 20 21 c8 bb fc db e5 1f 5d 9a 0c 70 85 84 1a 01 e4 95 85 f6 8b 
        4a fe e1 d7 07 e2 cb b1 a0 b4 23 aa 7e 32 d5 60 7b d9 9d d4 db 3c 9a aa ed 43 d3 5d 26 b4 b1 c6 84 71 71 ea a0 
        7a 9b c8 cb f7 58 49 9a 00 00 16""")
        self.assertEqual(decrypted_record, expected_decrypted_record)

    def test_should_return_unencrypted_record(self):
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
        unencrypted_record = RecordManager.build_unencrypted_record(TLSVersion.V1_0, RecordHeaderType.HANDSHAKE, message)
        expected_unencrypted_record = bytes.fromhex("""16 03 01 00 c4
         01 00 00 c0 03 03 cb 34 ec b1 e7 81 63
         ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83
         02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b
         00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00
         12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23
         00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2
         3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a
         af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03
         02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06
         02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01""")
        self.assertEqual(unencrypted_record, expected_unencrypted_record)

    def test_should_return_record_header(self):
        record = bytes.fromhex("""16 03 01 00 c4
         01 00 00 c0 03 03 cb 34 ec b1 e7 81 63
         ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83
         02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b
         00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00
         12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23
         00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2
         3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a
         af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03
         02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06
         02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01""")
        record_header = RecordManager.get_record_header(record)
        expected_record_header = bytes.fromhex("16 03 01 00 c4")
        self.assertEqual(record_header, expected_record_header)

    def test_should_return_record_type_handshake(self):
        record = bytes.fromhex("""16 03 01 00 c4
         01 00 00 c0 03 03 cb 34 ec b1 e7 81 63
         ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83
         02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b
         00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00
         12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23
         00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2
         3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a
         af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03
         02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06
         02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01""")
        record_type = RecordManager.get_disguised_record_type(record)
        self.assertEqual(record_type, RecordHeaderType.HANDSHAKE)

    def test_should_return_record_type_handshake_when_record_disguised(self):
        decrypted_record = bytes.fromhex("""17 03 03 00 2a 08 00 00 24 00 22 00 0a 00 14 00 12 00 1d
            00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 1c 00 02 40
            01 00 00 00 00 0b 00 01 b9 00 00 01 b5 00 01 b0 30 82 01 ac 30
            82 01 15 a0 03 02 01 02 02 01 02 30 0d 06 09 2a 86 48 86 f7 0d
            01 01 0b 05 00 30 0e 31 0c 30 0a 06 03 55 04 03 13 03 72 73 61
            30 1e 17 0d 31 36 30 37 33 30 30 31 32 33 35 39 5a 17 0d 32 36
            30 37 33 30 30 31 32 33 35 39 5a 30 0e 31 0c 30 0a 06 03 55 04
            03 13 03 72 73 61 30 81 9f 30 0d 06 09 2a 86 48 86 f7 0d 01 01
            01 05 00 03 81 8d 00 30 81 89 02 81 81 00 b4 bb 49 8f 82 79 30
            3d 98 08 36 39 9b 36 c6 98 8c 0c 68 de 55 e1 bd b8 26 d3 90 1a
            24 61 ea fd 2d e4 9a 91 d0 15 ab bc 9a 95 13 7a ce 6c 1a f1 9e
            aa 6a f9 8c 7c ed 43 12 09 98 e1 87 a8 0e e0 cc b0 52 4b 1b 01
            8c 3e 0b 63 26 4d 44 9a 6d 38 e2 2a 5f da 43 08 46 74 80 30 53
            0e f0 46 1c 8c a9 d9 ef bf ae 8e a6 d1 d0 3e 2b d1 93 ef f0 ab
            9a 80 02 c4 74 28 a6 d3 5a 8d 88 d7 9f 7f 1e 3f 02 03 01 00 01
            a3 1a 30 18 30 09 06 03 55 1d 13 04 02 30 00 30 0b 06 03 55 1d
            0f 04 04 03 02 05 a0 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05
            00 03 81 81 00 85 aa d2 a0 e5 b9 27 6b 90 8c 65 f7 3a 72 67 17
            06 18 a5 4c 5f 8a 7b 33 7d 2d f7 a5 94 36 54 17 f2 ea e8 f8 a5
            8c 8f 81 72 f9 31 9c f3 6b 7f d6 c5 5b 80 f2 1a 03 01 51 56 72
            60 96 fd 33 5e 5e 67 f2 db f1 02 70 2e 60 8c ca e6 be c1 fc 63
            a4 2a 99 be 5c 3e b7 10 7c 3c 54 e9 b9 eb 2b d5 20 3b 1c 3b 84
            e0 a8 b2 f7 59 40 9b a3 ea c9 d9 1d 40 2d cc 0c c8 f8 96 12 29
            ac 91 87 b4 2b 4d e1 00 00 0f 00 00 84 08 04 00 80 5a 74 7c 5d
            88 fa 9b d2 e5 5a b0 85 a6 10 15 b7 21 1f 82 4c d4 84 14 5a b3
            ff 52 f1 fd a8 47 7b 0b 7a bc 90 db 78 e2 d3 3a 5c 14 1a 07 86
            53 fa 6b ef 78 0c 5e a2 48 ee aa a7 85 c4 f3 94 ca b6 d3 0b be
            8d 48 59 ee 51 1f 60 29 57 b1 54 11 ac 02 76 71 45 9e 46 44 5c
            9e a5 8c 18 1e 81 8e 95 b8 c3 fb 0b f3 27 84 09 d3 be 15 2a 3d
            a5 04 3e 06 3d da 65 cd f5 ae a2 0d 53 df ac d4 2f 74 f3 14 00
            00 20 9b 9b 14 1d 90 63 37 fb d2 cb dc e7 1d f4 de da 4a b4 2c
            30 95 72 cb 7f ff ee 54 54 b7 8f 07 18 16""")
        record_type = RecordManager.get_disguised_record_type(decrypted_record)
        self.assertEqual(record_type, RecordHeaderType.HANDSHAKE)

    def test_should_return_record_type_when_application_not_disguised(self):
        decrypted_record = bytes.fromhex("""17 03 03 00 15 70 6f 6e 67 17""")
        record_type = RecordManager.get_disguised_record_type(decrypted_record)
        self.assertEqual(record_type, RecordHeaderType.APPLICATION_DATA)

    def test_should_return_handshake_message_type_client_hello(self):
        record = bytes.fromhex("""16 03 01 00 f8 01 00 00 f4 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 
        10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 
        f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 00 08 13 02 13 03 13 01 00 ff 01 00 00 a3 00 00 00 18 00 16 00 
        00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 00 0b 00 04 03 00 01 02 00 0a 00 16 00 14 
        00 1d 00 17 00 1e 00 19 00 18 01 00 01 01 01 02 01 03 01 04 00 23 00 00 00 16 00 00 00 17 00 00 00 0d 00 
        1e 00 1c 04 03 05 03 06 03 08 07 08 08 08 09 08 0a 08 0b 08 04 08 05 08 06 04 01 05 01 06 01 00 2b 00 03 
        02 03 04 00 2d 00 02 01 01 00 33 00 26 00 24 00 1d 00 20 35 80 72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 
        38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54""")
        message_type = RecordManager.get_handshake_message_type(record)
        self.assertEqual(message_type, HandshakeMessageType.CLIENT_HELLO)

    def test_should_return_handshake_message_type_server_hello(self):
        record = bytes.fromhex("""16 03 03 00 7a 02 00 00 76 03 03 70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 
        7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 20 e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef 
        f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 13 02 00 00 2e 00 2b 00 02 03 04 00 33 00 24 00 1d 00 
        20 9f d7 ad 6d cf f4 29 8d d3 f9 6d 5b 1b 2a f9 10 a0 53 5b 14 88 d7 f8 fa bb 34 9a 98 28 80 b6 15""")
        message_type = RecordManager.get_handshake_message_type(record)
        self.assertEqual(message_type, HandshakeMessageType.SERVER_HELLO)

    def test_should_return_record_type(self):
        record = bytes.fromhex("""16 03 03 00 7a 02 00 00 76 03 03 70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 
        7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 20 e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef 
        f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 13 02 00 00 2e 00 2b 00 02 03 04 00 33 00 24 00 1d 00 
        20 9f d7 ad 6d cf f4 29 8d d3 f9 6d 5b 1b 2a f9 10 a0 53 5b 14 88 d7 f8 fa bb 34 9a 98 28 80 b6 15""")
        record_type = RecordManager.get_record_type(record)
        self.assertEqual(record_type, RecordHeaderType.HANDSHAKE)

