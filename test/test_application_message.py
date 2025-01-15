import unittest

from src.messages.application_message import ApplicationMessage


class TestApplicationMessage(unittest.TestCase):
    def setUp(self):
        data = bytes.fromhex("70 69 6e 67 17")

        self.application_message = ApplicationMessage(data)

    def test_should_return_application_message_bytes(self):
        application_message = self.application_message.to_bytes()
        expected_application_message = bytes.fromhex("70 69 6e 67 17")
        self.assertEqual(application_message, expected_application_message)
