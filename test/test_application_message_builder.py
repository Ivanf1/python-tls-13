import unittest

from src.messages.application_message_builder import ApplicationMessageBuilder


class TestApplicationMessageBuilder(unittest.TestCase):
    def test_should_return_application_message(self):
        data = bytes.fromhex("70 69 6e 67 17")
        application_message = ApplicationMessageBuilder(data).get_application_message().to_bytes()
        expected_application_message = bytes.fromhex("70 69 6e 67 17")
        self.assertEqual(application_message, expected_application_message)
