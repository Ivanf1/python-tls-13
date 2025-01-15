from src.messages.application_message import ApplicationMessage


class ApplicationMessageBuilder:
    def __init__(self, data):
        self.data = data

    def get_application_message(self):
        return ApplicationMessage(self.data)