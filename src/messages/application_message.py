from dataclasses import dataclass


@dataclass
class ApplicationMessage:
    data: bytes

    def to_bytes(self):
        return self.data