from dataclasses import dataclass


@dataclass
class VmMixin:
    toto: str

    @property
    def tutu(self):
        return self.toto

    def ssh(self):
        print("ssh")