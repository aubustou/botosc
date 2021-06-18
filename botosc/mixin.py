from dataclasses import dataclass, field


@dataclass
class ResponseParameter:
    _all_optional: bool = field(default=True, init=False)


@dataclass
class VmMixin:
    toto: str

    @property
    def tutu(self):
        return self.toto

    def ssh(self):
        print("ssh")
