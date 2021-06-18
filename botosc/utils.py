import re

from osc_sdk import OSCCall


def to_camelcase(name: str) -> str:
    return "".join(x.title() for x in name.split("_"))


class OSCCall_(OSCCall):
    def make_request(self, *args, **kwargs) -> dict:
        super().make_request(*args, **kwargs)
        return self.response
