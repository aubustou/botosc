from __future__ import annotations

import time

from osc_sdk import OSCCall
from osc_sdk.sdk import OscApiException


def to_camelcase(name: str) -> str:
    return "".join(x.title() for x in name.split("_"))


class OSCCall_(OSCCall):
    def make_request(self, *args, **kwargs) -> dict:
        self.authentication_method = None

        throttled = True
        while throttled:
            try:
                super().make_request(*args, **kwargs)
            except OscApiException as e:
                if e.status_code == 503 and e.error_code == "6":
                    time.sleep(3)
                else:
                    raise
            else:
                throttled = False
        return self.response
