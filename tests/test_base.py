import inspect
import logging
import os

import pytest

from botosc.connector import Connector


@pytest.fixture(scope="module")
def connection():
    yield Connector(
        access_key=os.getenv("ACCESS_KEY"),
        secret_key=os.getenv("SECRET_KEY"),
        endpoint=os.getenv("OAPI_ENDPOINT", ""),
        ssl_verify=True,
        authentication_method="accesskey",
    )


def get_methods(prefix: str) -> list[str]:
    members = inspect.getmembers(Connector)
    names = []
    for name, member in members:
        if callable(member) and name.startswith(prefix):
            names.append(name)
    return names


@pytest.mark.parametrize("call", get_methods("read_"))
def test_reads(connection: Connector, call: str):
    try:
        getattr(connection, call)()
    except TypeError as e:
        # Pass when a call requires arguments
        logging.warning(e)
        pytest.skip()


def test_read_vms(connection: Connector):
    vms = connection.read_vms()
    assert vms
    vm = vms[0]
    assert vm.connection is connection
    assert vm.tutu == "toto"
    image_details = vm.get_image_details()
    assert image_details or image_details is None
