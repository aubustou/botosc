import argparse
import importlib.util
import inspect
import re
import sys
from dataclasses import field, fields, make_dataclass
from pathlib import Path
from typing import Any, get_args

import requests
import yaml
from yaml import Loader

YAML_URL = "https://raw.githubusercontent.com/outscale/osc-api/master/outscale.yaml"
TYPES = {
    "string": str,
    "array": list,
    "boolean": bool,
    "integer": int,
    "double": int,
    "float": float,
}

BASE_TYPES = {"str", "int", "float", "bool"}
MIXINS: dict[str, type] = {}
LISTED_TYPE_PATTERN = re.compile(r"^list\[(?:\"|')?([a-zA-Z0-9]+)(?:\"|')?\]$")


def camel_to_snake(name: str) -> str:
    name = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub("([a-z0-9])([A-Z])", r"\1_\2", name).lower()


def get_type(property_: dict) -> Any:
    type_ = property_.get("type", "")
    reference = property_.get("$ref")
    if type_ == "number":
        return TYPES.get(property_["format"])
    elif reference:
        return reference.rsplit("/", 1)[-1]
    elif type_ == "array":
        return list[get_type(property_["items"])]
    else:
        return TYPES.get(property_["type"], Any)


def get_mixins():
    global MIXINS

    module_name = "botosc.mixin"
    spec = importlib.util.spec_from_file_location(
        module_name, Path(__file__).parent / ".." / "botosc" / "mixin.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)

    MIXINS = {
        name: member
        for y in [sys.modules[__name__], sys.modules.get(module_name)]
        for name, member in inspect.getmembers(y, inspect.isclass)
        if name.endswith("Mixin")
    }


def create_dataclasses(api_content: dict) -> dict:
    entries = {}
    for name, obj in api_content["components"]["schemas"].items():
        print(name)

        attributes = []
        required_properties = set(obj.get("required", []))

        for key, value in obj["properties"].items():
            type_ = get_type(value)
            required = False
            if key in required_properties:
                required = True
            if key.lower() in {"with"}:
                key = key + "_"
            attributes.append((key, type_, field(metadata={"required": required})))

        if mixin := MIXINS.get(name + "Mixin"):
            bases = (mixin,)
        else:
            bases = tuple()

        entries[name] = make_dataclass(
            name,
            attributes,
            bases=bases,
        )

    return entries


def create_connector(api_content: dict, entries: dict) -> list[tuple[str, str, str]]:
    calls = []
    for name, obj in api_content["paths"].items():
        args = obj["post"]["requestBody"]["content"]["application/json"]["schema"][
            "$ref"
        ].rsplit("/", 1)[-1]
        response = obj["post"]["responses"]["200"]["content"]["application/json"][
            "schema"
        ]["$ref"].rsplit("/", 1)[-1]
        response_obj = entries.get(response)
        if not (
            response_obj
            and [x for x in fields(response_obj) if x.name != "ResponseContext"]
        ):
            response_obj = None

        calls.append((name.strip("/"), entries.get(args), response_obj))

    return calls


def generate_connector_code(
    calls: list, entries: dict, only_reply_as_dict: bool = False
) -> list[str]:
    imports = ["from .utils import OSCCall_ as OSCCall\n"]
    botosc_imports = set()
    import_any = False
    import_optional = False
    import_serialize = False
    import_apischema = False

    class_code = ["class Connector(OSCCall):\n"]

    code = []
    for call in calls:
        print(call[0])
        required_args = []
        optional_args = []
        for field_ in fields(call[1]):
            type_ = field_.type
            asdict_ = False
            if isinstance(type_, str):
                # Dataclass actually
                str_type = '"' + type_ + '"'
                botosc_imports.add(type_)
                asdict_ = True
            elif type_ is None:
                str_type = "None"
            elif type_.__name__ == "list":
                str_type = str(type_)
                listed_type = LISTED_TYPE_PATTERN.search(str_type)
                if listed_type and listed_type.group(1) not in BASE_TYPES:
                    print(" # " + listed_type.group(1))
                    botosc_imports.add(listed_type.group(1))
            else:
                str_type = type_.__name__
            if not field_.metadata["required"]:
                optional_args.append((field_.name, str_type, asdict_))
            else:
                required_args.append((field_.name, str_type, asdict_))

        # Get return type for the method
        return_type = call[2]
        return_is_list = False

        if return_type is not None:
            return_obj = next(x for x in fields(call[2]) if x.name != "ResponseContext")
            return_type = return_obj.type
            if return_type not in {str, int, float, bool}:
                listed_type = LISTED_TYPE_PATTERN.search(str(return_type))
                if listed_type:
                    # Meaning we have a list
                    return_is_list = True
                    return_type = listed_type.group(1)
                    if return_type not in BASE_TYPES:
                        print(" # " + return_type)
                        botosc_imports.add(return_type)
                elif return_type not in BASE_TYPES:
                    botosc_imports.add(return_type)
            else:
                return_type = return_type.__name__

        # Generate prototype
        code += [f"    def {camel_to_snake(call[0].strip('/'))}("]
        code += [
            ", ".join(
                [
                    "self",
                    *[
                        f"{camel_to_snake(name)}: {type_}"
                        for name, type_, _ in required_args
                    ],
                ]
            )
        ]
        if optional_args:
            import_optional = True
            code += [
                ", ",
                ", ".join(
                    [
                        f"{camel_to_snake(name)}: Optional[{type_}] = None"
                        for name, type_, _ in optional_args
                    ]
                ),
            ]
        code += [") -> "]
        if return_is_list:
            code += [f"list[{return_type}]:\n"]
        else:
            code += [f"{return_type}:\n"]

        # Generate handling of optional arguments
        if optional_args:
            code += ["        params = {}\n"]

        for name, type_, asdict_ in optional_args:
            code += [f"        if {camel_to_snake(name)} is not None:\n"]
            if asdict_:
                import_serialize = True
                code += [
                    f'            params["{name}"] = serialize({camel_to_snake(name)})\n'
                ]
            else:
                code += [f'            params["{name}"] = {camel_to_snake(name)}\n']

        # Generate make_request line
        code += [f'        response = self.make_request("{call[0]}"']

        kwargs = []
        for name, _, asdict_ in required_args:
            if asdict_:
                import_serialize = True
                arg = f"{name}=serialize({camel_to_snake(name)})"
            else:
                arg = f"{name}={camel_to_snake(name)}"
            kwargs.append(arg)

        if kwargs:
            code += [", ".join(["", *kwargs])]
        if optional_args:
            code += [", **params"]
        code += [")\n"]

        # Prepare for deserialisation
        if only_reply_as_dict:
            code += ["        return response\n", "\n"]
            continue

        if return_type is None:
            code += ["        return\n", "\n"]
            continue

        import_apischema = True
        if return_is_list:
            code += [
                f"""
        items = [deserialize({return_type}, x) for x in response["{return_obj.name}"]]
"""
            ]
            if return_type not in BASE_TYPES:
                code += [
                    """
        for item in items:
            item._connection = self
"""
                ]
            code += [
                """
        return items
"""
            ]

        else:
            code += [
                f"""
        item = deserialize({return_type}, response["{return_obj.name}"])
"""
            ]
            if return_type not in BASE_TYPES:
                code += [
                    """
        item._connection = self
"""
                ]
            code += [
                """
        return item
"""
            ]

    # Manage imports
    imports += [f"from botosc.model import {x}\n" for x in botosc_imports]
    if import_any:
        imports += ["from typing import Any\n"]
    if import_optional:
        imports += ["from typing import Optional\n"]
    if import_serialize:
        imports += ["from apischema import serialize\n"]
    if import_apischema:
        imports += ["from apischema import deserialize\n"]

    return imports + ["\n", "\n"] + class_code + code


def generate_code(entries) -> list[str]:
    imports = [
        """from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from apischema.aliases import alias

from .base import BaseObject
from .utils import to_camelcase
"""
    ]
    class_codes = []

    for name, entry in entries.items():
        if name.endswith("Response") or name.endswith("Request"):
            continue
        print(name)

        mixin_field_names: set[str] = set()

        class_code = ["@alias(to_camelcase)\n@dataclass\n"]

        base_classes = ["BaseObject"]
        inheritance = entry.__base__ if entry.__base__ != object else None
        if inheritance and inheritance.__module__ != "__main__":
            mixin_name = inheritance.__name__
            imports += [f"from {inheritance.__module__} import {mixin_name}\n"]
            mixin_field_names = {x.name for x in fields(inheritance)}
            base_classes.append(mixin_name)

        class_code += [f"class {name}({', '.join(x for x in base_classes)}):\n"]

        attrs = []
        with_default_attrs = []
        for field in fields(entry):
            name = field.name

            if name in mixin_field_names:
                continue

            type_ = field.type
            print(" - " + name)
            if isinstance(type_, str):
                str_type = type_
            elif type_ is None:
                str_type = "None"
            elif type_.__name__ == "list":
                # apischema does not work without annotations
                contained_type = get_args(type_)[0]
                if isinstance(contained_type, str):
                    str_type = f"list[{contained_type}]"
                else:
                    str_type = str(type_)
            else:
                str_type = type_.__name__

            if not field.metadata.get("required"):
                with_default_attrs.append((name, str_type))
            else:
                attrs.append((name, str_type))

        for name, str_type in attrs:
            class_code += [f"    {camel_to_snake(name)}: {str_type}\n"]
        for name, str_type in with_default_attrs:
            class_code += [f"    {camel_to_snake(name)}: Optional[{str_type}] = None\n"]

        class_code += ["\n", "\n"]
        class_codes.extend(class_code)

    return imports + ["\n", "\n"] + class_codes


def generate_init_code(entries: dict) -> list[str]:
    code = [
        "from botosc.connector import Connector\n",
    ]

    return code


def generate_base() -> list[str]:
    code = [
        """from __future__ import annotations
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .connector import Connector


class BotoscError(Exception):
    pass


class BaseObject:
    _connection = None

    @property
    def connection(self) -> Connector:
        if self._connection is None:
            raise BotoscError("Connection has not been initialized")
        return self._connection
"""
    ]

    return code


def generate_utils_code() -> list[str]:
    code = [
        """from __future__ import annotations

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
        return self.response""",
    ]

    return code


def write_modules(
    init_code: list[str],
    connector_code: list[str],
    model_code: list[str],
    utils_code: list[str],
    base_code: list[str],
):
    generated_modules = Path("botosc")
    generated_modules.mkdir(parents=True, exist_ok=True)

    init_file = generated_modules / "__init__.py"
    connector_file = generated_modules / "connector.py"
    model_file = generated_modules / "model.py"
    utils_file = generated_modules / "utils.py"
    base_file = generated_modules / "base.py"

    with init_file.open("w") as file_:
        file_.writelines(init_code)

    with connector_file.open("w") as file_:
        file_.writelines(connector_code)

    with model_file.open("w") as file_:
        file_.writelines(model_code)

    with utils_file.open("w") as file_:
        file_.writelines(utils_code)

    with base_file.open("w") as file_:
        file_.writelines(base_code)


def main():
    parser = argparse.ArgumentParser(
        description="Generate botosc library from oAPI YAML description"
    )
    parser.add_argument(
        "--url", default=YAML_URL, type=str, help="URL to an oAPI YAML description"
    )
    parser.add_argument("--file", type=Path, help="path to an oAPI YAML description")

    args = parser.parse_args()

    if file_path := args.file:
        yaml_content = file_path.read_text()
    elif url := args.url:
        yaml_content = requests.get(url).text
    else:
        raise RuntimeError("No YAML content specified")

    content = yaml.load(yaml_content, Loader)

    get_mixins()

    entries = create_dataclasses(content)

    connector = create_connector(content, entries)
    connector_code = generate_connector_code(connector, entries)

    model_code = generate_code(entries)

    init_code = generate_init_code(entries)

    utils_code = generate_utils_code()

    base_code = generate_base()

    write_modules(init_code, connector_code, model_code, utils_code, base_code)


if __name__ == "__main__":
    main()
