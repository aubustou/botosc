import inspect
import re
import sys
from dataclasses import dataclass, make_dataclass, field, fields
from pathlib import Path
from typing import Any

import requests
import yaml
from osc_sdk import OSCCall

from botosc import mixin, model


YAML_URL = "https://raw.githubusercontent.com/outscale/osc-api/master/outscale.yaml"
TYPES = {
    "string": str,
    "array": list,
    "boolean": bool,
    "integer": int,
    "double": int,
    "float": float,
}
MIXINS: list[tuple[str, Any]] = []
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

    MIXINS = [
        x
        for y in [sys.modules[__name__], sys.modules.get("botosc.mixin")]
        for x in inspect.getmembers(y, inspect.isclass)
    ]


def create_dataclasses(api_content: dict) -> dict:
    entries = {}
    for name, obj in api_content["components"]["schemas"].items():
        print(name)
        attributes = []
        for k, v in obj["properties"].items():
            type_ = get_type(v)
            required = False
            if k in obj.get("required", []):
                required = True
            if k.lower() in {"with"}:
                k = k + "_"
            attributes.append((k, type_, field(metadata={"required": required})))

        bases = tuple(x[1] for x in MIXINS if x[0] == (name + "Mixin"))

        entries[name] = make_dataclass(
            name,
            attributes,
            bases=bases,
        )

    return entries


@dataclass
class Connector(OSCCall):
    pass


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
        if not(response_obj and [x for x in fields(response_obj) if x.name != "ResponseContext"]):
            response_obj = None

        calls.append((name.strip("/"), entries.get(args), response_obj))

    return calls


def generate_connector_code(calls: list, entries: dict, only_reply_as_dict:bool=False) -> list[str]:
    imports = ["from osc_sdk import OSCCall\n"]
    botosc_imports = set()
    import_any = False
    import_optional = False
    import_asdict = False
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
                if listed_type and listed_type.group(1) not in {"str", "int", "float", "bool"}:
                    print(" # " + listed_type.group(1))
                    botosc_imports.add(listed_type.group(1))
            else:
                str_type = type_.__name__
            if not field_.metadata["required"]:
                optional_args.append((field_.name, str_type, asdict_))
            else:
                required_args.append((field_.name, str_type, asdict_))

        code += [f"    def {camel_to_snake(call[0].strip('/'))}("]
        code += [", ".join(["self", *[f"{camel_to_snake(name)}: {type_}" for name, type_, _ in required_args]])]
        if optional_args:
            import_optional = True
            code += [", ", ", ".join([f"{camel_to_snake(name)}: Optional[{type_}] = None" for name, type_, _ in optional_args])]
        code += ["):\n"]

        if optional_args:
            code += ["        params = {}\n"]

        for name, type_, asdict_ in optional_args:
            code += [f"        if {camel_to_snake(name)} is not None:\n"]
            if asdict_:
                import_asdict = True
                code += [f'            params["{name}"] = asdict({camel_to_snake(name)})\n']
            else:
                code += [f'            params["{name}"] = {camel_to_snake(name)}\n']

        # Generate make_request line
        code += [f'        response = self.make_request("{call[0]}"']

        kwargs = []
        for name, _, asdict_ in required_args:
            if asdict_:
                arg = f"{name}=asdict({camel_to_snake(name)})"
                import_asdict = True
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

        if call[2] is None:
            code += ["        return\n", "\n"]
            continue

        code += ["        return "]

        import_apischema = True
        return_obj = next(x for x in fields(call[2]) if x.name != "ResponseContext")
        type_ = return_obj.type
        if type_ in {str, int, float, bool}:
            code += [f'response["{return_obj.name}"]\n', "\n"]
            continue

        listed_type = LISTED_TYPE_PATTERN.search(str(type_))
        if listed_type:
            # Meaning we have a list
            listed_type = listed_type.group(1)
            if listed_type not in {"str", "int", "float", "bool"}:
                print(" # " + listed_type)
                botosc_imports.add(listed_type)
                code += [f'[deserialize({listed_type}, x) for x in response["{return_obj.name}"]]\n']
            else:
                code += [f'response["{return_obj.name}"]\n']
        else:
            if type_ not in {"str", "int", "float", "bool"}:
                botosc_imports.add(type_)
            code += [f'deserialize({type_}, response["{return_obj.name}"])\n']

        code += ["\n"]

    # Manage imports
    imports += [f"from botosc.model import {x}\n" for x in botosc_imports]
    if import_any:
        imports += ["from typing import Any\n"]
    if import_optional:
        imports += ["from typing import Optional\n"]
    if import_asdict:
        imports += ["from dataclasses import asdict\n"]
    if import_apischema:
        imports += ["from apischema import deserialize\n"]

    return imports + ["\n", "\n"] + class_code + code


def generate_code(entries) -> list[str]:
    imports = ["from dataclasses import dataclass\n"]
    class_codes = []
    for name, entry in entries.items():
        if name.endswith("Response") or name.endswith("Request"):
            continue
        print(name)
        class_code = ["@dataclass\n"]
        inheritance = entry.__base__ if entry.__base__ != object else None
        if inheritance and inheritance.__module__ != "__main__":
            imports += [
                    f"from {inheritance.__module__} import {inheritance.__name__}\n"
                ]

        class_code += [
            f"class {name}"
            + (f"({inheritance.__name__})" if inheritance else "")
            + ":\n"
        ]
        for attr, type_ in entry.__annotations__.items():
            print(" - " + attr)
            if isinstance(type_, str):
                str_type = '"' + type_ + '"'
            elif type_ is None:
                str_type = "None"
            elif type_.__name__ == "list":
                str_type = str(type_)
            else:
                str_type = type_.__name__

            class_code += ["    " + camel_to_snake(attr) + ": " + str_type + "\n"]
        class_code += ["\n", "\n"]
        class_codes.extend(class_code)

    return imports + ["\n", "\n"] + class_codes


def write_modules(init_code: list[str], connector_code: list[str], model_code: list[str]):
    generated_modules = Path("botosc")
    generated_modules.mkdir(parents=True, exist_ok=True)

    init_file = generated_modules / "__init__.py"
    connector_file = generated_modules / "connector.py"
    model_file = generated_modules / "model.py"

    with init_file.open("w") as file_:
        file_.writelines(init_code)

    with connector_file.open("w") as file_:
        file_.writelines(connector_code)

    with model_file.open("w") as file_:
        file_.writelines(model_code)


def main():
    yaml_file = requests.get(YAML_URL).text
    content = yaml.load(yaml_file)

    entries = create_dataclasses(content)

    connector = create_connector(content, entries)
    connector_code = generate_connector_code(connector, entries)

    model_code = generate_code(entries)

    write_modules([""], connector_code, model_code)


if __name__ == "__main__":
    main()
