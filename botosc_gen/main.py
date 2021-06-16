import inspect
from dataclasses import make_dataclass
from pathlib import Path
import re
from typing import Any
import yaml
import sys
import requests

from botosc import mixin

YAML_URL = "https://raw.githubusercontent.com/outscale/osc-api/master/outscale.yaml"
TYPES = {
    "string": str,
    "array": list,
    "boolean": bool,
    "integer": int,
    "double": int,
    "float": float,
}


def camel_to_snake(name:str)->str:
    name = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', name).lower()


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


def create_dataclasses(api_content: dict) -> dict:
    classes = [x for y in [sys.modules[__name__], sys.modules.get("botosc.mixin")] for x in
               inspect.getmembers(y, inspect.isclass)]

    entries = {}
    for name, obj in api_content["components"]["schemas"].items():
        if name.endswith("Response") or name.endswith("Request"):
            continue
        print(name)
        attributes = []
        for k, v in obj["properties"].items():
            attributes.append((camel_to_snake(k), get_type(v)))

        entries[name] = make_dataclass(name, attributes, bases=tuple(x[1] for x in classes if x[0] == (name + "Mixin")))

    return entries


def generate_code(entries) -> list[str]:
    imports = ["from dataclasses import dataclass\n"]
    class_codes = []
    for name, entry in entries.items():
        print(name)
        class_code = ["@dataclass\n"]
        inheritance = entry.__base__ if entry.__base__ != object else None
        if inheritance:
            if inheritance.__module__ != "__main__":
                imports += [f"from {inheritance.__module__} import {inheritance.__name__}\n"]

        class_code += [f"class {name}" + (f"({inheritance.__name__})" if inheritance else "") + ":\n"]
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

            class_code += ["    " + attr + ": " + str_type + "\n"]
        class_code += ["\n", "\n"]
        class_codes.extend(class_code)

    return imports + ["\n", "\n"] + class_codes


def write_modules(source_code: list[str]):
    generated_module = Path("botosc/__init__.py")
    generated_module.parent.mkdir(parents=True, exist_ok=True)

    with generated_module.open("w") as file_:
        file_.writelines(source_code)


def main():
    yaml_file = requests.get(YAML_URL).text
    content = yaml.load(yaml_file)

    entries = create_dataclasses(content)
    source_code = generate_code(entries)
    write_modules(source_code)





if __name__ == '__main__':
    main()

