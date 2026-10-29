"""Validate a CBOM against the official CycloneDX 1.6 JSON schema (bundled under schemas/)."""

import json
from pathlib import Path

SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"


def validate(bom):
    import jsonschema
    from referencing import Registry, Resource

    main = json.loads((SCHEMA_DIR / "bom-1.6.schema.json").read_text())
    resources = []
    for name in ("spdx.schema.json", "jsf-0.82.schema.json"):
        doc = json.loads((SCHEMA_DIR / name).read_text())
        resources.append((name, Resource.from_contents(doc)))
        if "$id" in doc:
            resources.append((doc["$id"], Resource.from_contents(doc)))
    registry = Registry().with_resources(resources)
    validator = jsonschema.Draft7Validator(main, registry=registry)
    return sorted((f"{'/'.join(map(str, e.absolute_path))}: {e.message}" for e in validator.iter_errors(bom)))
