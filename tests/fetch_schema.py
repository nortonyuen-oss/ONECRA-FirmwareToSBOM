#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fetch_schema - download the official CycloneDX JSON schemas for the test suite.

SchemaValidationTest checks every fixture SBOM against the published CycloneDX
1.6 schema, which is the only way to know that what fw2sbom emits will be
accepted by a downstream tool rather than merely look right to us.

The schemas are not vendored: they are a third-party artifact with their own
licence and their own release cadence, and a stale copy in our tree would be
worse than none. They are downloaded into tests/schema/ (git-ignored) by CI,
or by hand:

    python tests/fetch_schema.py

Without them the schema test skips, so the suite still runs offline - it just
proves less.

bom-1.6.schema.json references spdx.schema.json and jsf-0.82.schema.json by
bare filename, so those are needed for $ref resolution. spdx-2.3.schema.json is
the SPDX specification's own schema and validates fw2sbom's other output.
"""

import json
import os
import sys
import urllib.request

CYCLONEDX_BASE = ("https://raw.githubusercontent.com/CycloneDX/specification/"
                  "1.6/schema/")

# name -> URL. bom-1.6.schema.json references the next two by bare filename, so
# all three are needed for $ref resolution; spdx-2.3.schema.json is standalone
# and validates the other rendering of the same analysis.
SCHEMAS = {
    "bom-1.6.schema.json": CYCLONEDX_BASE + "bom-1.6.schema.json",
    "spdx.schema.json": CYCLONEDX_BASE + "spdx.schema.json",
    "jsf-0.82.schema.json": CYCLONEDX_BASE + "jsf-0.82.schema.json",
    # The 2.3 schema lives on the spec repo's support/v2.3 branch; the
    # development branch has moved on to 3.x and no longer carries it.
    "spdx-2.3.schema.json": ("https://raw.githubusercontent.com/spdx/spdx-spec/"
                             "support/v2.3/schemas/spdx-schema.json"),
}

TIMEOUT = 30


def fetch(name, out_dir):
    url = SCHEMAS[name]
    path = os.path.join(out_dir, name)
    with urllib.request.urlopen(url, timeout=TIMEOUT) as response:
        raw = response.read()
    # Parse before writing: a proxy error page saved under a .json name would
    # make the schema test fail in a thoroughly confusing way.
    try:
        json.loads(raw)
    except ValueError as e:
        raise SystemExit(f"{url} did not return JSON ({e})")
    with open(path, "wb") as f:
        f.write(raw)
    return path, len(raw)


def main(argv):
    out_dir = argv[1] if len(argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "schema")
    os.makedirs(out_dir, exist_ok=True)
    for name in sorted(SCHEMAS):
        path, size = fetch(name, out_dir)
        print(f"{name:<26} {size:>8} bytes -> {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
