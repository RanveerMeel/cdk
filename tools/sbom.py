#!/usr/bin/env python3
"""Generate a CycloneDX 1.5 SBOM for a CDK release from every Cargo.lock in
the repository (kernel, user programs, link, gateway, UEFI loader, disk-image
tool). Offline: licenses are read from the crate sources cargo has already
downloaded. Deterministic for a given commit (timestamp = SOURCE_DATE_EPOCH).

Usage: tools/sbom.py VERSION OUTPUT.json
"""

import json
import os
import sys
import time
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCKFILES = {
    "Cargo.lock": "kernel (cdk)",
    "user/Cargo.lock": "agent programs (cdk-user)",
    "link/Cargo.lock": "link protocol (cdk-link)",
    "gateway/Cargo.lock": "host gateway and tools (cdk-gateway, cdk-approve, cdk-sign)",
    "boot/uefi-loader/Cargo.lock": "measuring UEFI loader (cdk-uefi-loader)",
    "tools/create_disk_image/Cargo.lock": "disk image builder (build-time)",
}
REGISTRY = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo")) / "registry" / "src"


def license_of(name, version):
    for idx in REGISTRY.glob("*"):
        manifest = idx / f"{name}-{version}" / "Cargo.toml"
        if manifest.exists():
            try:
                pkg = tomllib.loads(manifest.read_text()).get("package", {})
            except tomllib.TOMLDecodeError:
                return None
            return pkg.get("license")
    return None


def main():
    version, out = sys.argv[1], Path(sys.argv[2])
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", time.time()))
    components, deps, used_in = {}, {}, {}
    for lock, role in LOCKFILES.items():
        path = ROOT / lock
        if not path.exists():
            continue
        packages = tomllib.loads(path.read_text()).get("package", [])
        by_name = {}
        for p in packages:
            by_name.setdefault(p["name"], []).append(p["version"])
        for p in packages:
            ref = f"pkg:cargo/{p['name']}@{p['version']}"
            used_in.setdefault(ref, set()).add(role)
            if ref not in components:
                c = {
                    "type": "library",
                    "bom-ref": ref,
                    "name": p["name"],
                    "version": p["version"],
                    "purl": ref,
                }
                if "source" not in p:
                    c["type"] = "application"
                    c["description"] = "CDK first-party crate (in this repository)"
                    c["licenses"] = [{"license": {"id": "Apache-2.0"}}]
                    if p["name"] == "cdk-uefi-loader":
                        c["licenses"] = [{"expression": "MIT OR Apache-2.0"}]
                        c["description"] = "Fork of rust-osdev bootloader-x86_64-uefi 0.11.17 (see NOTICE)"
                else:
                    lic = license_of(p["name"], p["version"])
                    if lic:
                        # Old-style "MIT/Apache-2.0" means "MIT OR Apache-2.0".
                        c["licenses"] = [{"expression": " OR ".join(x.strip() for x in lic.split("/"))}]
                    else:
                        # Cargo never downloaded it: a platform-specific
                        # dependency in the lockfile that is not built for
                        # CDK's targets.
                        c["scope"] = "excluded"
                        c["properties"] = [{"name": "cdk:note", "value": "in Cargo.lock but not built for CDK's targets (not downloaded)"}]
                    if "checksum" in p:
                        c["hashes"] = [{"alg": "SHA-256", "content": p["checksum"]}]
                    if p["source"].startswith("git+"):
                        c["externalReferences"] = [{"type": "vcs", "url": p["source"]}]
                components[ref] = c
            # Resolve "name" or "name version" dependency entries.
            out_deps = deps.setdefault(ref, set())
            for d in p.get("dependencies", []):
                parts = d.split()
                name = parts[0]
                ver = parts[1] if len(parts) > 1 else (by_name.get(name) or [None])[0]
                if ver:
                    out_deps.add(f"pkg:cargo/{name}@{ver}")
    for ref, roles in used_in.items():
        components[ref].setdefault("properties", []).append(
            {"name": "cdk:used-in", "value": "; ".join(sorted(roles))}
        )
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:00000000-0000-4000-8000-{epoch:012x}"[:45],
        "version": 1,
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch)),
            "tools": [{"name": "cdk tools/sbom.py"}],
            "component": {
                "type": "operating-system",
                "bom-ref": f"pkg:github/RanveerMeel/cdk@v{version}",
                "name": "cdk",
                "version": version,
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            },
        },
        "components": sorted(components.values(), key=lambda c: c["bom-ref"]),
        "dependencies": [
            {"ref": r, "dependsOn": sorted(d & components.keys())} for r, d in sorted(deps.items())
        ],
    }
    out.write_text(json.dumps(bom, indent=2) + "\n")
    lic = {}
    for c in (c for c in components.values() if c.get("scope") != "excluded"):
        for l in c.get("licenses", [{"expression": "UNKNOWN"}]):
            key = l.get("expression") or l.get("license", {}).get("id", "UNKNOWN")
            lic[key] = lic.get(key, 0) + 1
    excluded = sum(1 for c in components.values() if c.get("scope") == "excluded")
    print(f"SBOM: {len(components)} components ({excluded} listed but not built) -> {out}")
    for k, n in sorted(lic.items(), key=lambda x: -x[1])[:12]:
        print(f"  {n:4}  {k}")


if __name__ == "__main__":
    main()
