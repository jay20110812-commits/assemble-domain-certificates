#!/usr/bin/env python3
"""Assemble matching TLS chains and private keys into DNS SAN folders."""

import argparse
import hashlib
import os
import re
import subprocess
import tempfile
import zipfile
from pathlib import Path

PEM = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----\s+.*?-----END \1-----", re.S)
DNS = re.compile(r"(?:\*\.)?[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\Z", re.I)
EXTENSIONS = {".pem", ".crt", ".cer", ".key", ".pfx", ".p12"}
MAX_FILE = 50 * 1024 * 1024
MAX_TOTAL = 250 * 1024 * 1024
CONFIG = Path(os.environ.get("CERT_OUTPUT_CONFIG", str(Path.home() / ".codex" / "cert-output-path")))


def run_openssl(arguments, data=None, env=None):
    result = subprocess.run(["openssl", *arguments], input=data, capture_output=True, env=env)
    if result.returncode:
        raise ValueError(result.stderr.decode(errors="replace").strip() or "OpenSSL failed")
    return result.stdout


def public_hash(pem, is_key, env):
    if is_key:
        public = run_openssl(["pkey", "-pubout", "-passin", "env:CERT_INPUT_PASSWORD"], pem, env)
    else:
        public = run_openssl(["x509", "-pubkey", "-noout"], pem)
    der = run_openssl(["pkey", "-pubin", "-outform", "DER"], public)
    return hashlib.sha256(der).hexdigest()


def load_inputs(paths):
    total = 0
    for path in paths:
        if not path.exists():
            raise ValueError(f"Input does not exist: {path}")
        if path.is_dir():
            entries = ((str(p), p.stat().st_size, lambda p=p: p.read_bytes()) for p in sorted(path.rglob("*")) if p.is_file() and p.suffix.lower() in EXTENSIONS)
        elif zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as archive:
                entries = [(f"{path}!{info.filename}", info.file_size, lambda info=info: archive.read(info)) for info in archive.infolist() if not info.is_dir() and Path(info.filename).suffix.lower() in EXTENSIONS]
                for name, size, read in entries:
                    if size > MAX_FILE or total + size > MAX_TOTAL:
                        raise ValueError(f"Input size limit exceeded: {name}")
                    total += size
                    yield name, read()
            continue
        else:
            entries = [(str(path), path.stat().st_size, path.read_bytes)]
        for name, size, read in entries:
            if size > MAX_FILE or total + size > MAX_TOTAL:
                raise ValueError(f"Input size limit exceeded: {name}")
            total += size
            yield name, read()


def materials(paths, password):
    env = os.environ.copy()
    env["CERT_INPUT_PASSWORD"] = password
    certs, keys, ignored = {}, {}, []
    for source, data in load_inputs(paths):
        if source.lower().endswith((".pfx", ".p12")):
            with tempfile.TemporaryDirectory() as temp:
                pfx = Path(temp) / "input.pfx"
                pfx.write_bytes(data)
                try:
                    data = run_openssl(["pkcs12", "-in", str(pfx), "-nodes", "-passin", "env:CERT_INPUT_PASSWORD"], env=env)
                except ValueError as exc:
                    raise ValueError(f"Cannot open PFX {source}: {exc}") from exc
        found = False
        for match in PEM.finditer(data):
            kind = match.group(1).decode()
            pem = match.group(0).strip() + b"\n"
            if kind == "CERTIFICATE":
                detail = run_openssl(["x509", "-noout", "-subject", "-issuer", "-nameopt", "RFC2253", "-ext", "subjectAltName"], pem).decode(errors="replace")
                subject = re.search(r"^subject=(.*)$", detail, re.M)
                issuer = re.search(r"^issuer=(.*)$", detail, re.M)
                if not subject or not issuer:
                    raise ValueError(f"Cannot read certificate identity: {source}")
                names = tuple(dict.fromkeys(n.lower().rstrip(".") for n in re.findall(r"DNS:([^,\s]+)", detail)))
                der = run_openssl(["x509", "-outform", "DER"], pem)
                fingerprint = hashlib.sha256(der).hexdigest()
                certs[fingerprint] = {"pem": pem, "source": source, "fingerprint": fingerprint, "subject": subject.group(1), "issuer": issuer.group(1), "names": names, "public": public_hash(pem, False, env)}
                found = True
            elif "PRIVATE KEY" in kind:
                try:
                    fingerprint = public_hash(pem, True, env)
                except ValueError as exc:
                    raise ValueError(f"Cannot read private key {source}: {exc}") from exc
                keys[fingerprint] = pem
                found = True
        if not found:
            ignored.append(source)
    return list(certs.values()), keys, ignored


def chain_for(leaf, certs):
    chain = [leaf]
    seen = {leaf["fingerprint"]}
    while chain[-1]["issuer"] != chain[-1]["subject"]:
        matches = [c for c in certs if c["subject"] == chain[-1]["issuer"] and c["fingerprint"] not in seen]
        if not matches:
            break
        if len(matches) != 1:
            raise ValueError(f"Ambiguous issuer chain for {leaf['source']}")
        chain.append(matches[0])
        seen.add(matches[0]["fingerprint"])
    return b"".join(c["pem"] for c in chain)


def plan_output(certs, keys):
    plan = {}
    for leaf in (c for c in certs if c["names"]):
        key = keys.get(leaf["public"])
        if key is None:
            raise ValueError(f"No matching private key for certificate {leaf['source']}")
        chain = chain_for(leaf, certs)
        for name in leaf["names"]:
            if not DNS.fullmatch(name) or ".." in name or "/" in name or "\\" in name:
                raise ValueError(f"Unsafe DNS SAN name: {name!r}")
            files = {"fullchain.crt": chain, f"{name}.key": key}
            if name in plan and plan[name] != files:
                raise ValueError(f"Multiple different certificates claim {name}")
            plan[name] = files
    if not plan:
        raise ValueError("No certificates with DNS SAN names found")
    return plan


def write_output(plan, destination, overwrite):
    if destination.is_symlink():
        raise ValueError("Output directory cannot be a symbolic link")
    destination.mkdir(parents=True, exist_ok=True)
    for name, files in plan.items():
        folder = destination / name
        if folder.is_symlink():
            raise ValueError(f"Output folder is a symbolic link: {folder}")
        for filename, content in files.items():
            target = folder / filename
            if target.is_symlink():
                raise ValueError(f"Output file is a symbolic link: {target}")
            if target.exists() and target.read_bytes() != content and not overwrite:
                raise ValueError(f"Existing output differs: {target}; use --overwrite only if intended")
    for name, files in sorted(plan.items()):
        folder = destination / name
        folder.mkdir(exist_ok=True)
        for filename, content in files.items():
            target = folder / filename
            if target.exists() and target.read_bytes() == content:
                continue
            fd, temporary = tempfile.mkstemp(prefix=".cert-", dir=folder)
            try:
                os.fchmod(fd, 0o600 if filename.endswith(".key") else 0o644)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(content)
                os.replace(temporary, target)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="*", type=Path)
    parser.add_argument("--output", type=Path, help="Output path for this run; overrides the saved path")
    parser.add_argument("--set-output", type=Path, help="Save the default output path for future runs")
    parser.add_argument("--show-output", action="store_true", help="Show the saved output path")
    parser.add_argument("--password-env", help="Environment variable containing a PFX or private-key password")
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    if args.set_output is not None:
        if args.inputs or args.output or args.show_output:
            parser.error("--set-output cannot be combined with inputs, --output, or --show-output")
        selected = args.set_output.expanduser().resolve()
        if selected.exists() and not selected.is_dir():
            parser.error(f"Output path is not a directory: {selected}")
        CONFIG.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".cert-path-", dir=CONFIG.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(str(selected) + "\n")
            os.replace(temporary, CONFIG)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        print(f"Saved certificate output path: {selected}")
        return
    if args.show_output:
        if args.inputs or args.output:
            parser.error("--show-output cannot be combined with inputs or --output")
        if not CONFIG.is_file():
            parser.exit(1, "No certificate output path has been saved.\n")
        print(CONFIG.read_text(encoding="utf-8").strip())
        return
    if not args.inputs:
        parser.error("provide one or more certificate inputs")
    if args.output is None:
        if not CONFIG.is_file() or not CONFIG.read_text(encoding="utf-8").strip():
            parser.exit(2, "No output path configured. Specify one with --set-output before processing.\n")
        args.output = Path(CONFIG.read_text(encoding="utf-8").strip())
    password = os.environ.get(args.password_env, "") if args.password_env else ""
    try:
        certs, keys, ignored = materials(args.inputs, password)
        plan = plan_output(certs, keys)
        write_output(plan, args.output, args.overwrite)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        parser.exit(1, f"Error: {exc}\n")
    print(f"Created or verified {len(plan)} DNS folders in {args.output}")
    if ignored:
        print("Ignored files without usable PEM material:")
        for item in ignored:
            print(f"  {item}")


if __name__ == "__main__":
    main()
