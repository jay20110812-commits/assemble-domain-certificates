---
name: cert-path
description: Set or inspect the saved output directory for certificate assembly when the user invokes cert-path or asks for /cert_path. Use the path for future cert requests.
---

# Certificate output path

Treat `/cert_path <path>` or an equivalent request as setting the certificate output directory. If the path is missing, ask for it. Otherwise run the sibling `assemble-domain-certificates/scripts/assemble.py --set-output <path>`, resolving that path relative to this `SKILL.md`, then report the normalized saved path. Do not process certificate files merely because the user changed the path. If the user asks to see the current path, run `--show-output` instead.
