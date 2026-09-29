---
name: cert
description: Assemble attached or named TLS certificate files into per-domain folders when the user invokes cert or /cert. Use the saved certificate output path, and request a path if none is set.
---

# Cert

Read and follow [the certificate assembly skill](../assemble-domain-certificates/SKILL.md), resolving the link and script path relative to this `SKILL.md`. Treat a user message beginning `/cert` as a request to process its attached or named certificate file(s). Check for a saved output path with the linked skill's `scripts/assemble.py --show-output`. If no output path was saved and the user did not give one in this request, ask for the destination and wait before writing. When a path is available, run the assembly script on the provided file(s) and report the result.
