---
name: Bug report
about: Report incorrect or unexpected server behavior
title: "[bug] "
labels: bug
---

## Summary

A clear description of what went wrong.

## Steps to reproduce

1. Start the server with: `shellx-drive --bind ... --data-dir ... --token-file /path/to/private-token-file` (do not attach the token file)
2. Call: `...` (the exact request — method, path, body; redact secrets)
3. Observe: `...`

## Expected behavior

What you expected to happen.

## Actual behavior

What actually happened. Include the HTTP status and response body, and any
relevant `/debug/*` output (with tokens/secrets redacted).

## Environment

- ShellX Drive version / commit:
- OS + architecture:
- Reverse proxy (if any):
- Started with `--e2e`? (yes/no)

## Additional context

Logs (redacted), configuration, or anything else that helps.
