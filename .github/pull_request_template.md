## What and why

Describe the change and the reason for it. Link any related issue.

## Type

- [ ] feat
- [ ] fix
- [ ] refactor
- [ ] test
- [ ] docs
- [ ] chore
- [ ] security

## Checklist

- [ ] `cargo fmt --check` is clean
- [ ] `cargo test` passes
- [ ] `./scripts/e2e_local.sh` passes (if server behavior changed)
- [ ] Added/updated tests that verify the change (via `/debug/*` where relevant)
- [ ] Updated `docs/public/API.md` / `docs/public/DEBUG_API.md` **and** `skill/shellx-drive/reference.md` for any endpoint change
- [ ] Examples use synthetic credentials and portable configuration
- [ ] Commits follow Conventional Commits; signing is welcome alongside review and verification

## Verification

State the exact commands you ran and their output (not just "tests pass").

## Notes for reviewers

Anything reviewers should focus on, or follow-ups intentionally left out of scope.
