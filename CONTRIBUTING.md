# Contributing to VibeCrack

Thanks for contributing.

## Before You Open a PR

- Read [SECURITY.md](SECURITY.md)
- Use the tool only against targets you own or are authorized to test
- Do not include real credentials, tokens, customer data, or private scan results in issues or pull requests
- Keep changes focused and easy to review

## Local Setup

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e .
```

Optional extras:

```bash
pip install -e .[full]
```

## Development Guidelines

- Prefer small, reviewable pull requests
- Keep the CLI safe by default
- Preserve non-destructive behavior
- Add or update documentation when behavior changes
- If you change scanner behavior, explain the tradeoff in the PR

## Reporting Bugs

Use GitHub Issues for normal bugs and usability problems.

Do **not** open a public issue for a security vulnerability. Report those through [SECURITY.md](SECURITY.md).

## Pull Request Checklist

- I tested the change locally
- I did not include secrets or private data
- I updated docs if behavior changed
- I kept the change within the project's authorized, non-destructive scope
