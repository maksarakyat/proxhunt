# Contributing

## Development setup

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

Run the CLI from the source tree:

```bash
python -m proxhunt --help
```

## Guidelines

- Keep the dependency surface small.
- Validation changes must be measurable against real public proxies; describe
  the change and the observed effect in the pull request.
- Never commit credentials, tokens, local paths, database files, or logs.
- Follow the existing style: type hints where practical, small functions,
  explicit error handling, and no fabricated success states.
- A proxy capability is not proven until it is reproduced: include the command
  and the observed result in the pull request description.

## Pull requests

1. Fork the repository and create a focused branch.
2. Run `python -m compileall proxhunt` before opening the pull request.
3. Describe the behavior change, the test method, and any trade-offs.
4. Keep unrelated formatting changes out of functional pull requests.
