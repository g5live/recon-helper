# Contributing

Keep changes small and explain what was observed, what it means and what remains unknown. Port hints and service banners are clues, not proof of a vulnerability.

From the project folder, create a virtual environment, install the project and run the tests:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -v
```

Use mocked network calls in regression tests. For a live check, use a local fixture or an explicitly authorised lab. Do not include client data, credentials or live scan output in a commit. If behaviour or command options change, update the relevant example and note the change under **Unreleased** in [the changelog](CHANGELOG.md).
