# Vulnex automatic virtual environment setup

## Start Vulnex

From the project directory, run:

```bash
python3 app.py
```

On the first launch, Vulnex automatically:

1. Creates a project-local `.venv` virtual environment if one does not exist.
2. Installs dependencies from `requirements.txt` inside `.venv` only.
3. Records a hash of `requirements.txt` so packages are checked/updated when that file changes.
4. Starts Streamlit using the virtual environment's Python interpreter.

On later launches, it reuses `.venv` and starts the app without reinstalling packages unless `requirements.txt` has changed.

## macOS / Homebrew Python

This avoids installing packages into Homebrew's externally managed Python and therefore avoids the `externally-managed-environment` / PEP 668 error. Do not use `--break-system-packages` for Vulnex.

## Notes

- The first run requires an internet connection to download Python packages.
- Nmap is a separate system dependency and must be installed independently (for example, `brew install nmap` on macOS).
- If the virtual environment becomes corrupted, stop Vulnex, remove the project `.venv` directory, and run `python3 app.py` again to recreate it.
