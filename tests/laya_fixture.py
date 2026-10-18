"""Points shgrep's required Laya at the user's running llama-server (SHGREP_LAYA_PORT, default 8080)."""
import json
import os
import urllib.request

# Only stop words: BM25 gets no query terms, so regression findings keep their scan order.
REGRESSION_INTENT = "Show all of this."


def strip_selection(text):
    return "".join(line for line in text.splitlines(keepends=True) if not line.startswith("[laya selection "))


def laya_port():
    return int(os.environ.get("SHGREP_LAYA_PORT", "8080"))


def require_server(port=None):
    """Fails fast with a clear message when llama-server with the Laya GGUF is not running."""
    port = port or laya_port()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/props", timeout=10) as response:
            return json.load(response)
    except OSError as error:
        raise SystemExit(f"llama-server with the Laya GGUF is not answering on 127.0.0.1:{port}: {error}") from None


class RegressionLaya:
    """Grep regression runs: the real llama-server transport, a zero scoring budget and no pool or return limit,
    so every finding comes back in scan order and exact-output checks stay meaningful."""

    def __init__(self):
        require_server()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def environment(self):
        return {**os.environ, "SHGREP_LAYA_BUDGET_MS": "0", "SHGREP_LAYA_POOL": "0", "SHGREP_LAYA_RETURN": "0"}

    def close(self):
        pass
