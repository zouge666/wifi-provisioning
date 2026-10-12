import importlib.util
import json
from pathlib import Path

PROTOCOL = Path(__file__).parent.parent / "protocol"


def load_generator():
    spec = importlib.util.spec_from_file_location(
        "generate_vectors", PROTOCOL / "generate_vectors.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_vector_file_is_what_the_python_code_produces_today():
    # The TypeScript code is tested against this file. If the Python code changes and the
    # file does not, the two would drift apart, so this fails until the file is made again:
    #   uv run python protocol/generate_vectors.py
    generator = load_generator()
    assert json.loads((PROTOCOL / "vectors.json").read_text(encoding="utf-8")) == generator.build()


def test_the_vectors_are_the_same_every_time():
    generator = load_generator()
    assert generator.render() == generator.render()
