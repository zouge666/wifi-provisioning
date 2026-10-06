import re

import wifiprov


def test_package_is_importable_and_has_a_version():
    assert re.fullmatch(r"\d+\.\d+\.\d+", wifiprov.__version__)
