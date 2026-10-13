import re
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
DOCS = [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]
LINK = re.compile(r"\]\(([^)\s]+)\)|(?:src|href)=\"([^\"]+)\"")


def local_targets(path):
    for match in LINK.finditer(path.read_text(encoding="utf-8")):
        target = match.group(1) or match.group(2)
        if not target.startswith(("http://", "https://", "mailto:", "#")):
            yield target.split("#")[0]


@pytest.mark.parametrize("path", DOCS, ids=lambda path: path.name)
def test_every_link_and_image_in_the_docs_points_to_a_file_that_exists(path):
    for target in local_targets(path):
        if target:
            assert (path.parent / target).is_file(), f"{path.name}: missing linked file {target}"


def test_the_photos_in_the_evidence_folder_have_no_metadata():
    # Photos carry the place and the time inside the file. The repository is public.
    for photo in (ROOT / "evidence").glob("*.jpg"):
        data = photo.read_bytes()
        assert b"Exif" not in data, photo.name
        assert b"ns.adobe.com/xap" not in data, photo.name
