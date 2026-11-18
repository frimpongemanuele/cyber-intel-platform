"""Import the agent-written archive into ``developments`` as cross-day stories.

    python -m cyberintel.store.archive_import /path/to/cyber-intel-archive

Uses the same story linker as the evaluation harness (``eval.archive.link_stories``), so
one development per story with dated sightings, and roll-ups linked rather than merged.
The archive is private: it is read at runtime and never committed to this repository.
"""

from __future__ import annotations

import argparse
import os
import re
from collections.abc import Sequence
from pathlib import Path

from cyberintel.eval.archive import Story, link_stories, load_archive

_SLUG_BAD = re.compile(r"[^a-z0-9-]+")


def story_slug(story: Story) -> str:
    """Stable, constraint-safe slug: the first member's archive id."""
    slug = _SLUG_BAD.sub("-", story.members[0].id.lower()).strip("-")[:160]
    return slug or "story"


def main(argv: Sequence[str] | None = None) -> int:
    import psycopg

    from cyberintel.store.repo import Store

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("archive", type=Path)
    args = ap.parse_args(argv)
    loaded = load_archive(args.archive)
    for problem in loaded.problems:
        print(f"WARNING: {problem}")
    stories = link_stories(loaded.developments)
    with psycopg.connect(os.environ.get("CIT_DATABASE_URL", ""), autocommit=True) as conn:
        n = Store(conn).import_archive_stories(stories)
    print(f"imported {n} stories from {len(loaded.developments)} archive developments")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
