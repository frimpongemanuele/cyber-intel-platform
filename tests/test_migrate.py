"""Migration discovery and planning (pure: no database)."""

from pathlib import Path

import pytest

from cyberintel.store.migrate import Applied, MigrationError, discover, plan


def write(d: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        (d / name).write_text(body)
    return d


def two(d: Path) -> Path:
    return write(
        d,
        {
            "0001_initial.up.sql": "CREATE TABLE a (x int);",
            "0001_initial.down.sql": "DROP TABLE a;",
            "0002_more.up.sql": "CREATE TABLE b (x int);",
            "0002_more.down.sql": "DROP TABLE b;",
        },
    )


def test_repo_migrations_are_valid() -> None:
    migrations = discover()
    assert migrations[0].version == 1
    assert all(len(m.checksum) == 64 for m in migrations)


def test_plan_fresh_and_partial(tmp_path: Path) -> None:
    ms = discover(two(tmp_path))
    assert [m.version for m in plan(ms, [])] == [1, 2]
    applied = [Applied(1, "initial", ms[0].checksum)]
    assert [m.version for m in plan(ms, applied)] == [2]
    assert plan(ms, [*applied, Applied(2, "more", ms[1].checksum)]) == []


def test_modified_applied_migration_is_refused(tmp_path: Path) -> None:
    ms = discover(two(tmp_path))
    applied = [Applied(1, "initial", ms[0].checksum)]
    (tmp_path / "0001_initial.up.sql").write_text("CREATE TABLE a (x int); -- sneaky edit")
    with pytest.raises(MigrationError, match="modified after being applied"):
        plan(discover(tmp_path), applied)


def test_database_ahead_of_code_is_refused(tmp_path: Path) -> None:
    ms = discover(two(tmp_path))
    with pytest.raises(MigrationError, match="this code lacks"):
        plan(
            ms,
            [
                Applied(1, "initial", ms[0].checksum),
                Applied(2, "more", ms[1].checksum),
                Applied(3, "future", "0" * 64),
            ],
        )


def test_non_contiguous_applied_history_is_refused(tmp_path: Path) -> None:
    ms = discover(two(tmp_path))
    with pytest.raises(MigrationError, match="contiguous"):
        plan(ms, [Applied(2, "more", ms[1].checksum)])


@pytest.mark.parametrize(
    ("files", "match"),
    [
        (
            {
                "0001_a.up.sql": "",
                "0001_a.down.sql": "",
                "0003_c.up.sql": "",
                "0003_c.down.sql": "",
            },
            "no gaps",
        ),
        ({"0001_a.up.sql": ""}, "both"),
        ({"1_a.up.sql": ""}, "badly named"),
        ({"0001_Bad-Name.up.sql": ""}, "badly named"),
    ],
)
def test_discover_rejects_bad_layouts(tmp_path: Path, files: dict[str, str], match: str) -> None:
    with pytest.raises(MigrationError, match=match):
        discover(write(tmp_path, files))
