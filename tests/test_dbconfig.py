from __future__ import annotations

from pathlib import Path

import pytest

from cyberintel.dbconfig import database_dsn, quote_conninfo_value


def test_precedence_and_password_file(tmp_path: Path) -> None:
    url = tmp_path / "url"
    url.write_text("host=db dbname=cit user=cit_web\n")
    pw = tmp_path / "pw"
    pw.write_text("s3cr3t\n")
    assert database_dsn({}) == ""
    assert database_dsn({"CIT_DATABASE_URL": "dbname=x"}) == "dbname=x"
    env = {"CIT_DATABASE_URL_FILE": str(url), "CIT_DATABASE_URL": "ignored"}
    assert database_dsn(env) == "host=db dbname=cit user=cit_web"
    env["CIT_DB_PASSWORD_FILE"] = str(pw)
    assert database_dsn(env) == "host=db dbname=cit user=cit_web password='s3cr3t'"
    assert database_dsn({"CIT_DB_PASSWORD_FILE": str(pw)}) == "password='s3cr3t'"


@pytest.mark.parametrize(
    ("raw", "quoted"),
    [
        ("a b", "'a b'"),
        ("it's", "'it\\'s'"),
        ("back\\slash", "'back\\\\slash'"),
        ("x' host=evil", "'x\\' host=evil'"),
    ],
)
def test_quoting_cannot_inject_keywords(raw: str, quoted: str) -> None:
    assert quote_conninfo_value(raw) == quoted


def test_rejects_empty_password_and_uri_mix(tmp_path: Path) -> None:
    empty = tmp_path / "pw"
    empty.write_text("\n")
    with pytest.raises(ValueError, match="empty"):
        database_dsn({"CIT_DB_PASSWORD_FILE": str(empty)})
    empty.write_text("pw")
    with pytest.raises(ValueError, match="URI"):
        database_dsn({"CIT_DATABASE_URL": "postgresql://h/db", "CIT_DB_PASSWORD_FILE": str(empty)})
