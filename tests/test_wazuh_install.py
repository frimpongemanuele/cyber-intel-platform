"""detections/wazuh/install.sh against a fake manager: idempotent, reversible, safe."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
from defusedxml import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "detections" / "wazuh" / "install.sh"
SNIPPET = ROOT / "detections" / "wazuh" / "ossec-cit.conf"
ORIGINAL = "<ossec_config>\n  <global><logall>no</logall></global>\n</ossec_config>\n"

SH = shutil.which("sh") or "/bin/sh"


def setup(tmp_path: Path, restart_ok: bool = True) -> tuple[Path, Path, dict[str, str]]:
    home = tmp_path / "ossec"
    (home / "etc").mkdir(parents=True)
    conf = home / "etc" / "ossec.conf"
    conf.write_text(ORIGINAL)
    systemctl = tmp_path / "systemctl"
    systemctl.write_text(
        f'#!/bin/sh\necho "$@" >> "$(dirname "$0")/calls"\nexit {0 if restart_ok else 1}\n'
    )
    systemctl.chmod(0o755)
    cit = tmp_path / "cit"
    cit.mkdir()
    (cit / "compose.yaml").write_text("services: {}\n")
    env = {**os.environ, "WAZUH_HOME": str(home), "SYSTEMCTL": str(systemctl),
           "CIT_RESTART_WAIT": "0"}  # fmt: skip
    return conf, cit, env


def run(
    env: dict[str, str], *args: str, cwd: Path | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [SH, str(SCRIPT), *args], env=env, capture_output=True, text=True, cwd=cwd
    )


def blocks(text: str) -> int:
    return text.count("<!-- BEGIN cyber-intel-platform")


def test_snippet_is_well_formed_xml_after_substitution() -> None:
    body = SNIPPET.read_text().replace("@CIT_DIR@", "/srv/cit")
    root = ET.fromstring(body[body.index("<ossec_config>") :])
    locations = [e.text for e in root.iter("location")]
    assert "/srv/cit/logs/*/security.json" in locations
    secrets = [d for d in root.iter("directories") if d.text == "/srv/cit/deploy/secrets"]
    assert secrets and secrets[0].get("report_changes") == "no"  # never store secret diffs
    assert "@CIT_DIR@" not in body


def test_install_is_idempotent_and_keeps_the_original(tmp_path: Path) -> None:
    conf, cit, env = setup(tmp_path)
    for _ in range(2):
        r = run(env, str(cit))
        assert r.returncode == 0, r.stderr
    text = conf.read_text()
    assert text.startswith(ORIGINAL) and blocks(text) == 1
    assert f"<location>{cit}/logs/*/security.json</location>" in text
    assert len(list(conf.parent.glob("ossec.conf.cit-backup.*"))) >= 1


def test_uninstall_restores_the_original(tmp_path: Path) -> None:
    conf, cit, env = setup(tmp_path)
    run(env, str(cit))
    rules = conf.parent / "rules" / "cit_rules.xml"
    assert rules.read_text() == (SCRIPT.parent / "rules" / "cit_rules.xml").read_text()
    r = run(env, "--uninstall")
    assert r.returncode == 0, r.stderr
    assert conf.read_text() == ORIGINAL and not rules.exists()


def test_failed_restart_rolls_back(tmp_path: Path) -> None:
    conf, cit, env = setup(tmp_path, restart_ok=False)
    rules = conf.parent / "rules" / "cit_rules.xml"
    r = run(env, str(cit))
    assert r.returncode == 1 and "restoring" in r.stderr
    assert conf.read_text() == ORIGINAL and not rules.exists()


def test_rollback_restores_previous_rules(tmp_path: Path) -> None:
    conf, cit, env = setup(tmp_path, restart_ok=False)
    rules = conf.parent / "rules" / "cit_rules.xml"
    rules.parent.mkdir()
    rules.write_text("<!-- previous version -->\n")
    assert run(env, str(cit)).returncode == 1
    assert rules.read_text() == "<!-- previous version -->\n"


@pytest.mark.parametrize("bad", ["relative/path", "/nonexistent-cit-dir"])
def test_refuses_bad_platform_dir(tmp_path: Path, bad: str) -> None:
    conf, _, env = setup(tmp_path)
    r = run(env, bad)
    assert r.returncode == 1 and conf.read_text() == ORIGINAL


def test_relative_dir_refused_even_if_it_exists(tmp_path: Path) -> None:
    # Wazuh needs absolute paths in ossec.conf; a relative one would silently match nothing
    conf, _, env = setup(tmp_path)
    r = run(env, "cit", cwd=tmp_path)  # tmp_path/cit/compose.yaml exists
    assert r.returncode == 1 and "absolute" in r.stderr
    assert conf.read_text() == ORIGINAL


def test_failed_config_check_rolls_back_without_restart(tmp_path: Path) -> None:
    conf, cit, env = setup(tmp_path)
    bindir = Path(env["WAZUH_HOME"]) / "bin"
    bindir.mkdir()
    checker = bindir / "wazuh-syscheckd"
    checker.write_text(
        "#!/bin/sh\necho 'wazuh-syscheckd: ERROR: (1235): Invalid value for element'\nexit 1\n"
    )
    checker.chmod(0o755)
    r = run(env, str(cit))
    assert r.returncode == 1
    assert "config check failed in wazuh-syscheckd" in r.stderr and "(1235)" in r.stderr
    assert conf.read_text() == ORIGINAL
    assert not (tmp_path / "calls").exists()  # the manager was never restarted


def test_passing_config_check_then_restart(tmp_path: Path) -> None:
    _, cit, env = setup(tmp_path)
    bindir = Path(env["WAZUH_HOME"]) / "bin"
    bindir.mkdir()
    for d in ("wazuh-logcollector", "wazuh-syscheckd"):
        (bindir / d).write_text("#!/bin/sh\nexit 0\n")
        (bindir / d).chmod(0o755)
    r = run(env, str(cit))
    assert r.returncode == 0, r.stderr
    assert "restart wazuh-manager" in (tmp_path / "calls").read_text()
