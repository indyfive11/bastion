"""AI backend configuration (setup/ai_backend.py + wizard._secrets_step).

Detection precedence (bastion config first), reuse-on-reinstall, request-on-fresh, the secret
write (secrets.conf + edge-ai EnvironmentFile, chmod 600, never machine.conf), and the provider
menu — all driven offline with a fake System (detection) or a temp-rooted real System (writes).
The placeholder key deliberately avoids the `sk-ant-` shape so it can't trip `make leak-check`.
"""
import os
from pathlib import Path

from bastion import state
from bastion.setup import ai_backend, wizard
from bastion.system import System

REPO = Path(__file__).resolve().parent.parent
EXAMPLE = REPO / "bastion" / "machine.conf.example"
DUMMY = "k-test-dummy-0001"          # NOT an sk-ant- key; safe for the repo


class FakeSystem(System):
    """root-prefixing is bypassed: file content is served from an in-memory map."""
    def __init__(self, files: dict):
        super().__init__()
        self._files = files

    def exists(self, p):
        return str(p) in self._files

    def read(self, p):
        return self._files[str(p)]


# --- detection -------------------------------------------------------------

def test_detect_nothing_present():
    st = ai_backend.detect_backend(FakeSystem({}), env={})
    assert st.backend_cmd is None and not st.key_present and st.key_env is None


def test_detect_secrets_conf_beats_env():
    # bastion config first: a key in secrets.conf wins even when one also sits in the environment.
    files = {"/etc/bastion/secrets.conf": f"[secrets]\nanthropic_api_key = {DUMMY}\n"}
    st = ai_backend.detect_backend(FakeSystem(files), env={"ANTHROPIC_API_KEY": "env-key"})
    assert st.key_present and st.key_source == "secrets.conf" and st.key_env == "ANTHROPIC_API_KEY"


def test_detect_custom_secrets_file_path():
    # machine.conf can repoint secrets_file; detection must follow it.
    files = {
        "/etc/bastion/machine.conf": "[machine]\nsecrets_file = /opt/sec.conf\n",
        "/opt/sec.conf": f"[secrets]\nanthropic_api_key = {DUMMY}\n",
    }
    st = ai_backend.detect_backend(FakeSystem(files), env={})
    assert st.key_present and st.key_source == "secrets.conf"


def test_detect_claude_env_file():
    files = {"/etc/edge-ai/claude.env": f"ANTHROPIC_API_KEY={DUMMY}\n"}
    st = ai_backend.detect_backend(FakeSystem(files), env={})
    assert st.key_present and st.key_source == ai_backend.EDGE_AI_ENV


def test_detect_backend_cmd_from_backendconf():
    files = {"/etc/edge-ai/backend.conf": "BACKEND_CMD=/usr/local/sbin/edge-ai-backend-mock\nMODEL=x\n"}
    st = ai_backend.detect_backend(FakeSystem(files), env={})
    assert st.backend_cmd == "/usr/local/sbin/edge-ai-backend-mock" and st.model == "x"


def test_detect_machine_conf_ai_section_wins_over_backendconf():
    files = {
        "/etc/bastion/machine.conf": "[ai]\nbackend_cmd = /usr/local/sbin/edge-ai-backend-claude\nmodel = claude-opus-4-8\n",
        "/etc/edge-ai/backend.conf": "BACKEND_CMD=/other\n",
    }
    st = ai_backend.detect_backend(FakeSystem(files), env={})
    assert st.backend_cmd.endswith("edge-ai-backend-claude") and st.model == "claude-opus-4-8"


def test_detect_env_is_last_resort():
    st = ai_backend.detect_backend(FakeSystem({}), env={"ANTHROPIC_API_KEY": DUMMY})
    assert st.key_present and st.key_source == "env:ANTHROPIC_API_KEY"


# --- provider mapping ------------------------------------------------------

def test_provider_for_cmd():
    assert ai_backend.provider_for_cmd(None) is None
    assert ai_backend.provider_for_cmd(f"{ai_backend.SBIN}/edge-ai-backend-claude").key == "claude"
    assert ai_backend.provider_for_cmd("/some/local/model").key == "custom"


# --- the secret write ------------------------------------------------------

def test_apply_secret_writes_both_files_chmod_600(tmp_path):
    sys_ = System(root=tmp_path)
    written = ai_backend.apply_secret(sys_, secrets_path=ai_backend.DEFAULT_SECRETS_FILE,
                                      key_env="ANTHROPIC_API_KEY", key_value=DUMMY)
    assert written == [ai_backend.DEFAULT_SECRETS_FILE, ai_backend.EDGE_AI_ENV]

    sec = tmp_path / "etc/bastion/secrets.conf"
    envf = tmp_path / "etc/edge-ai/claude.env"
    assert state.load_secrets(sec)["anthropic_api_key"] == DUMMY
    assert f"ANTHROPIC_API_KEY={DUMMY}" in envf.read_text()
    assert (sec.stat().st_mode & 0o777) == 0o600
    assert (envf.stat().st_mode & 0o777) == 0o600


def test_apply_secret_merges_existing_secrets(tmp_path):
    sys_ = System(root=tmp_path)
    sec = tmp_path / "etc/bastion/secrets.conf"
    sec.parent.mkdir(parents=True)
    state.write_secrets({"other_token": "keep-me"}, sec)
    ai_backend.apply_secret(sys_, secrets_path=ai_backend.DEFAULT_SECRETS_FILE,
                            key_env="ANTHROPIC_API_KEY", key_value=DUMMY)
    merged = state.load_secrets(sec)
    assert merged["other_token"] == "keep-me" and merged["anthropic_api_key"] == DUMMY


# --- wizard _secrets_step integration -------------------------------------

def _wizard(sys_, *, inp, secret_inp, assume_defaults=False, dry_run=False):
    return wizard.Wizard(sys_, dry_run=dry_run, profile="full-edge",
                         assume_defaults=assume_defaults, inp=inp, secret_inp=secret_inp,
                         example_conf=str(EXAMPLE))


def test_secrets_step_fresh_claude_captures_key(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    sys_ = System(root=tmp_path)
    answers: dict = {}
    wiz = _wizard(sys_, inp=lambda *_: "1", secret_inp=lambda *_: DUMMY)   # choose Claude
    wiz._secrets_step("full-edge", answers)

    assert answers["ai_backend_cmd"].endswith("edge-ai-backend-claude")
    assert answers["ai_model"] == "claude-opus-4-8"
    # secret landed in secrets.conf + EnvironmentFile, NOT in any machine.conf
    assert state.load_secrets(tmp_path / "etc/bastion/secrets.conf")["anthropic_api_key"] == DUMMY
    assert (tmp_path / "etc/edge-ai/claude.env").exists()
    assert not (tmp_path / "etc/bastion/machine.conf").exists()


def test_secrets_step_reinstall_reuses_key_no_prompt(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    # An existing live key file -> reuse, never call the (exploding) secret prompt.
    envf = tmp_path / "etc/edge-ai/claude.env"
    envf.parent.mkdir(parents=True)
    envf.write_text(f"ANTHROPIC_API_KEY={DUMMY}\n")
    sys_ = System(root=tmp_path)

    def boom(*_):
        raise AssertionError("must not re-prompt for a key on reinstall")

    answers: dict = {}
    wiz = _wizard(sys_, inp=lambda *_: "1", secret_inp=boom)
    notes = wiz._secrets_step("full-edge", answers)
    assert answers["ai_backend_cmd"].endswith("edge-ai-backend-claude")
    assert notes == []          # reuse path returns no deferral note
    assert not (tmp_path / "etc/bastion/secrets.conf").exists()


def test_secrets_step_mock_needs_no_key(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    sys_ = System(root=tmp_path)

    def boom(*_):
        raise AssertionError("mock backend must not prompt for a key")

    answers: dict = {}
    wiz = _wizard(sys_, inp=lambda *_: "3", secret_inp=boom)   # choose Mock
    wiz._secrets_step("full-edge", answers)
    assert answers["ai_backend_cmd"].endswith("edge-ai-backend-mock")
    assert not (tmp_path / "etc/bastion/secrets.conf").exists()
    assert not (tmp_path / "etc/edge-ai/claude.env").exists()


def test_secrets_step_no_l3_is_noop():
    sys_ = System(root=Path("/nonexistent-root"))
    answers: dict = {}
    wiz = _wizard(sys_, inp=lambda *_: "1", secret_inp=lambda *_: DUMMY)
    assert wiz._secrets_step("minimal-endpoint", answers) == []
    assert answers == {}        # no AI layer -> nothing recorded


def test_secrets_step_dry_run_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    sys_ = System(root=tmp_path)

    def boom(*_):
        raise AssertionError("dry-run must not prompt or write")

    answers: dict = {}
    wiz = _wizard(sys_, inp=lambda *_: "1", secret_inp=boom, dry_run=True)
    notes = wiz._secrets_step("full-edge", answers)
    assert notes and "would capture" in notes[0]
    assert not (tmp_path / "etc/bastion/secrets.conf").exists()
    assert not (tmp_path / "etc/edge-ai/claude.env").exists()
