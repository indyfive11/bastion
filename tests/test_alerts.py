"""notify-alert sink configuration (setup/alerts.py + wizard._alerts_step).

Render/quoting, the chmod-600 write (root-prefixed, never machine.conf), reuse-on-reinstall,
skip-when-empty, and the dry-run / non-interactive guards — all offline with a temp-rooted System.
The sample email/topic use example.com / a random word so `make leak-check` stays clean.
"""
import stat
from pathlib import Path

from bastion.setup import alerts, wizard
from bastion.system import System

REPO = Path(__file__).resolve().parent.parent
EXAMPLE = REPO / "bastion" / "machine.conf.example"
ALERT_REL = "etc/bastion/notify-alert.conf"


# --- pure render / apply ---------------------------------------------------

def test_render_conf_is_shell_sourceable_and_single_quoted():
    body = alerts.render_conf({
        "NTFY_TOPIC": "alpha-topic",
        "NTFY_SERVER": "https://ntfy.sh",
        "ALERT_EMAIL": "ops@example.com",
        "INTERNAL_NTFY_URL": "https://nt.internal/x",
        # an auth header with a $ and a space must survive single-quoting intact
        "INTERNAL_NTFY_AUTH": "Bearer tk_$ecret value",
    })
    assert "NTFY_TOPIC='alpha-topic'" in body
    assert "ALERT_EMAIL='ops@example.com'" in body
    assert "INTERNAL_NTFY_AUTH='Bearer tk_$ecret value'" in body


def test_render_conf_blank_disables_sink():
    body = alerts.render_conf({"NTFY_TOPIC": "", "ALERT_EMAIL": ""})
    assert "NTFY_TOPIC=''" in body
    assert "ALERT_EMAIL=''" in body
    # every FIELD key is always emitted (so notify-alert sources a complete file)
    for f in alerts.FIELDS:
        assert f"{f.key}=" in body


def test_apply_alerts_writes_chmod_600_rooted(tmp_path):
    sys_ = System(root=tmp_path)
    path = alerts.apply_alerts(sys_, {"NTFY_TOPIC": "t"})
    dest = tmp_path / ALERT_REL
    assert path == alerts.ALERT_CONF              # logical (un-rooted) path returned
    assert dest.is_file()
    assert stat.S_IMODE(dest.stat().st_mode) == 0o600
    assert "NTFY_TOPIC='t'" in dest.read_text()


def test_has_any_sink():
    assert alerts.has_any_sink({"NTFY_TOPIC": "x"})
    assert alerts.has_any_sink({"ALERT_EMAIL": "a@b.c"})
    assert alerts.has_any_sink({"INTERNAL_NTFY_URL": "u"})
    # server/auth alone are NOT real sinks (nothing to send to)
    assert not alerts.has_any_sink({"NTFY_SERVER": "https://ntfy.sh", "INTERNAL_NTFY_AUTH": "tk"})
    assert not alerts.has_any_sink({})


# --- wizard _alerts_step integration ---------------------------------------

def _wizard(sys_, *, inp, secret_inp, assume_defaults=False, dry_run=False):
    return wizard.Wizard(sys_, dry_run=dry_run, profile="full-edge",
                         assume_defaults=assume_defaults, inp=inp, secret_inp=secret_inp,
                         example_conf=str(EXAMPLE))


def _responder(mapping):
    """Return an `inp` that answers by matching a substring of the prompt; default '' otherwise."""
    def inp(prompt):
        for needle, value in mapping.items():
            if needle in prompt:
                return value
        return ""
    return inp


def test_alerts_step_captures_sinks_and_writes(tmp_path):
    sys_ = System(root=tmp_path)
    inp = _responder({"Public ntfy topic": "alpha-topic", "Alert email": "ops@example.com"})
    wiz = _wizard(sys_, inp=inp, secret_inp=lambda *_: "")
    notes = wiz._alerts_step("full-edge")

    dest = tmp_path / ALERT_REL
    assert notes == []
    assert dest.is_file() and stat.S_IMODE(dest.stat().st_mode) == 0o600
    text = dest.read_text()
    assert "NTFY_TOPIC='alpha-topic'" in text
    assert "ALERT_EMAIL='ops@example.com'" in text
    assert "NTFY_SERVER='https://ntfy.sh'" in text       # default kept when topic is set
    assert "INTERNAL_NTFY_URL=''" in text                # blank → URL-dependent auth skipped
    # operator/secret sink config never lands in machine.conf
    assert not (tmp_path / "etc/bastion/machine.conf").exists()


def test_alerts_step_internal_auth_is_hidden_input(tmp_path):
    sys_ = System(root=tmp_path)
    inp = _responder({"Internal ntfy URL": "https://nt.internal/x"})

    def secret_inp(prompt):
        assert "auth" in prompt.lower() and "hidden" in prompt.lower()
        return "Bearer tk_z"

    wiz = _wizard(sys_, inp=inp, secret_inp=secret_inp)
    wiz._alerts_step("full-edge")
    text = (tmp_path / ALERT_REL).read_text()
    assert "INTERNAL_NTFY_URL='https://nt.internal/x'" in text
    assert "INTERNAL_NTFY_AUTH='Bearer tk_z'" in text


def test_alerts_step_no_sink_leaves_conf_absent(tmp_path):
    sys_ = System(root=tmp_path)
    wiz = _wizard(sys_, inp=lambda *_: "", secret_inp=lambda *_: "")   # everything blank
    notes = wiz._alerts_step("full-edge")
    assert notes == []
    assert not (tmp_path / ALERT_REL).exists()


def test_alerts_step_reinstall_reuses_conf_no_prompt(tmp_path):
    dest = tmp_path / ALERT_REL
    dest.parent.mkdir(parents=True)
    dest.write_text("NTFY_TOPIC='existing'\n")
    sys_ = System(root=tmp_path)

    def boom(*_):
        raise AssertionError("must not re-prompt when a notify-alert.conf already exists")

    wiz = _wizard(sys_, inp=boom, secret_inp=boom)
    assert wiz._alerts_step("full-edge") == []
    assert dest.read_text() == "NTFY_TOPIC='existing'\n"   # untouched


def test_alerts_step_no_l6_is_noop(tmp_path):
    sys_ = System(root=tmp_path)
    wiz = _wizard(sys_, inp=lambda *_: "x", secret_inp=lambda *_: "x")
    assert wiz._alerts_step("custom") == []                 # custom profile → no declared l6
    assert not (tmp_path / ALERT_REL).exists()


def test_alerts_step_dry_run_writes_nothing(tmp_path):
    sys_ = System(root=tmp_path)

    def boom(*_):
        raise AssertionError("dry-run must not prompt or write")

    wiz = _wizard(sys_, inp=boom, secret_inp=boom, dry_run=True)
    notes = wiz._alerts_step("full-edge")
    assert notes and "would capture" in notes[0]
    assert not (tmp_path / ALERT_REL).exists()


def test_alerts_step_non_interactive_skips(tmp_path):
    sys_ = System(root=tmp_path)

    def boom(*_):
        raise AssertionError("non-interactive must not prompt")

    wiz = _wizard(sys_, inp=boom, secret_inp=boom, assume_defaults=True)
    notes = wiz._alerts_step("full-edge")
    assert notes and "non-interactive" in notes[0].lower()
    assert not (tmp_path / ALERT_REL).exists()
