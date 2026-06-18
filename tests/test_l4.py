"""L4 dns-dhcp layer (Phase 4 / L4 gate). Edge-mode only; skipped on endpoint."""
import subprocess
from pathlib import Path

from bastion import layers, state, templates
from bastion.layers.base import Context
from bastion.system import System

REPO = Path(__file__).resolve().parent.parent
EXAMPLE = REPO / "bastion" / "machine.conf.example"
TEMPLATES = REPO / "bastion" / "templates"
SCRIPTS = REPO / "bastion" / "scripts"


def _ctx(root: Path, config: dict, dry_run=True) -> Context:
    return Context(system=System(root=root, dry_run=dry_run), config=config,
                   templates_dir=TEMPLATES, scripts_dir=SCRIPTS)


def test_l4_in_registry():
    l4 = layers.get("l4")
    assert "l4" in layers.REGISTRY
    assert l4.title == "dns-dhcp"


def test_l4_install_edge_writes_configs_and_seeds_blocklist(tmp_path):
    config = state.load_conf(EXAMPLE)          # mode = edge
    ctx = _ctx(tmp_path, config)
    layers.get("l4").install(ctx)

    assert (tmp_path / "usr/local/sbin/edge-dnsblock-update").is_file()
    assert (tmp_path / "etc/dnsmasq.conf").is_file()
    assert (tmp_path / "etc/unbound/unbound.conf").is_file()
    for u in ("edge-dnsblock.service", "edge-dnsblock.timer"):
        assert (tmp_path / f"etc/systemd/system/{u}").is_file()

    # dnsmasq.conf is fully resolved — no real {{ section.key }} placeholders remain.
    # (A literal "{{ }}" in a doc comment is not a placeholder and is left as-is.)
    assert templates.find_placeholders((tmp_path / "etc/dnsmasq.conf").read_text()) == set()
    # Empty sinkhole file seeded so unbound's include: starts before the first run.
    blk = tmp_path / "etc/unbound/blocklist.conf"
    assert blk.is_file() and "edge-dnsblock-update" in blk.read_text()

    # G3: dnsmasq reads a drop-in dir (so machine-specific DHCP reservations live outside the repo).
    assert "conf-dir=/etc/dnsmasq.d/,*.conf" in (tmp_path / "etc/dnsmasq.conf").read_text()
    assert (tmp_path / "etc/dnsmasq.d").is_dir()

    st = layers.get("l4").status(ctx)
    assert st.installed is True


def test_l4_skipped_on_endpoint(tmp_path):
    config = state.load_conf(EXAMPLE)
    config["machine"]["mode"] = "endpoint"
    ctx = _ctx(tmp_path, config)
    layers.get("l4").install(ctx)
    # Nothing written under an endpoint install.
    assert not any(tmp_path.iterdir())

    st = layers.get("l4").status(ctx)
    assert st.installed is False
    assert "edge mode only" in st.detail
    # health_check returns a single N/A check, all ok.
    checks = layers.get("l4").health_check(ctx)
    assert len(checks) == 1 and checks[0].ok is True


# --- G1: unbound DNSSEC validation + hardening ---------------------------------------------------
def test_l4_unbound_conf_hardened(tmp_path):
    # The rendered resolver must carry the DNSSEC-validation + hardening posture, fully static.
    config = state.load_conf(EXAMPLE)
    layers.get("l4").install(_ctx(tmp_path, config))
    body = (tmp_path / "etc/unbound/unbound.conf").read_text()
    for directive in (
        'auto-trust-anchor-file: "/var/lib/unbound/root.key"',
        "harden-algo-downgrade: yes",
        "harden-referral-path: yes",
        "aggressive-nsec: yes",
        "val-clean-additional: yes",
        "do-ip6: yes",
        "deny-any: yes",
        "qname-minimisation: yes",
        'include: "/etc/unbound/blocklist.conf"',
    ):
        assert directive in body, directive
    # Still topology-independent — no machine.conf placeholders.
    assert templates.find_placeholders(body) == set()


def test_l4_ships_unbound_anchor_dropin(tmp_path):
    # The RFC5011 anchor auto-refresh needs the unbound user to own /var/lib/unbound, which the
    # distro unit's StateDirectory leaves root-owned — the drop-in re-owns it before start.
    layers.get("l4").install(_ctx(tmp_path, state.load_conf(EXAMPLE)))
    drop = tmp_path / "etc/systemd/system/unbound.service.d/10-bastion-anchor.conf"
    assert drop.is_file()
    body = drop.read_text()
    assert "User=unbound" in body and "Group=unbound" in body


class _LiveSys(System):
    """A live-claiming System that records run() calls and stubs unbound-anchor/systemctl so no real
    command touches the host (mirrors tests/test_l0._FwSys). is_live=True drives the seeding path."""
    def __init__(self, root, has_anchor=True):
        super().__init__(root=root)
        self._has_anchor = has_anchor
        self.calls = []

    @property
    def is_live(self) -> bool:
        return True

    def command_exists(self, name: str) -> bool:
        return self._has_anchor if name == "unbound-anchor" else True

    def run(self, *args, **kwargs):
        self.calls.append(tuple(args))
        return subprocess.CompletedProcess(args, 0, "", "")


def test_l4_live_seeds_trust_anchor_before_unbound_start(tmp_path):
    sysobj = _LiveSys(tmp_path)
    ctx = Context(system=sysobj, config=state.load_conf(EXAMPLE),
                  templates_dir=TEMPLATES, scripts_dir=SCRIPTS)
    layers.get("l4").install(ctx)
    seed = ("unbound-anchor", "-a", "/var/lib/unbound/root.key")
    start = ("systemctl", "enable", "--now", "unbound.service")
    assert seed in sysobj.calls
    assert sysobj.calls.index(seed) < sysobj.calls.index(start)   # anchor BEFORE first start
    assert (tmp_path / "var/lib/unbound").is_dir()


def test_l4_live_missing_unbound_anchor_warns_and_skips(tmp_path, capsys):
    sysobj = _LiveSys(tmp_path, has_anchor=False)
    ctx = Context(system=sysobj, config=state.load_conf(EXAMPLE),
                  templates_dir=TEMPLATES, scripts_dir=SCRIPTS)
    layers.get("l4").install(ctx)
    assert not any(c[0] == "unbound-anchor" for c in sysobj.calls)
    assert "unbound-anchor not found" in capsys.readouterr().out
