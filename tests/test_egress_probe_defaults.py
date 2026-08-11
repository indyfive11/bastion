"""N1 — the default egress/liveness probe is a neutral host (example.com, IANA/RFC-2606 reserved),
not a specific SaaS API. A general firewall framework shouldn't hard-default its liveness canary to
one vendor's endpoint. example.com returns a clean HTTP 200 (satisfies flowcheck's [200|404] gate)
and has no bot-challenge infrastructure (so it doesn't false-FAIL on datacenter/VPS egress).

Invariants pinned here:
  * net-confirm + flowcheck default EGRESS_PROBE → https://example.com.
  * edge-watchdog's EXT_HTTPS any-success list drops api.anthropic.com and keeps two neutral infra
    hosts (example.com + cloudflare), both of which are in dns-allowlist so the box can't sinkhole
    its own canary.
  * flowcheck's INDEPENDENT cross-check stays a DIFFERENT host from the main probe (independence).
  * example.com is in the DNS never-sink allowlist.
"""
import re
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "bastion" / "scripts"
TEMPLATES = Path(__file__).resolve().parent.parent / "bastion" / "templates"
PKG = Path(__file__).resolve().parent.parent / "bastion"


def test_net_confirm_default_probe_is_neutral():
    txt = (SCRIPTS / "net-confirm").read_text()
    assert "EGRESS_PROBE=${EGRESS_PROBE:-https://example.com}" in txt
    assert "api.anthropic.com" not in txt


def test_flowcheck_default_probe_is_neutral_and_crosscheck_independent():
    txt = (SCRIPTS / "flowcheck").read_text()
    assert "EGRESS_PROBE=${EGRESS_PROBE:-https://example.com}" in txt
    assert "api.anthropic.com" not in txt
    # The independent cross-check must remain a DIFFERENT host than the main probe, or it stops being
    # independent. It stays cloudflare (already allowlisted, reachability-only).
    m = re.search(r"_ck_cloudflare\(\)\{[^}]*\}", txt)
    assert m and "cloudflare.com" in m.group(0)


def test_watchdog_ext_https_drops_anthropic_keeps_neutral_pair():
    txt = (SCRIPTS / "edge-watchdog").read_text()
    m = re.search(r'EXT_HTTPS=\$\{EXT_HTTPS:-"([^"]*)"\}', txt)
    assert m, "EXT_HTTPS default not found"
    hosts = m.group(1)
    assert "api.anthropic.com" not in hosts
    assert "example.com" in hosts and "cloudflare.com" in hosts


def test_example_com_in_dns_allowlist():
    txt = (TEMPLATES / "dns-allowlist").read_text()
    # Every EXT_HTTPS / cross-check host must be allowlisted or the box's own L4 sinkhole can NXDOMAIN
    # its own canary (these hosts are NOT auto-protected like EGRESS_PROBE is).
    lines = [l.strip() for l in txt.splitlines() if l.strip() and not l.strip().startswith("#")]
    assert "example.com" in lines
    assert "cloudflare.com" in lines


def test_machine_conf_example_ships_neutral_default():
    txt = (PKG / "machine.conf.example").read_text()
    assert "egress_probe = https://example.com" in txt
    assert "api.anthropic.com" not in txt
