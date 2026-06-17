"""edge-dnsblock-update accepts hosts / plain-domain / adblock list formats (Option A).

The old extractor only matched `0.0.0.0 <domain>` hosts lines, silently yielding zero domains from
adblock- or plain-domain-format lists (OISD, HaGeZi domains/adblock, AdGuard). This pins the broader
extractor: each format normalizes to bare domains, and junk (IPs, comments, wildcard/regex/exception
adblock rules, localhost) is dropped. Driven via the project's bash idiom.
"""
import subprocess
import textwrap
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "bastion" / "scripts" / "edge-dnsblock-update"


def _run(sample: str) -> list[str]:
    """Extract domains the way the script does: extract_domains | the final validate/clean grep."""
    fn = subprocess.run(["sed", "-n", "/^extract_domains()/,/^}/p", str(SCRIPT)],
                        capture_output=True, text=True, check=True).stdout
    assert "extract_domains()" in fn
    driver = fn + textwrap.dedent("""
        extract_domains \
          | sort -u | grep -E '^[a-z0-9_.-]+\\.[a-z0-9_.-]+$' \
          | grep -vE '^([0-9.]+|localhost|localhost\\.localdomain|local|broadcasthost|ip6-[a-z]+)$'
    """)
    # grep exits 1 when it filters everything out (an all-junk list) — that's a valid empty result.
    out = subprocess.run(["bash", "-c", driver], input=sample, capture_output=True, text=True)
    return sorted(out.stdout.split())


def test_hosts_format():
    assert _run("0.0.0.0 ads.example.com\n127.0.0.1 t.example.net\n::1 v6.example.org\n") == \
        ["ads.example.com", "t.example.net", "v6.example.org"]


def test_plain_domain_format():
    assert _run("plaindomain.example.com\nads.tracker.io\n") == ["ads.tracker.io", "plaindomain.example.com"]


def test_adblock_format():
    # ||domain^ (plain anchored-domain rules, with/without $options) are kept
    got = _run("||doubleclick.net^\n||adserver.example.com^$third-party\n")
    assert got == ["adserver.example.com", "doubleclick.net"]


def test_skips_unmappable_and_junk():
    sample = textwrap.dedent("""\
        # a comment
        ! adblock comment
        [Adblock Plus 2.0]
        0.0.0.0 0.0.0.0
        192.168.1.1
        localhost
        ||*.wildcard.com^
        /regex.*rule/
        @@||allowlisted.example^
        a line with spaces and stuff
    """)
    assert _run(sample) == []          # nothing here maps to a sinkholable domain


def test_mixed_list_round_trips():
    sample = "0.0.0.0 a.example\nb.example\n||c.example^\n# x\n0.0.0.0 0.0.0.0\n"
    assert _run(sample) == ["a.example", "b.example", "c.example"]


def test_doc_comment_lists_supported_formats():
    body = SCRIPT.read_text()
    assert "plain domain" in body and "adblock" in body and "hosts" in body
