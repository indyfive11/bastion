"""P2 ownership mode — net-rollback's nft teardown is scope-aware.

net-rollback is the ONE place the "loaders inherit the rendered preamble for free" property breaks:
its UFW-restore path issues a bare nft teardown, not a replay of /etc/nftables.conf. So it must
honour FIREWALL_SCOPE itself — exclusive => `nft flush ruleset`; cooperative => delete only
bastion's own tables so co-resident tables (libvirt/docker) survive the rollback.

Bash idiom (project standard): extract the function with sed, source it in a child bash with `nft`
redefined as a recording shell function, drive via the env seams (FIREWALL_SCOPE / NFT_TABLE).
"""
import subprocess
from pathlib import Path

NET_ROLLBACK = Path(__file__).resolve().parent.parent / "bastion" / "scripts" / "net-rollback"


def _clear_bastion_nft(scope: str, nft_table: str = "inet edge") -> str:
    fn = subprocess.run(["sed", "-n", "/^clear_bastion_nft()/,/^}/p", str(NET_ROLLBACK)],
                        capture_output=True, text=True).stdout
    assert "clear_bastion_nft()" in fn, "could not extract clear_bastion_nft from net-rollback"
    script = (
        'nft(){ printf "NFT %s\\n" "$*"; }\n'      # record every nft invocation
        f'FIREWALL_SCOPE={scope}\n'
        f'NFT_TABLE="{nft_table}"\n'
        f'{fn}\n'
        'clear_bastion_nft\n'
    )
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True).stdout


def test_exclusive_flushes_whole_ruleset():
    out = _clear_bastion_nft("exclusive")
    assert "NFT flush ruleset" in out
    assert "delete table" not in out


def test_cooperative_deletes_only_bastion_tables_edge():
    out = _clear_bastion_nft("cooperative", "inet edge")
    assert "NFT flush ruleset" not in out                # never a global flush in cooperative
    assert "NFT delete table inet edge" in out           # the filter table
    assert "NFT delete table ip edge_nat" in out         # + the edge NAT table


def test_cooperative_endpoint_table_name_tracks_nft_table():
    out = _clear_bastion_nft("cooperative", "inet bastion")
    assert "NFT flush ruleset" not in out
    assert "NFT delete table inet bastion" in out         # endpoint's filter table


def test_default_scope_is_exclusive():
    # An older machine.env without FIREWALL_SCOPE must default to the historical flush behavior.
    out = _clear_bastion_nft("")
    assert "NFT flush ruleset" in out
