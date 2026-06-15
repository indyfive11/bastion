import os
import stat

from bastion import state


MACHINE_CONF = """\
[machine]
mode = edge
[network]
lan_cidr = 10.0.1.0/24
lan_ip = 10.0.1.1
gateway = 10.0.1.254
# a value containing '#': must survive parsing intact
dns_upstream = 127.0.0.1#5335
[monitoring]
relay_dst = 10.0.0.3
nm_conn =
"""


def test_load_conf_preserves_hash_in_value(tmp_path):
    p = tmp_path / "machine.conf"
    p.write_text(MACHINE_CONF)
    conf = state.load_conf(p)
    assert conf["network"]["dns_upstream"] == "127.0.0.1#5335"
    assert conf["machine"]["mode"] == "edge"
    # full-line comments are not turned into keys
    assert "secrets" not in conf


def test_secrets_isolated_from_machine_conf(tmp_path):
    mp = tmp_path / "machine.conf"
    mp.write_text(MACHINE_CONF)
    sp = tmp_path / "secrets.conf"
    state.write_secrets({"anthropic_api_key": "key-value"}, sp)

    machine = state.load_conf(mp)
    assert all("secrets" not in section for section in machine)  # no secrets section
    assert "key-value" not in repr(machine)
    # secrets only via the dedicated loader
    assert state.load_secrets(sp)["anthropic_api_key"] == "key-value"


def test_write_secrets_is_chmod_600(tmp_path):
    sp = tmp_path / "secrets.conf"
    state.write_secrets({"anthropic_api_key": "x"}, sp)
    mode = stat.S_IMODE(os.stat(sp).st_mode)
    assert mode == 0o600


def test_render_machine_env_maps_and_derives(tmp_path):
    p = tmp_path / "machine.conf"
    p.write_text(MACHINE_CONF)
    conf = state.load_conf(p)
    env = state.render_machine_env(conf)
    assert "LAN_NET='10.0.1.0/24'" in env
    assert "GATEWAY='10.0.1.254'" in env
    assert "RELAY_DST='10.0.0.3'" in env
    assert "NM_CONN=''" in env                       # blank renders empty
    assert "LAN_IP_CIDR='10.0.1.1/24'" in env        # derived from lan_ip + lan_cidr prefix
    assert "DNS_UPSTREAM='127.0.0.1#5335'" in env     # local stub host#port (flowcheck probes it)


def test_render_machine_env_is_shell_safe():
    conf = {"monitoring": {"egress_probe": "https://x/$(rm -rf)"}}
    env = state.render_machine_env(conf)
    # single-quoted, so the shell never evaluates the payload
    assert "EGRESS_PROBE='https://x/$(rm -rf)'" in env
