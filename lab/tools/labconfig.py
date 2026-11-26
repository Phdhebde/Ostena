#!/usr/bin/env python3
"""Lab configuration helper (ADR-0025), independent of the hypervisor.

Reads lab/machines.json and lab/images.json and produces what a provider
needs: the secrets of a run, the configuration file of each machine, the
firewall rules of the isolated zone and, at the end, the lab.json entry
point consumed by the end-to-end tests. Standard library only.

  labconfig.py secrets <state>             draw the passwords of the run
  labconfig.py vms                         one line per machine (TSV)
  labconfig.py vm-config <state> <vm> <dir>  write <dir>/ostena-vm.json
  labconfig.py nft                         nftables ruleset of the lab
  labconfig.py assemble <state> <out-dir>  write <out-dir>/lab.json
"""

import base64
import ipaddress
import json
import os
import secrets
import string
import sys
from pathlib import Path

LAB = Path(__file__).resolve().parent.parent
BRIDGE_PREFIX = "ost-"
TAP_PREFIX = "ost-t-"


def load(name):
    with open(LAB / name, encoding="utf-8") as f:
        return json.load(f)


def password(length=24):
    """Random password meeting the default AD complexity rules.

    Letters and digits only, so that it can be passed through XML, JSON,
    PowerShell and cmd without quoting.
    """
    alphabet = string.ascii_letters + string.digits
    while True:
        value = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in value)
            and any(c.isupper() for c in value)
            and any(c.isdigit() for c in value)
        ):
            return value


def write_private(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")


def cmd_secrets(state):
    lab = load("machines.json")
    path = Path(state) / "secrets.json"
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
    else:
        accounts = lab["accounts"]
        data = {
            "admin": password(),
            "dsrm": password(),
            "domain": {a["name"]: password() for a in accounts["domain"]},
            "service": password(),
            "local": password(),
        }
        write_private(path, data)
    if os.environ.get("GITHUB_ACTIONS") == "true":
        values = [data["admin"], data["dsrm"], data["service"], data["local"]]
        values += list(data["domain"].values())
        for value in values:
            print(f"::add-mask::{value}")


def machine(lab, name):
    for m in lab["machines"]:
        if m["name"] == name:
            return m
    sys.exit(f"labconfig: unknown machine {name}")


def mac_of(m):
    last = ipaddress.ip_address(m["ip"]).packed
    return "52:54:00:4f:%02x:%02x" % (last[2], last[3])


def cmd_vms():
    lab = load("machines.json")
    for m in lab["machines"]:
        print(
            "\t".join(
                [
                    m["name"],
                    m["role"],
                    m["image"],
                    m["segment"],
                    m["ip"],
                    str(m["memory_mb"]),
                    str(m["cpus"]),
                    mac_of(m),
                    BRIDGE_PREFIX + m["segment"],
                    TAP_PREFIX + m["name"],
                ]
            )
        )


def dc_of(lab):
    return next(m for m in lab["machines"] if m["role"] == "dc")


def cmd_vm_config(state, name, out_dir):
    lab = load("machines.json")
    sec = json.loads((Path(state) / "secrets.json").read_text(encoding="utf-8"))
    m = machine(lab, name)
    seg = lab["segments"][m["segment"]]
    net = ipaddress.ip_network(seg["cidr"])
    dc = dc_of(lab)
    cfg = {
        "name": m["name"],
        "hostname": m["name"],
        "role": m["role"],
        "ip": m["ip"],
        "prefix": net.prefixlen,
        "gateway": seg["gateway"],
        "dns": ["127.0.0.1"] if m["role"] == "dc" else [dc["ip"]],
        "domain": lab["domain"],
        "control_url": f"http://{seg['gateway']}:{lab['host']['control_port']}",
        "admin_password": sec["admin"],
    }
    if m["role"] == "dc":
        accounts = lab["accounts"]
        cfg["dsrm_password"] = sec["dsrm"]
        cfg["accounts"] = [
            {"name": a["name"], "groups": a["groups"], "password": sec["domain"][a["name"]]}
            for a in accounts["domain"]
        ]
        cfg["service"] = {
            "name": accounts["service"]["name"],
            "spn": accounts["service"]["spn"],
            "password": sec["service"],
        }
        cfg["bastion"] = {"name": lab["host"]["name"], "ip": seg["gateway"]}
    elif m["role"] == "member":
        cfg["local_account"] = {"name": lab["accounts"]["local"]["name"], "password": sec["local"]}
    write_private(Path(out_dir) / "ostena-vm.json", cfg)


def targets(lab, to):
    if to.startswith("role:"):
        role = to.split(":", 1)[1]
        return [m["ip"] for m in lab["machines"] if m["role"] == role]
    sys.exit(f"labconfig: unknown egress destination {to}")


def cmd_nft():
    """Rules enforcing the isolation (no inbound flow into isolated zones).

    Only traffic touching the lab bridges is judged; the rest of the host
    keeps its own rules.
    """
    lab = load("machines.json")
    segs = lab["segments"]
    bridges = ", ".join(f'"{BRIDGE_PREFIX}{s}"' for s in segs)
    out = ["table inet ostena_lab", "delete table inet ostena_lab", "table inet ostena_lab {"]
    # Named counters first: the smoke test reads them.
    for name, seg in segs.items():
        if seg.get("isolated"):
            for what in ("egress", "host", "inbound"):
                out.append(f"  counter {name}_{what}_refused {{ }}")
    for name, seg in segs.items():
        if not seg.get("isolated"):
            continue
        out.append(f"  chain egress_{name} {{")
        host_rules = []
        for rule in seg.get("egress", []):
            ports = ", ".join(str(p) for p in rule["ports"])
            if rule["to"] == "host":
                host_rules.append(rule)
                continue
            addrs = ", ".join(targets(lab, rule["to"]))
            out.append(f"    ip daddr {{ {addrs} }} {rule['proto']} dport {{ {ports} }} accept")
        out.append(f'    counter name "{name}_egress_refused" drop')
        out.append("  }")
        out.append(f"  chain to_host_{name} {{")
        out.append(f"    ip daddr {seg['gateway']} tcp dport {lab['host']['control_port']} accept")
        for rule in host_rules:
            ports = ", ".join(str(p) for p in rule["ports"])
            out.append(f"    ip daddr {seg['gateway']} {rule['proto']} dport {{ {ports} }} accept")
        out.append(f'    counter name "{name}_host_refused" drop')
        out.append("  }")
    out.append("  chain forward {")
    out.append("    type filter hook forward priority filter; policy accept;")
    out.append(f"    iifname != {{ {bridges} }} oifname != {{ {bridges} }} accept")
    out.append("    ct state established,related accept")
    for name, seg in segs.items():
        br = BRIDGE_PREFIX + name
        if seg.get("isolated"):
            out.append(f'    oifname "{br}" counter name "{name}_inbound_refused" drop')
            out.append(f'    iifname "{br}" jump egress_{name}')
        else:
            out.append(f'    iifname "{br}" oifname "{br}" accept')
    out.append("    # Lab segments are routed to nothing else (no Internet access).")
    out.append("    drop")
    out.append("  }")
    out.append("  chain input {")
    out.append("    type filter hook input priority filter; policy accept;")
    for name, seg in segs.items():
        if seg.get("isolated"):
            br = BRIDGE_PREFIX + name
            out.append(f'    iifname "{br}" ct state established,related accept')
            out.append(f'    iifname "{br}" jump to_host_{name}')
    out.append("  }")
    out.append("  chain output {")
    out.append("    type filter hook output priority filter; policy accept;")
    for name, seg in segs.items():
        if seg.get("isolated"):
            br = BRIDGE_PREFIX + name
            out.append(f'    oifname "{br}" ct state established,related accept')
            out.append(f'    oifname "{br}" counter name "{name}_inbound_refused" drop')
    out.append("  }")
    out.append("}")
    print("\n".join(out))


def read_facts(state, name):
    path = Path(state) / "facts" / f"{name}.json"
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {}


def cert(facts, key):
    c = facts.get(key) or {}
    return {k: c.get(k) for k in ("subject", "issuer", "sha256", "sha1", "not_after")} if c else None


def cmd_assemble(state, out_dir):
    lab = load("machines.json")
    images = load("images.json")["images"]
    sec = json.loads((Path(state) / "secrets.json").read_text(encoding="utf-8"))
    dom = lab["domain"]
    dc = dc_of(lab)
    dc_facts = read_facts(state, dc["name"])
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    keytab_path = None
    if dc_facts.get("keytab_base64"):
        keytab_path = out / "service.keytab"
        fd = os.open(keytab_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(base64.b64decode(dc_facts["keytab_base64"]))
    ca_pem = None
    ca = dc_facts.get("ca") or {}
    if ca.get("der_base64"):
        body = ca["der_base64"]
        lines = [body[i : i + 64] for i in range(0, len(body), 64)]
        ca_pem = "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"
        (out / "lab-ca.pem").write_text(ca_pem, encoding="ascii")

    machines = {}
    for m in lab["machines"]:
        facts = read_facts(state, m["name"])
        entry = {
            "role": m["role"],
            "os": images[m["image"]]["label"],
            "image": m["image"],
            "segment": m["segment"],
            "ip": m["ip"],
            "fqdn": facts.get("fqdn") or (m["name"] if m["role"] == "gateway" else f"{m['name']}.{dom['fqdn']}"),
            "domain_joined": m["role"] in ("dc", "member"),
        }
        if m["role"] == "member":
            entry["rdp"] = {"port": 3389, "nla": True, "certificate": cert(facts, "rdp")}
        if m["role"] == "dc":
            entry["ldaps"] = {"port": 636, "certificate": cert(facts, "ldaps")}
            entry["kerberos"] = {"port": 88}
        machines[m["name"]] = entry

    accounts = lab["accounts"]
    netbios = dom["netbios"]
    result = {
        "version": 1,
        "comment": "Generated by lab/tools/labconfig.py for one run; holds test passwords of this run only. Never publish.",
        "domain": {
            "fqdn": dom["fqdn"],
            "netbios": netbios,
            "realm": dom["realm"],
            "dc": dc["name"],
            "dc_ip": dc["ip"],
            "sid": dc_facts.get("domain_sid"),
        },
        "host": {
            "fqdn": f"{lab['host']['name']}.{dom['fqdn']}",
            "addresses": {name: seg["gateway"] for name, seg in lab["segments"].items()},
            "control_port": lab["host"]["control_port"],
        },
        "segments": lab["segments"],
        "ca": None
        if not ca
        else {
            "subject": ca.get("subject"),
            "sha256": ca.get("sha256"),
            "pem_file": str(out / "lab-ca.pem"),
            "pem": ca_pem,
        },
        "machines": machines,
        "accounts": {
            "administrator": {
                "user": f"{netbios}\\Administrator",
                "upn": f"Administrator@{dom['fqdn']}",
                "password": sec["admin"],
                "comment": "domain Administrator and local Administrator of every machine",
            },
            "domain": [
                {
                    "user": f"{netbios}\\{a['name']}",
                    "upn": f"{a['name']}@{dom['fqdn']}",
                    "password": sec["domain"][a["name"]],
                    "groups": a["groups"],
                    "purpose": a["purpose"],
                }
                for a in accounts["domain"]
            ],
            "local": {
                "user": accounts["local"]["name"],
                "password": sec["local"],
                "machines": [m["name"] for m in lab["machines"] if m["role"] == "member"],
                "purpose": accounts["local"]["purpose"],
            },
            "service": {
                "user": f"{netbios}\\{accounts['service']['name']}",
                "spn": accounts["service"]["spn"],
                "principal": dc_facts.get("keytab_principal"),
                "password": sec["service"],
                "keytab": str(keytab_path) if keytab_path else None,
            },
        },
    }
    timings = Path(state) / "timings.json"
    if timings.exists():
        result["timings_s"] = json.loads(timings.read_text(encoding="utf-8"))
    write_private(out / "lab.json", result)
    print(out / "lab.json")


def main(argv):
    if len(argv) < 2:
        sys.exit(__doc__)
    cmd, args = argv[1], argv[2:]
    table = {
        "secrets": (cmd_secrets, 1),
        "vms": (cmd_vms, 0),
        "vm-config": (cmd_vm_config, 3),
        "nft": (cmd_nft, 0),
        "assemble": (cmd_assemble, 2),
    }
    if cmd not in table or len(args) != table[cmd][1]:
        sys.exit(__doc__)
    table[cmd][0](*args)


if __name__ == "__main__":
    main(sys.argv)
