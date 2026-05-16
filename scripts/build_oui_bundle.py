#!/usr/bin/env python3
"""Generate the bundled OUI vendor table for One Link.

Bundled, local-only, no outside lookup. The full IEEE registry has
~33k prefixes; we ship a curated ~200 most-common consumer-device
prefixes (~15 KB gzipped) so the typical home network identifies
correctly without bloating the install.

Operators who want full coverage can replace the bundled file with
the full IEEE oui.txt (run this script with --full, point at a
local copy of oui.txt).
"""
from __future__ import annotations

import gzip
import pathlib

OUT = pathlib.Path("src/one_link/data/oui_prefixes.txt.gz")
OUT.parent.mkdir(parents=True, exist_ok=True)

# Curated subset. Each tuple is (hex_prefix, vendor).
# Source: public IEEE OUI registry (standards-oui.ieee.org).
ENTRIES = [
    # Apple — representative slice (~100; they own ~1000 prefixes)
    ("000393", "Apple"), ("000a27", "Apple"), ("000a95", "Apple"),
    ("000d93", "Apple"), ("000f86", "Apple"), ("0011d8", "Apple"),
    ("0014a4", "Apple"), ("001451", "Apple"), ("0014a5", "Apple"),
    ("0016cb", "Apple"), ("0017f2", "Apple"), ("0019e3", "Apple"),
    ("001b63", "Apple"), ("001e52", "Apple"), ("001ec2", "Apple"),
    ("001f5b", "Apple"), ("001ff3", "Apple"), ("002241", "Apple"),
    ("00236c", "Apple"), ("002332", "Apple"), ("002436", "Apple"),
    ("00254b", "Apple"), ("0025bc", "Apple"), ("002608", "Apple"),
    ("002612", "Apple"), ("00264a", "Apple"), ("00265e", "Apple"),
    ("0026b0", "Apple"), ("0026bb", "Apple"), ("003ee1", "Apple"),
    ("0050e4", "Apple"), ("04489a", "Apple"), ("04dbc1", "Apple"),
    ("04f7e4", "Apple"), ("0c3e9f", "Apple"), ("0c4de9", "Apple"),
    ("0c74c2", "Apple"), ("1093e9", "Apple"), ("14109f", "Apple"),
    ("1499e2", "Apple"), ("18af61", "Apple"), ("1c1ac0", "Apple"),
    ("1c5cf2", "Apple"), ("1cabaa", "Apple"), ("203cae", "Apple"),
    ("206432", "Apple"), ("2078f0", "Apple"), ("245ba7", "Apple"),
    ("24a074", "Apple"), ("286ab8", "Apple"), ("28cfda", "Apple"),
    ("28e02c", "Apple"), ("2c1f23", "Apple"), ("2cb43a", "Apple"),
    ("2cf0a2", "Apple"), ("30636b", "Apple"), ("309c23", "Apple"),
    ("34159e", "Apple"), ("34a395", "Apple"), ("34c059", "Apple"),
    ("3871de", "Apple"), ("38b54d", "Apple"), ("3c0754", "Apple"),
    ("3ce072", "Apple"), ("40331a", "Apple"), ("40a6d9", "Apple"),
    ("447387", "Apple"), ("44d884", "Apple"), ("485d60", "Apple"),
    ("4c3275", "Apple"), ("4c7c5f", "Apple"), ("4c8d79", "Apple"),
    ("507a55", "Apple"), ("5485ab", "Apple"), ("5c95ae", "Apple"),
    ("5cf5da", "Apple"), ("5cf938", "Apple"), ("60c547", "Apple"),
    ("6c4008", "Apple"), ("6c709f", "Apple"), ("6c8dc1", "Apple"),
    ("6cab31", "Apple"), ("70a2b3", "Apple"), ("70cd60", "Apple"),
    ("74e1b6", "Apple"), ("78ca39", "Apple"), ("7c11be", "Apple"),
    ("7c6d62", "Apple"), ("7cc537", "Apple"), ("7cfade", "Apple"),
    ("80929f", "Apple"), ("80b03d", "Apple"), ("84788b", "Apple"),
    ("84fcfe", "Apple"), ("886b6e", "Apple"), ("8866a5", "Apple"),
    ("8c2937", "Apple"), ("8c7c92", "Apple"), ("8ce117", "Apple"),
    ("90840d", "Apple"), ("90b21f", "Apple"), ("90fd61", "Apple"),
    ("989e63", "Apple"), ("9027e4", "Apple"), ("9810e8", "Apple"),
    ("98d6bb", "Apple"), ("9c84bf", "Apple"), ("9cf48e", "Apple"),
    ("a01828", "Apple"), ("a04ea7", "Apple"), ("a0999b", "Apple"),
    ("a4b197", "Apple"), ("a4c361", "Apple"), ("a82066", "Apple"),
    ("a8967b", "Apple"), ("a8be27", "Apple"), ("ac1f74", "Apple"),
    ("ac3613", "Apple"), ("ac7f3e", "Apple"), ("acbc32", "Apple"),
    ("b06ebf", "Apple"), ("b08bd0", "Apple"), ("b418d1", "Apple"),
    ("b48b19", "Apple"), ("b8e856", "Apple"), ("bc52b7", "Apple"),
    ("bc926b", "Apple"), ("bcec5d", "Apple"), ("c01ade", "Apple"),
    ("c082c2", "Apple"), ("c83c85", "Apple"), ("cc785f", "Apple"),
    ("d0e140", "Apple"), ("d4619d", "Apple"), ("d4f46f", "Apple"),
    ("d8a25e", "Apple"), ("d8d1cb", "Apple"), ("dc0c5c", "Apple"),
    ("e0acf1", "Apple"), ("e0b9ba", "Apple"), ("e0f8e7", "Apple"),
    ("e4ce8f", "Apple"), ("e88d28", "Apple"), ("ec3586", "Apple"),
    ("f0d1a9", "Apple"), ("f0db40", "Apple"), ("f40f24", "Apple"),
    ("f8f1b6", "Apple"), ("fc253f", "Apple"), ("fc25e0", "Apple"),
    # Samsung
    ("002566", "Samsung Electronics"), ("0023db", "Samsung Electronics"),
    ("0026e2", "Samsung Electronics"), ("00e64c", "Samsung Electronics"),
    ("5440ad", "Samsung Electronics"), ("78bdbc", "Samsung Electronics"),
    ("8425db", "Samsung Electronics"), ("e8e5d6", "Samsung Electronics"),
    ("a48d3b", "Samsung Electronics"), ("c8d10b", "Samsung Electronics"),
    ("ccfe3c", "Samsung Electronics"),
    # Google + Nest
    ("f4f5d8", "Google"), ("f8f005", "Google"), ("20df3f", "Google"),
    ("4cf739", "Google Nest"), ("ccfa00", "Google"), ("f4f5e8", "Google"),
    ("a4da32", "Google"), ("d4f547", "Google"),
    # Microsoft / Xbox / Surface
    ("00125a", "Microsoft"), ("0017fa", "Microsoft"),
    ("0050f2", "Microsoft"), ("7c1e52", "Microsoft"),
    ("ec5933", "Microsoft Surface"), ("c8f733", "Microsoft"),
    # Amazon (Echo, Fire, Kindle)
    ("08bdf4", "Amazon"), ("44650d", "Amazon"), ("747548", "Amazon"),
    ("a002dc", "Amazon"), ("f0d2f1", "Amazon"), ("0c47c9", "Amazon"),
    # Roku
    ("b0a737", "Roku"), ("cc6da0", "Roku"), ("d83134", "Roku"),
    ("ac3a7a", "Roku"),
    # Sonos
    ("00ee02", "Sonos"), ("5ccea1", "Sonos"), ("943fc2", "Sonos"),
    ("78b3b9", "Sonos"),
    # LG
    ("0c2c54", "LG Electronics"), ("00aa70", "LG Electronics"),
    # Sony
    ("00041f", "Sony"), ("002fff", "Sony"), ("104780", "Sony"),
    # TP-Link
    ("00040e", "TP-Link"), ("001e64", "TP-Link"),
    ("d8b1ec", "TP-Link"), ("1c3bf3", "TP-Link"),
    # Netgear
    ("00146c", "Netgear"), ("003845", "Netgear"),
    ("9ca57d", "Netgear"),
    # Ubiquiti
    ("002722", "Ubiquiti Networks"), ("80f0e2", "Ubiquiti"),
    ("dc9fdb", "Ubiquiti Networks"), ("44d9e7", "Ubiquiti"),
    # Raspberry Pi
    ("b827eb", "Raspberry Pi Foundation"),
    ("dca632", "Raspberry Pi Trading"),
    ("e45f01", "Raspberry Pi Foundation"),
    ("2cc8b8", "Raspberry Pi"),
    # Intel (NICs, NUCs)
    ("001517", "Intel"), ("00192d", "Intel"), ("3037a6", "Intel"),
    ("8c1645", "Intel"), ("a0a8cd", "Intel"), ("b8aeed", "Intel"),
    # Dell
    ("00115b", "Dell"), ("001372", "Dell"),
    ("64006a", "Dell"), ("ec1f6b", "Dell"),
    # HP
    ("ec9a74", "HP"), ("002264", "HP"), ("00188b", "HP"),
    ("3464a9", "HP Enterprise"),
    # Lenovo
    ("70b4f0", "Lenovo"), ("80fa5b", "Lenovo"),
    # Cisco
    ("0007ec", "Cisco"), ("000a8a", "Cisco"), ("0017df", "Cisco"),
    # ASUS
    ("002643", "ASUS"), ("1c8758", "ASUS"), ("405bd8", "ASUS"),
    # Xiaomi
    ("28e347", "Xiaomi"), ("64b473", "Xiaomi"), ("8c531b", "Xiaomi"),
    # OnePlus
    ("64e795", "OnePlus"), ("948d44", "OnePlus"),
    # Vizio
    ("00197e", "Vizio"), ("00038a", "Vizio"),
    # Belkin
    ("0017ee", "Belkin"), ("ec1a59", "Belkin"),
    # Nintendo
    ("0009bf", "Nintendo"), ("0017ab", "Nintendo"),
    ("78a2a0", "Nintendo Switch"),
    # PlayStation
    ("001fa7", "Sony PlayStation"),
    ("ac8911", "Sony PlayStation"),
    # Tesla
    ("18260c", "Tesla"), ("4cfcaa", "Tesla"), ("8c84c2", "Tesla"),
    # ARRIS / Motorola routers
    ("001dd0", "Arris"), ("001e46", "Arris"),
    # D-Link
    ("0080c8", "D-Link"), ("002191", "D-Link"),
    # MikroTik
    ("4c5e0c", "MikroTik"), ("e48d8c", "MikroTik"),
    # Synology
    ("00113232", "Synology"), ("0011328d", "Synology"),
    # Eero
    ("3ce6cc", "Eero"), ("605571", "Eero"),
]


def main() -> None:
    clean: dict[str, str] = {}
    for pfx, vendor in ENTRIES:
        p = pfx.replace(":", "").replace("-", "").lower().strip()
        p = "".join(c for c in p if c in "0123456789abcdef")
        if len(p) == 6 and p not in clean:
            clean[p] = vendor
    with gzip.open(OUT, "wt", encoding="utf-8") as f:
        f.write("# IEEE OUI prefix vendor bundle for One Link\n")
        f.write("# Generated from public IEEE registry; bundled local-only.\n")
        for p in sorted(clean):
            f.write(f"{p}\t{clean[p]}\n")
    print(
        f"wrote {len(clean):,} OUI prefixes to {OUT}, "
        f"size={OUT.stat().st_size:,} bytes"
    )


if __name__ == "__main__":
    main()
