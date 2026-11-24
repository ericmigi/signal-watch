#!/usr/bin/env python3
"""Generate lib/Fieldwatch/FieldwatchCatalog.inc from Fieldwatch's signature catalog.

Source: https://github.com/OffGridPete/Fieldwatch (MIT, Copyright (c) 2026 Off Grid Pete LLC)
  app/src/main/java/app/fieldwatch/domain/DefaultCatalog.kt
  app/src/main/java/app/fieldwatch/domain/ApVendorOuis.kt

Usage: gen_fieldwatch_catalog.py <DefaultCatalog.kt> <ApVendorOuis.kt> <out.inc>
"""
import re
import sys

ALERT_CLASSES = {"DRONE"}  # plus every row with an attentionNote (Fieldwatch's default watchlist)

RULE_FNS = {
    # name: (kind, radio, arg shape)
    "oui": ("OUI", "ANY", "s"),
    "wifiOui": ("OUI", "WIFI", "s"),
    "vendorIe": ("VIE", "WIFI", "s"),
    "name": ("NAME", "ANY", "s"),
    "bleName": ("NAME", "BLE", "s"),
    "wifiName": ("NAME", "WIFI", "s"),
    "glob": ("GLOB", "ANY", "s"),
    "bleGlob": ("GLOB", "BLE", "s"),
    "wifiGlob": ("GLOB", "WIFI", "s"),
    "uuid": ("UUID", "BLE", "s"),
    "bleUuid": ("UUID", "BLE", "s"),
    "mfg": ("MFG", "BLE", "i"),
    "bleMfg": ("MFG", "BLE", "i"),
    "mfgData": ("MFGDATA", "BLE", "is"),
    "bleMfgData": ("MFGDATA", "BLE", "is"),
    "svcData": ("SVCDATA", "BLE", "ss"),
    "svcAny": ("SVCDATA", "BLE", "s"),
    "svcContainsAscii": ("SVCASCII", "BLE", "s"),
}


def find_block(text, start):
    """Return index just past the paren that closes the one opened at text[start]."""
    depth = 0
    i = start
    in_str = False
    while i < len(text):
        c = text[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise ValueError("unbalanced")


def string_lists(text):
    out = {}
    for m in re.finditer(r"val ([A-Z_]+)\s*=\s*listOf\(", text):
        end = find_block(text, m.end() - 1)
        out[m.group(1)] = re.findall(r'"([^"]*)"', text[m.end():end])
    return out


def string_consts(text):
    return dict(re.findall(r'const val ([A-Z_]+)\s*=\s*"([^"]*)"', text))


def parse_int(s):
    s = s.strip().replace("_", "")
    return int(s, 16) if s.lower().startswith("0x") else int(s)


def norm_hex(s):
    return re.sub(r"[^0-9A-Fa-f]", "", s).upper()


def norm_uuid(s):
    h = norm_hex(s)
    if len(h) == 32 and h[:4] == "0000" and h[8:] == "00001000800000805F9B34FB":
        h = h[4:8]
    return h


def make_rule(fn, args, consts):
    kind, radio, shape = RULE_FNS[fn]
    vals = []
    for a, t in zip(args, shape):
        a = a.strip()
        if t == "i":
            vals.append(parse_int(a))
        else:
            if a in consts:
                a = consts[a]
            elif a.startswith('"'):
                a = a.strip('"')
            else:
                raise ValueError(f"unresolved arg {a!r} in {fn}")
            vals.append(a)
    if kind in ("OUI", "VIE"):
        return (kind, radio, 0, norm_hex(vals[0]), "")
    if kind in ("NAME", "GLOB"):
        return (kind, radio, 0, vals[0], "")
    if kind == "UUID":
        return (kind, radio, 0, norm_uuid(vals[0]), "")
    if kind == "MFG":
        return (kind, radio, vals[0], "", "")
    if kind == "MFGDATA":
        return (kind, radio, vals[0], norm_hex(vals[1]), "")
    if kind == "SVCDATA":
        return (kind, radio, 0, norm_uuid(vals[0]), norm_hex(vals[1]) if len(vals) > 1 else "")
    if kind == "SVCASCII":
        return ("SVCDATA", radio, 0, "", vals[0].encode().hex().upper())
    raise ValueError(kind)


CALL_RE = re.compile(r"\b(" + "|".join(sorted(RULE_FNS, key=len, reverse=True)) + r')\(((?:"[^"]*"|[^()"])*)\)')


def split_args(s):
    return [a for a in re.findall(r'"[^"]*"|[^,]+', s) if a.strip()]


MATCHRULE_KINDS = {
    "OUI": "OUI",
    "MAC_PREFIX": "OUI",
    "VENDOR_IE_OUI": "VIE",
    "NAME_CONTAINS": "NAME",
    "NAME_GLOB": "GLOB",
    "SERVICE_UUID": "UUID",
    "MANUFACTURER_ID": "MFG",
    "MANUFACTURER_DATA": "MFGDATA",
    "SERVICE_DATA": "SVCDATA",
}


def match_rule(args, consts):
    """A direct MatchRule(RuleKind.X, text = .., companyId = .., dataPrefixHex = .., radio = ..)."""
    kind = re.match(r"\s*RuleKind\.(\w+)", args).group(1)
    if kind not in MATCHRULE_KINDS:
        raise ValueError(f"unsupported RuleKind.{kind}")
    named = dict(re.findall(r'(\w+)\s*=\s*("[^"]*"|[\w.]+)', args))
    text = named.get("text", '""')
    text = consts.get(text, text).strip('"')
    prefix = named.get("dataPrefixHex", '""')
    prefix = consts.get(prefix, prefix).strip('"')
    company = parse_int(named["companyId"]) if "companyId" in named else 0
    radio = named.get("radio", "")
    radio = "BLE" if radio.endswith("BLE") else "WIFI" if radio.endswith("WIFI") else None
    k = MATCHRULE_KINDS[kind]
    default_radio = "BLE" if k in ("UUID", "MFG", "MFGDATA", "SVCDATA") else "WIFI" if k == "VIE" else "ANY"
    radio = radio or default_radio
    if k in ("OUI", "VIE"):
        return (k, radio, 0, norm_hex(text), "")
    if k in ("NAME", "GLOB"):
        return (k, radio, 0, text, "")
    if k == "UUID":
        return (k, radio, 0, norm_uuid(text), "")
    if k == "MFG":
        return (k, radio, company, "", "")
    if k == "MFGDATA":
        return (k, radio, company, norm_hex(prefix), "")
    return ("SVCDATA", radio, 0, norm_uuid(text), norm_hex(prefix))


def rules_of(body, consts, lists, ouis, fleet):
    """Every rule in a fleet's `rules = ...` expression. Fails on anything it does not consume."""
    body = re.sub(r"(?m)(^|\s)//[^\n]*$", r"\1", body)  # line comments
    rules = []
    consumed = []  # spans of `body` turned into rules

    def take(m):
        consumed.append(m.span())

    for m in re.finditer(r"listOf\(([^()]*)\)\s*\.forEach\s*\{\s*add\((\w+)\(it\)\)\s*\}", body):
        for s_ in re.findall(r'"([^"]*)"', m.group(1)):
            rules.append(make_rule(m.group(2), [f'"{s_}"'], consts))
        take(m)
    for m in re.finditer(r"(\w+(?:\.\w+)?)\.map\s*\{\s*(\w+)\(([^()]*)\)\s*\}", body):
        src = m.group(1).split(".")[-1]
        items = lists.get(src) or ouis.get(src)
        if items is None:
            raise ValueError(f"{fleet}: unknown list {m.group(1)}")
        for s_ in items:
            args = [f'"{s_}"' if a.strip() == "it" else a.strip() for a in split_args(m.group(3))]
            rules.append(make_rule(m.group(2), args, consts))
        take(m)
    # withWifiOuis(base, listOf("AA:BB:CC", ...)): a literal OUI list as the second argument.
    for m in re.finditer(r"withWifiOuis\(", body):
        end = find_block(body, m.end() - 1)
        tail = re.search(r',\s*listOf\(((?:\s*"[^"]*",?)+)\s*\)\s*,?\s*\)$', body[m.start():end])
        if tail:
            for s_ in re.findall(r'"([^"]*)"', tail.group(1)):
                rules.append(("OUI", "WIFI", 0, norm_hex(s_), ""))
            consumed.append((m.start() + tail.start(), end))
    for m in re.finditer(r"ApVendorOuis\.([A-Z_]+)", body):
        if any(a <= m.start() < b for a, b in consumed):
            continue
        for s_ in ouis[m.group(1)]:
            rules.append(("OUI", "WIFI", 0, norm_hex(s_), ""))
        take(m)
    for m in re.finditer(r"MatchRule\(", body):
        end = find_block(body, m.end() - 1)
        rules.append(match_rule(body[m.end():end - 1], consts))
        consumed.append((m.start(), end))
    for m in CALL_RE.finditer(body):
        if any(a <= m.start() < b for a, b in consumed):
            continue
        rules.append(make_rule(m.group(1), split_args(m.group(2)), consts))
        take(m)

    # Anything left besides list plumbing is a rule form this script does not know.
    rest = list(body)
    for a, b in consumed:
        rest[a:b] = " " * (b - a)
    leftover = re.sub(r"\b(listOf|buildList|add|withWifiOuis|emptyList)\b|[\s(){},+]", "", "".join(rest))
    if leftover:
        raise ValueError(f"{fleet}: unparsed rule text {leftover[:80]!r}")
    if not rules:
        raise ValueError(f"{fleet}: no rules")
    return rules


def main():
    catalog = open(sys.argv[1], encoding="utf-8").read()
    ouis = string_lists(open(sys.argv[2], encoding="utf-8").read())
    consts = string_consts(catalog)
    lists = string_lists(catalog)

    head = "fun fleets(): List<Fleet> = listOf("
    order_start = catalog.index(head) + len(head) - 1
    order_end = find_block(catalog, order_start)
    order = re.findall(r"(\w+)\(\)", catalog[order_start:order_end])

    fleets = []
    for fn in order:
        m = re.search(r"private fun " + fn + r"\(\) = (Fleet|oemVehicle|radioMic)\(", catalog)
        if not m:
            raise ValueError(f"fleet {fn} not found")
        end = find_block(catalog, m.end() - 1)
        block = catalog[m.end():end]
        helper = m.group(1)
        if helper == "radioMic":  # radioMic(id, name, opener, pattern): one BLE name glob, Two Way
            args = re.findall(r'"([^"]*)"', block)
            name, cls, match_any, attention = args[1], "TWO_WAY", True, False
            rules = [("GLOB", "BLE", 0, args[3], "")]
        else:
            name = re.search(r'\bname = "([^"]*)"', block).group(1)
            cls = "VEHICLE" if helper == "oemVehicle" else re.search(r"kind = SignatureClass\.(\w+)", block).group(1)
            match_any = "matchAny = false" not in block
            attention = re.search(r'attentionNote = "[^"]', block) is not None
            rm = re.search(r"\brules = ", block)
            rules_expr = block[rm.end():]
            # The rules expression ends at the next top-level named argument, or the block end.
            nxt = re.search(r",\n\s{8}\w+ = ", rules_expr)
            rules = rules_of(rules_expr[: nxt.start()] if nxt else rules_expr, consts, lists, ouis, name)
        # De-duplicate, keep order.
        seen = set()
        rules = [r for r in rules if not (r in seen or seen.add(r))]
        if True:
            fleets.append((name, cls, match_any, attention or cls in ALERT_CLASSES, rules))

    classes = sorted({f[1] for f in fleets})
    # 24-bit OUIs go to one sorted table (binary search): OUI << 8 | wifiOnly << 7 | OUI-fleet slot.
    oui_fleets = []
    ouis = {}
    def in_table(match_any, kind, a):  # match-all fleets keep their OUIs as ordinary rules
        return match_any and kind == "OUI" and len(a) == 6

    for fi, (_, _, match_any, _, rules) in enumerate(fleets):
        for kind, radio, _, a, _ in rules:
            if not in_table(match_any, kind, a) or a in ouis:
                continue
            if fi not in oui_fleets:
                oui_fleets.append(fi)
            ouis[a] = (int(a, 16) << 8) | (0x80 if radio == "WIFI" else 0) | oui_fleets.index(fi)
    if len(oui_fleets) > 127:
        raise ValueError("too many OUI fleets for 7-bit slot")

    out = []
    out.append("// Generated by scripts/gen_fieldwatch_catalog.py. Do not edit.")
    out.append("// Signature catalog from Fieldwatch (https://github.com/OffGridPete/Fieldwatch),")
    out.append("// MIT License, Copyright (c) 2026 Off Grid Pete LLC.")
    nrules = sum(1 for f in fleets for r in f[4] if not in_table(f[2], r[0], r[3]))
    out.append(f"// {len(fleets)} signatures, {nrules} rules, {len(ouis)} OUIs.")
    out.append("")
    out.append("static const char* const kClassNames[] = {" + ", ".join(f'"{c.replace("_", " ").title()}"' for c in classes) + "};")
    out.append("")
    out.append("static const uint16_t kOuiFleets[] = {" + ", ".join(str(f) for f in oui_fleets) + "};")
    out.append("")
    out.append("static const uint32_t kOuis[] = {")
    vals = sorted(ouis.values())
    for k in range(0, len(vals), 8):
        out.append("    " + ", ".join(f"0x{v:08X}" for v in vals[k:k + 8]) + ",")
    out.append("};")
    out.append("")
    out.append("static const CatalogRule kRules[] = {")
    first = 0
    fleet_rows = []
    for name, cls, match_any, alert, rules in fleets:
        count = 0
        for kind, radio, num, a, b in rules:
            if in_table(match_any, kind, a):
                continue
            text = f"{a}:{b}" if kind == "SVCDATA" else a
            text = text.replace("\\", "\\\\").replace('"', '\\"')
            text = text.replace("?", "\\?")  # no trigraphs
            out.append(f'    {{RuleKind::{kind}, RuleRadio::{radio}, 0x{num:04X}, "{text}"}},')
            count += 1
        fleet_rows.append((name, first, count, match_any, alert, cls))
        first += count
    out.append("};")
    out.append("")
    out.append("static const CatalogFleet kFleets[] = {")
    for name, first, count, match_any, alert, cls in fleet_rows:
        flags = []
        if match_any:
            flags.append("kFleetMatchAny")
        if alert:
            flags.append("kFleetAlert")
        name_esc = name.replace('"', '\\"')
        out.append(f'    {{"{name_esc}", {first}, {count}, {"|".join(flags) or "0"}, {classes.index(cls)}}},')
    out.append("};")
    open(sys.argv[3], "w", encoding="utf-8").write("\n".join(out) + "\n")
    print(f"{len(fleets)} fleets, {nrules} rules, {len(ouis)} OUIs, {len(classes)} classes")

if __name__ == "__main__":
    main()
