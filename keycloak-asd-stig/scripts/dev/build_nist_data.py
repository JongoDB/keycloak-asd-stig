"""Build references/nist-800-53r5.json: ASD CCIs -> NIST SP 800-53 Rev 5 controls (from the DISA CCI list),
control titles (NIST OSCAL catalog) and Low/Moderate/High baselines (NIST OSCAL profiles).
Usage: build_nist_data.py U_CCI_List.xml catalog.json LOW.json MODERATE.json HIGH.json asd-stig-v6r4.json out.json"""
import json, re, sys, xml.etree.ElementTree as ET
cci_xml, cat, lo, mo, hi, rules_p, out = sys.argv[1:8]
ns = {"c": "http://iase.disa.mil/cci"}
need = {c for r in json.load(open(rules_p))["rules"] for c in r["ccis"]}
root = ET.parse(cci_xml).getroot()
ver = root.findtext(".//c:metadata/c:version", namespaces=ns)
def norm(index):
    # "IA-2 (1)" -> ia-2.1 ; "AU-12 c" -> au-12 ; "SC-8 (1)" -> sc-8.1
    m = re.match(r"([A-Z]{2})-(\d+)(?:\s*\((\d+)\))?", index.strip())
    return (m.group(1).lower() + "-" + m.group(2) + ("." + m.group(3) if m.group(3) else "")) if m else None
cci = {}
for it in root.iterfind(".//c:cci_item", ns):
    cid = it.get("id")
    if cid not in need:
        continue
    refs = [f.get("index") for f in it.iterfind(".//c:reference", ns) if f.get("version") == "5"]
    rev4 = [f.get("index") for f in it.iterfind(".//c:reference", ns) if f.get("version") == "4"]
    cci[cid] = {"definition": it.findtext("c:definition", namespaces=ns), "rev5": refs, "rev4": rev4,
                "controls": sorted({norm(x) for x in refs if norm(x)}),
                # no Rev 5 reference in the DISA list: control withdrawn/incorporated in Rev 5; keep the Rev 4 id, flagged
                "rev4_only": sorted({norm(x) for x in rev4 if norm(x)}) if not refs else []}
catalog = json.load(open(cat))["catalog"]
titles, fam = {}, {}
def walk(ctrls, family):
    for c in ctrls or []:
        titles[c["id"]] = c["title"]; fam[c["id"]] = family
        walk(c.get("controls"), family)
for g in catalog["groups"]:
    walk(g.get("controls"), g["title"])
base = {}
for name, p in (("L", lo), ("M", mo), ("H", hi)):
    d = json.load(open(p))["profile"]
    for imp in d["imports"]:
        for inc in imp.get("include-controls", []):
            for i in inc.get("with-ids", []):
                base.setdefault(i, []).append(name)
ctrl_ids = sorted({c for v in cci.values() for c in v["controls"]})
data = {"sources": {"cci_list": "DISA U_CCI_List.xml version %s" % ver,
                    "catalog": catalog["metadata"]["title"] + " " + catalog["metadata"].get("version", ""),
                    "baselines": "NIST SP 800-53B Rev 5 OSCAL profiles (LOW/MODERATE/HIGH)"},
        "cci": cci,
        "controls": {c: {"title": titles.get(c, "?"), "family": fam.get(c, "?"), "baselines": base.get(c, [])} for c in ctrl_ids}}
json.dump(data, open(out, "w"), indent=1)
missing = ["%s (rev4 %s)" % (c, cci[c]["rev4"]) for c in need if c in cci and not cci[c]["controls"]]
print(len(cci), "CCIs,", len(ctrl_ids), "controls; CCIs without a Rev5 mapping:", missing)
