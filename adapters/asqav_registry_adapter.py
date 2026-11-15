"""Adapter: Asqav Compliance Receipts registries (jagmarques/asqav-registry), re-derived from REGISTRATION.md and CHANGELOG.md.

Reads the checkout named by argument 1 and recomputes, with none of their validate.py:
  manifest      registry/MANIFEST.sha256: SHA-256 of each listed file
  entries       REGISTRATION.md review criteria: field names lowercase ASCII letters, digits and underscore; namespaces
                lowercase letters, digits, hyphen, underscore and colon; no duplicates; the three scope tags; every entry
                names a reference and a change controller
  reservation   protectmcp and its sub-namespaces carry the defining document's change controller; a parent:suffix
                sub-namespace names a registered parent and inherits that parent's change controller
  stability     "never removed, never renamed": every entry of registry/previous.json survives with the same scope and
                change controller
  changelog     both registries carry one version; CHANGELOG.md has an entry for it that states the entry counts
  wire          vocabulary/wire.json receipt_types equals the registered namespaces; which of its field names are registered is reported
Prints one line per check; exit 0 iff all agree.
"""
import collections
import hashlib
import json
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
reg = root / "registry"
fields = json.loads((reg / "extension-fields.json").read_text())
spaces = json.loads((reg / "type-namespaces.json").read_text())
prev = json.loads((reg / "previous.json").read_text())
changelog = (root / "CHANGELOG.md").read_text()
wire = json.loads((root / "vocabulary/wire.json").read_text())
results = []


def check(name, ok, detail):
    results.append(ok)
    print(("AGREE" if ok else "DIFF ") + " %s: %s" % (name, detail))


bad = []
lines = (reg / "MANIFEST.sha256").read_text().splitlines()
for line in lines:
    h, p = line.split("  ", 1)
    if hashlib.sha256((root / p).read_bytes()).hexdigest() != h:
        bad.append(p)
check("manifest", not bad, "%d listed files, %d digests differ %s" % (len(lines), len(bad), bad))

fe, ne = fields["entries"], spaces["entries"]
scopes = {"signed-payload", "envelope-level", "signing-time declaration"}
problems = []
names = [e["field_name"] for e in fe]
if len(set(names)) != len(names):
    problems.append("duplicate field_name")
problems += ["field name %r" % n for n in names if not re.fullmatch(r"[a-z0-9_]+", n)]
problems += ["scope %r on %s" % (e["scope"], e["field_name"]) for e in fe if e["scope"] not in scopes]
nsn = [e["namespace"] for e in ne]
if len(set(nsn)) != len(nsn):
    problems.append("duplicate namespace")
problems += ["namespace %r" % n for n in nsn if not re.fullmatch(r"[a-z0-9_:-]+", n)]
problems += ["%s lacks reference or controller" % (e.get("field_name") or e.get("namespace"))
             for e in fe + ne if not e.get("reference", "").strip() or not e.get("change_controller", "").strip()]
check("entries", not problems, "%d extension fields (%s), %d type namespaces; problems %s"
      % (len(fe), ", ".join("%d %s" % (v, k) for k, v in sorted(collections.Counter(e["scope"] for e in fe).items())),
         len(ne), problems))

ctrl = {e["namespace"]: e["change_controller"] for e in ne}
problems = []
for n, c in ctrl.items():
    if n.split(":")[0] == "protectmcp" and c != "Asqav":
        problems.append("%s controller %r" % (n, c))
    if n.count(":") >= 2:
        parent = n.rsplit(":", 1)[0]
        if parent not in ctrl:
            problems.append("%s has no registered parent" % n)
        elif ctrl[parent] != c:
            problems.append("%s controller %r differs from parent's %r" % (n, c, ctrl[parent]))
check("reservation", not problems, "%d namespaces, all under protectmcp; problems %s" % (len(ctrl), problems))

problems = []
for fname, key, doc in (("extension-fields.json", "field_name", fe), ("type-namespaces.json", "namespace", ne)):
    cur = {e[key]: e for e in doc}
    for old in prev[fname]["entries"]:
        new = cur.get(old[key])
        if new is None:
            problems.append("%s removed or renamed" % old[key])
        else:
            for a in ("scope", "change_controller"):
                if old.get(a) != new.get(a):
                    problems.append("%s %s changed" % (old[key], a))
check("stability", not problems, "previous.json (version %s, %d fields, %d namespaces) survives; problems %s"
      % (prev["extension-fields.json"]["version"], len(prev["extension-fields.json"]["entries"]),
         len(prev["type-namespaces.json"]["entries"]), problems))

v = fields["version"]
m = re.search(r"## \[%s\] - (\S+)\n\n- \*\*(\d+) extension fields\*\*" % re.escape(v), changelog)
ok = fields["version"] == spaces["version"] and bool(m) and int(m.group(2)) == len(fe) and m.group(1) == fields["updated"] == spaces["updated"]
check("changelog", ok, "version %s on both registries; CHANGELOG entry %s states %s extension fields and date %s; file has %d, updated %s"
      % (v, "found" if m else "NOT found", m and m.group(2), m and m.group(1), len(fe), fields["updated"]))

reg_names = set(names)
wire_fields = set(wire["fields"]) | set(wire["metadata"])
problems = []
if set(wire["receipt_types"]) != set(nsn):
    problems.append("receipt_types differ: %s" % sorted(set(wire["receipt_types"]) ^ set(nsn)))
missing = sorted(wire_fields - reg_names)
check("wire", not problems, "wire.json lists %d receipt types (equal to the registered namespaces: %s); problems %s"
      % (len(wire["receipt_types"]), set(wire["receipt_types"]) == set(nsn), problems))
print("OBSERVE wire.json describes %d field names; %d are registered extension fields and %d are not: %s. Neither document says a wire.json field must be registered (vocabulary/README.md: 'Listing a field here does not establish support in every SDK or route'), so this is reported and not scored."
      % (len(wire_fields), len(wire_fields) - len(missing), len(missing), missing))

print("SUMMARY %d of %d agree" % (sum(results), len(results)))
sys.exit(0 if all(results) else 1)
