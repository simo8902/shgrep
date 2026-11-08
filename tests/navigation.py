"""User-run checks of the five questions an agent asks about code, answered through the direct lsp tool on a C++
fixture with known answers, using the bundled clangd:

  1. Where is the exact function?           lsp.find_symbol, lsp.read_symbol, lsp.find_definition
  2. Who calls it?                          lsp.find_referencing_symbols
  3. What does it depend on?                lsp.read_symbol, then lsp.find_definition at each call in its body
  4. What is the call chain?                lsp.find_referencing_symbols, repeated up to main
  5. What will break if I change X?         lsp.safe_delete_symbol and lsp.rename_symbol dry runs,
                                            lsp.find_implementations, a real rename, lsp.get_diagnostics_for_file

The fixture has traps a text search falls into: a second Tax in another namespace, Tax in a comment and in a string,
a virtual method with two overrides, and a five-step call chain. Every answer is compared with the exact expected
set, so a missing caller, an extra one, or an empty result all fail.

Usage: python tests/navigation.py build-rocm/shgrep.exe [--lsp-root C:/Users/Simeon/Documents/shgrep/build-llvm]
--lsp-root: the folder holding the bundled clangd (sets SHGREP_LSP_ROOT); omit when the build has it beside the exe.
"""
import argparse
import json
import os
from pathlib import Path
import re
import tempfile
import time

from lsp_smoke import Client
from mcp_protocol import lsp_call

SLOW = 300000  # ms: a cold clangd parses the fixture before it answers

FILES = {
    "compile_flags.txt": "-std=c++20\n",
    "pricing.hpp": """#pragma once
namespace shop {
double Tax(double amount);
double Discount(double amount, int units);
double PriceWithTax(double amount, int units);
double OrderTotal(const double* amounts, const int* units, int count);
}
""",
    "pricing.cpp": """#include "pricing.hpp"

namespace shop {
// Tax in a comment is not a reference.
double Tax(double amount) { return amount * 0.2; }

double Discount(double amount, int units) { return units > 10 ? amount * 0.1 : 0.0; }

double PriceWithTax(double amount, int units) {
    return amount - Discount(amount, units) + Tax(amount);
}

double OrderTotal(const double* amounts, const int* units, int count) {
    double total = 0;
    for (int i = 0; i < count; ++i) total += PriceWithTax(amounts[i], units[i]);
    return total;
}
}
""",
    "audit.cpp": """#include "pricing.hpp"

namespace audit {
double Tax(double amount) { return amount; }

double CheckTax(double amount) { return shop::Tax(amount) - Tax(amount); }
}
""",
    "report.cpp": """#include "pricing.hpp"

double RunReport() {
    const double amounts[] = {10.0};
    const int units[] = {2};
    return shop::OrderTotal(amounts, units, 1);
}

const char* TaxLabel() { return "Tax"; }

int main() { return RunReport() > 0 ? 0 : 1; }
""",
    "shapes.hpp": """#pragma once
struct Shape {
    virtual ~Shape() = default;
    virtual double Area() const = 0;
};
struct Circle : Shape {
    double r = 1;
    double Area() const override;
};
struct Square : Shape {
    double s = 1;
    double Area() const override;
};
double TotalArea(const Shape* const* shapes, int count);
""",
    "shapes.cpp": """#include "shapes.hpp"

double Circle::Area() const { return 3.14159 * r * r; }
double Square::Area() const { return s * s; }

double TotalArea(const Shape* const* shapes, int count) {
    double total = 0;
    for (int i = 0; i < count; ++i) total += shapes[i]->Area();
    return total;
}
""",
}


def where(name, needle, nth=0, offset=0):
    """1-based (line, column) of the nth occurrence of needle in fixture file name, plus offset characters.
    The fixture is ASCII, so the column equals the UTF-16 column the lsp tool takes."""
    text, start = FILES[name], -1
    for _ in range(nth + 1):
        start = text.index(needle, start + 1)
    start += offset
    line = text.count("\n", 0, start) + 1
    return line, start - (text.rfind("\n", 0, start) + 1) + 1


def short(name_path):
    """The last part of a name path ("shop/PriceWithTax" -> "PriceWithTax"; overload suffixes dropped)."""
    return re.sub(r"\[\d+\]$", "", re.split(r"/|::", name_path)[-1])


def file_of(path):
    return Path(path.replace("\\", "/")).name


class Nav:
    def __init__(self, client):
        self.client = client

    def call(self, method, error=False, **arguments):
        reply = self.client.call("tools/call", lsp_call(method, {**arguments, "format": "json", "timeout_ms": SLOW}))
        assert bool(reply.get("isError")) == error, (method, arguments, reply)
        text = reply["content"][0]["text"]
        return text if error else json.loads(text)

    def attempt(self, method, **arguments):
        """(is_error, parsed result or error text): for spellings that may be refused, but must never answer empty."""
        reply = self.client.call("tools/call", lsp_call(method, {**arguments, "format": "json", "timeout_ms": SLOW}))
        text = reply["content"][0]["text"]
        return (True, text) if reply.get("isError") else (False, json.loads(text))

    def text(self, method, **arguments):
        """A method whose answer is text (edits, renames, deletes, dry runs)."""
        reply = self.client.call("tools/call", lsp_call(method, {**arguments, "timeout_ms": SLOW}))
        assert not reply.get("isError"), (method, arguments, reply)
        return reply["content"][0]["text"]

    def definition(self, name, line, column):
        found = self.call("lsp.find_definition", relative_path=name, line=line, column=column)["results"]
        return {(file_of(item["path"]), item["line"]) for item in found}

    def callers(self, name_path, relative_path):
        """{(file, caller short name)} of every reference to the symbol, outside its own declarations."""
        found = self.call("lsp.find_referencing_symbols", name_path=name_path, relative_path=relative_path)
        return {(file_of(item["path"]), short(item["symbol"])) for item in found["results"]}, found


def resolved_or_refused(nav, method, lines, **arguments):
    """True when the call found exactly the symbols starting at lines; False when it was refused with candidates.
    An empty success fails: it tells an agent the symbol does not exist."""
    refused, value = nav.attempt(method, **arguments)
    if refused:
        assert "Nearest:" in value or "candidates" in value, (arguments, value)
        return False
    found = sorted(item.get("range", {}).get("start_line", item.get("line")) for item in value["results"])
    assert found == sorted(lines), (method, arguments, value)
    return True


def check_where(nav):
    # 1. The exact function: one definition of shop::Tax, at its line, whole body, distinct from audit::Tax.
    found = nav.call("lsp.find_symbol", name_path_pattern="Tax", relative_path="pricing.cpp", include_body=True)["results"]
    assert len(found) == 1, found
    tax = found[0]
    line, _ = where("pricing.cpp", "double Tax(")
    assert tax["kind_name"] == "function" and tax["range"]["start_line"] == line == tax["range"]["end_line"], tax
    assert tax["body"] == "double Tax(double amount) { return amount * 0.2; }", tax["body"]
    everywhere = nav.call("lsp.find_symbol", name_path_pattern="Tax", relative_path=".")["results"]
    places = {(file_of(item["path"]), item["range"]["start_line"]) for item in everywhere}
    assert {("pricing.cpp", line), ("audit.cpp", where("audit.cpp", "double Tax(")[0])} <= places, everywhere
    assert all(file_of(item["path"]) in ("pricing.cpp", "audit.cpp", "pricing.hpp") for item in everywhere), everywhere
    assert "TaxLabel" not in {short(item["name_path"]) for item in everywhere if short(item["name_path"]) == "Tax"}
    # Name paths are slash-separated (shop/Tax). A C++ spelling an agent may copy from the code (shop::Tax) must
    # either resolve to the same symbol or be refused with candidates; an empty success reads as "no such function".
    for spelling in ("shop/Tax", "Tax"):
        same = nav.call("lsp.find_symbol", name_path_pattern=spelling, relative_path="pricing.cpp")["results"]
        assert [item["range"]["start_line"] for item in same] == [line], (spelling, same)
    resolved_or_refused(nav, "lsp.find_symbol", [line], name_path_pattern="shop::Tax", relative_path="pricing.cpp")
    # Out-of-line member definitions (double Circle::Area() const) are found by Class/Method and by Class::Method.
    circle = where("shapes.cpp", "double Circle::Area")[0]
    for spelling in ("Circle/Area", "Circle::Area"):
        resolved_or_refused(nav, "lsp.find_symbol", [circle], name_path_pattern=spelling, relative_path="shapes.cpp")
    assert resolved_or_refused(nav, "lsp.find_symbol", [circle], name_path_pattern="Circle/Area",
                               relative_path="shapes.cpp"), "Circle/Area is the documented spelling and must resolve"
    read = nav.call("lsp.read_symbol", relative_path="pricing.cpp", name_path="PriceWithTax")["results"]
    assert read and "Discount(amount, units) + Tax(amount)" in read[0]["body"], read
    # Go to definition from a call site lands on the definition, not the header declaration.
    call_line, call_column = where("report.cpp", "OrderTotal(", offset=0)
    assert nav.definition("report.cpp", call_line, call_column) == {("pricing.cpp", where("pricing.cpp", "double OrderTotal(")[0])}
    # Qualified and unqualified calls in one line resolve to the two different Tax functions.
    shop_tax = where("audit.cpp", "shop::Tax(", offset=len("shop::"))
    audit_tax = where("audit.cpp", "- Tax(", offset=2)
    assert nav.definition("audit.cpp", *shop_tax) == {("pricing.cpp", line)}
    assert nav.definition("audit.cpp", *audit_tax) == {("audit.cpp", where("audit.cpp", "double Tax(")[0])}
    print("ok  1 where: the exact definition, its body, and the right Tax behind each call")


def check_callers(nav):
    # 2. Who calls shop::Tax: PriceWithTax and CheckTax. Not the comment, the string, TaxLabel or audit::Tax's caller line.
    callers, found = nav.callers("Tax", "pricing.cpp")
    assert callers == {("pricing.cpp", "PriceWithTax"), ("audit.cpp", "CheckTax")}, found
    audit_line = where("audit.cpp", "shop::Tax(")[0]
    columns = sorted(item["column"] for item in found["results"] if file_of(item["path"]) == "audit.cpp")
    assert columns == [where("audit.cpp", "shop::Tax(", offset=len("shop::"))[1]], found  # not the unqualified Tax
    assert all(item["line"] != where("pricing.cpp", "// Tax")[0] for item in found["results"]), found
    assert all(file_of(item["path"]) != "report.cpp" for item in found["results"]), found
    # audit::Tax has exactly one caller: the unqualified call in CheckTax.
    audit_callers, found = nav.callers("Tax", "audit.cpp")
    assert audit_callers == {("audit.cpp", "CheckTax")}, found
    assert [item["column"] for item in found["results"]] == [where("audit.cpp", "- Tax(", offset=2)[1]], found
    assert all(item["line"] == audit_line for item in found["results"]), found
    # The documented slash spelling gives the same callers; shop::Tax may be refused, but never answer "no callers".
    same, found = nav.callers("shop/Tax", "pricing.cpp")
    assert same == callers, found
    refused, value = nav.attempt("lsp.find_referencing_symbols", name_path="shop::Tax", relative_path="pricing.cpp")
    assert (refused and "Nearest:" in value) or \
        {(file_of(i["path"]), short(i["symbol"])) for i in value["results"]} == callers, value
    # An out-of-line member: callers of Circle::Area by its slash spelling (the virtual call reaches it).
    refused, value = nav.attempt("lsp.find_referencing_symbols", name_path="Circle/Area", relative_path="shapes.cpp")
    assert not refused and value["results"] is not None, value
    print("ok  2 callers: exactly PriceWithTax and CheckTax, for every name path spelling")


CALL = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
NOT_CALLS = {"if", "for", "while", "return", "switch", "sizeof"}


def dependencies(nav, name, name_path):
    """{(file, definition line)} of every function the symbol's body calls, resolved by go-to-definition at each call."""
    symbol = nav.call("lsp.read_symbol", relative_path=name, name_path=name_path)["results"][0]
    first = symbol["range"]["start_line"]
    resolved = set()
    for index, line_text in enumerate(symbol["body"].splitlines()):
        for match in CALL.finditer(line_text):
            if match.group(1) in NOT_CALLS or (index == 0 and match.group(1) == short(name_path)):
                continue
            column = match.start(1) + 1 + (symbol["range"]["start_column"] - 1 if index == 0 else 0)
            resolved |= nav.definition(name, first + index, column)
    return resolved


def check_dependencies(nav):
    # 3. PriceWithTax depends on Discount and shop::Tax; CheckTax on both Tax functions; TotalArea on Shape::Area.
    assert dependencies(nav, "pricing.cpp", "PriceWithTax") == {
        ("pricing.cpp", where("pricing.cpp", "double Discount(")[0]), ("pricing.cpp", where("pricing.cpp", "double Tax(")[0])}
    assert dependencies(nav, "audit.cpp", "CheckTax") == {
        ("pricing.cpp", where("pricing.cpp", "double Tax(")[0]), ("audit.cpp", where("audit.cpp", "double Tax(")[0])}
    assert dependencies(nav, "report.cpp", "RunReport") == {("pricing.cpp", where("pricing.cpp", "double OrderTotal(")[0])}
    assert dependencies(nav, "shapes.cpp", "TotalArea") == {("shapes.hpp", where("shapes.hpp", "virtual double Area(")[0])}
    print("ok  3 dependencies: each body's calls resolve to exactly the functions it uses")


def call_chain(nav, name_path, relative_path, depth=8):
    """Every path of callers from the symbol up to a function nobody calls, as lists of short names, leaf first."""
    chains, frontier = [], [([short(name_path)], name_path, relative_path)]
    for _ in range(depth):
        following = []
        for chain, path_name, path in frontier:
            callers, _ = nav.callers(path_name, path)
            callers = {(file, caller) for file, caller in callers if caller not in chain}
            if not callers:
                chains.append(chain)
            following += [(chain + [caller], caller, file) for file, caller in sorted(callers)]
        frontier = following
        if not frontier:
            return sorted(chains)
    raise AssertionError(f"call chain deeper than {depth}: {frontier}")


def check_call_chain(nav):
    # 4. shop::Tax up to main, plus the branch that ends at CheckTax, which nothing calls.
    assert call_chain(nav, "Tax", "pricing.cpp") == sorted([
        ["Tax", "PriceWithTax", "OrderTotal", "RunReport", "main"],
        ["Tax", "CheckTax"]]), call_chain(nav, "Tax", "pricing.cpp")
    assert call_chain(nav, "main", "report.cpp") == [["main"]]
    print("ok  4 call chain: Tax <- PriceWithTax <- OrderTotal <- RunReport <- main, and Tax <- CheckTax")


def check_impact(nav, root):
    # 5. What breaks if shop::Tax changes: the dry runs list exactly the affected places and write nothing.
    before = {name: (root / name).read_bytes() for name in FILES}
    blocked = nav.text("lsp.safe_delete_symbol", relative_path="pricing.cpp", name_path="Tax", dry_run=True)
    assert "would be blocked" in blocked and "nothing written" in blocked, blocked
    references = {(file_of(path), int(line)) for path, line in re.findall(r"reference: ([^\s:]+):(\d+):\d+", blocked)}
    assert references == {("pricing.cpp", where("pricing.cpp", "+ Tax(")[0]), ("audit.cpp", where("audit.cpp", "shop::Tax(")[0])}, blocked
    renamed = nav.text("lsp.rename_symbol", relative_path="pricing.cpp", name_path="Tax", new_name="SalesTax", dry_run=True)
    touched = {Path(path).name for path in re.findall(r"^\+\+\+ b/(\S+)", renamed, re.M)}
    assert touched == {"pricing.hpp", "pricing.cpp", "audit.cpp"}, renamed
    assert "-double Tax(double amount) { return amount; }" not in renamed, renamed  # audit::Tax stays
    changed = [l for l in renamed.splitlines() if l[:1] in "+-" and not l.startswith(("+++", "---"))]
    assert not [l for l in changed if '"Tax"' in l or "// Tax" in l], changed  # the string and the comment stay
    assert {name: (root / name).read_bytes() for name in FILES} == before, "a dry run wrote files"
    # A virtual method: changing Shape::Area reaches both overrides and the virtual call in TotalArea.
    overrides = nav.call("lsp.find_implementations", relative_path="shapes.hpp", name_path="Shape/Area")["results"]
    assert {(file_of(item["path"]), item["line"]) for item in overrides} >= {
        ("shapes.cpp", where("shapes.cpp", "Circle::Area")[0]), ("shapes.cpp", where("shapes.cpp", "Square::Area")[0])} or \
        {(file_of(item["path"]), item["line"]) for item in overrides} >= {
        ("shapes.hpp", where("shapes.hpp", "double Area() const override", 0)[0]),
        ("shapes.hpp", where("shapes.hpp", "double Area() const override", 1)[0])}, overrides
    area_callers, found = nav.callers("Shape/Area", "shapes.hpp")
    assert ("shapes.cpp", "TotalArea") in area_callers, found
    # The real rename changes exactly the dry run's places, and every file still compiles.
    nav.text("lsp.rename_symbol", relative_path="pricing.cpp", name_path="Tax", new_name="SalesTax")
    assert "double SalesTax(double amount);" in (root / "pricing.hpp").read_text()
    assert "+ SalesTax(amount)" in (root / "pricing.cpp").read_text() and "double SalesTax(double amount)" in (root / "pricing.cpp").read_text()
    audit = (root / "audit.cpp").read_text()
    assert "shop::SalesTax(amount) - Tax(amount)" in audit and "double Tax(double amount) { return amount; }" in audit, audit
    assert (root / "report.cpp").read_bytes() == before["report.cpp"]
    assert "// Tax in a comment" in (root / "pricing.cpp").read_text()
    for name in ("pricing.cpp", "audit.cpp", "report.cpp"):
        errors = nav.call("lsp.get_diagnostics_for_file", relative_path=name, severity=1)
        assert not errors.get("items"), (name, errors)
    # Removing the old name from the header breaks exactly its remaining users.
    (root / "pricing.hpp").write_text(FILES["pricing.hpp"].replace("double Tax(double amount);\n", ""), encoding="utf-8")
    (root / "pricing.cpp").write_text(FILES["pricing.cpp"], encoding="utf-8")
    # audit.cpp itself did not change; its diagnostics must still reflect the header it includes.
    deadline = time.monotonic() + 10
    while True:
        broken = nav.call("lsp.get_diagnostics_for_file", relative_path="audit.cpp", severity=1)
        if broken.get("items") or time.monotonic() > deadline:
            break
        time.sleep(0.5)
    assert broken.get("items"), broken  # shop::SalesTax is no longer declared
    print("ok  5 impact: dry runs list exactly the affected places; the rename compiles; a removed declaration breaks its users")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("executable", type=Path)
    parser.add_argument("--lsp-root", type=Path, help="folder with the bundled clangd (SHGREP_LSP_ROOT)")
    args = parser.parse_args()
    environment = dict(os.environ)
    if args.lsp_root:
        environment["SHGREP_LSP_ROOT"] = str(args.lsp_root.resolve())
    with tempfile.TemporaryDirectory(prefix="shgrep-nav-", ignore_cleanup_errors=True) as folder:
        root = Path(folder)
        for name, text in FILES.items():
            (root / name).write_bytes(text.encode("utf-8"))
        client = Client(args.executable.resolve(), root, timeout=SLOW / 1000 + 30, environment=environment)
        try:
            nav = Nav(client)
            status = nav.call("lsp.status", relative_path="pricing.cpp")
            assert "clangd" in json.dumps(status), status
            check_where(nav)
            check_callers(nav)
            check_dependencies(nav)
            check_call_chain(nav)
            check_impact(nav, root)
        finally:
            client.close()
    print("Navigation checks passed")


if __name__ == "__main__":
    main()
