"""Flag high-impact Azure RBAC roles at broad scopes from an Azure CLI JSON export."""
import argparse
import json
import sys
from collections import Counter
from pathlib import Path

PRIVILEGED = {"owner", "user access administrator", "role based access control administrator"}


class AssignmentError(ValueError):
    """Invalid Azure CLI role assignment export."""


def scope_level(scope: str) -> str:
    parts = [part.lower() for part in scope.strip("/").split("/")]
    if len(parts) == 4 and parts[:2] == ["providers", "microsoft.management"] and parts[2] == "managementgroups":
        return "management-group"
    if len(parts) == 2 and parts[0] == "subscriptions":
        return "subscription"
    if len(parts) == 4 and parts[0] == "subscriptions" and parts[2] == "resourcegroups":
        return "resource-group"
    if len(parts) > 2 and parts[0] == "subscriptions":
        return "resource"
    return "unknown"


def analyze(assignments: object) -> dict:
    if not isinstance(assignments, list):
        raise AssignmentError("expected JSON array from az role assignment list")
    counts = Counter()
    findings = []
    for i, item in enumerate(assignments, 1):
        if not isinstance(item, dict):
            raise AssignmentError(f"item {i} is not an object")
        role = item.get("roleDefinitionName")
        scope = item.get("scope")
        if not isinstance(role, str) or not isinstance(scope, str) or not scope.startswith("/"):
            raise AssignmentError(f"item {i} lacks a valid roleDefinitionName or scope")
        level = scope_level(scope)
        counts[level] += 1
        if role.casefold() in PRIVILEGED and level in {"management-group", "subscription"}:
            findings.append({
                "principal": item.get("principalName") or item.get("principalId") or "(unknown)",
                "principal_type": item.get("principalType") or "(unknown)",
                "role": role,
                "scope": scope,
                "scope_level": level,
                "reason": "privileged role assigned at broad scope; review whether necessary",
            })
    findings.sort(key=lambda x: (x["scope"], x["role"], x["principal"]))
    return {"assignment_count": len(assignments), "scope_counts": dict(sorted(counts.items())),
            "findings": findings, "finding_count": len(findings)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="JSON from az role assignment list --all")
    parser.add_argument("--output", type=Path, help="report path; defaults to stdout")
    args = parser.parse_args(argv)
    try:
        report = analyze(json.loads(args.input.read_text(encoding="utf-8-sig")))
        data = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
        if args.output:
            args.output.write_text(data, encoding="utf-8")
        else:
            sys.stdout.write(data)
    except (OSError, json.JSONDecodeError, AssignmentError) as exc:
        parser.exit(2, f"error: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
