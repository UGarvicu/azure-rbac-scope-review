import json
import tempfile
import unittest
from pathlib import Path
from azure_rbac_scope_review.cli import AssignmentError, analyze, main, scope_level

SUB = "/subscriptions/00000000-0000-0000-0000-000000000000"
MG = "/providers/Microsoft.Management/managementGroups/demo"


class ReviewTest(unittest.TestCase):
    def test_scopes(self):
        self.assertEqual(scope_level(MG), "management-group")
        self.assertEqual(scope_level(SUB), "subscription")
        self.assertEqual(scope_level(SUB + "/resourceGroups/demo"), "resource-group")
        self.assertEqual(scope_level(SUB + "/resourceGroups/demo/providers/Microsoft.Storage/storageAccounts/demo"), "resource")

    def test_flag_broad_privilege_only(self):
        sample = [
            {"principalName": "admin@example.invalid", "roleDefinitionName": "Owner", "scope": SUB},
            {"principalName": "reader@example.invalid", "roleDefinitionName": "Reader", "scope": MG},
            {"principalName": "team@example.invalid", "roleDefinitionName": "User Access Administrator", "scope": SUB + "/resourceGroups/test"},
        ]
        result = analyze(sample)
        self.assertEqual(result["assignment_count"], 3)
        self.assertEqual(result["finding_count"], 1)
        self.assertEqual(result["findings"][0]["principal"], "admin@example.invalid")

    def test_invalid_input(self):
        with self.assertRaises(AssignmentError):
            analyze({})
        with self.assertRaises(AssignmentError):
            analyze([{"roleDefinitionName": "Owner"}])

    def test_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, out = Path(tmp) / "assignments.json", Path(tmp) / "report.json"
            src.write_text(json.dumps([{"roleDefinitionName": "Owner", "scope": SUB}]))
            self.assertEqual(main([str(src), "--output", str(out)]), 0)
            self.assertEqual(json.loads(out.read_text())["finding_count"], 1)


if __name__ == "__main__":
    unittest.main()
