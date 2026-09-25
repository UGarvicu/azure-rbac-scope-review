# Azure RBAC scope review

An **offline, read-only** Python report that flags broad Azure RBAC assignments worth a human review. It highlights Owner, User Access Administrator, and Role Based Access Control Administrator at subscription or management-group scope. It does not change assignments, infer effective permissions, or declare anything insecure.

## Try it

Python 3.10 or newer; no runtime dependencies:

```bash
python -m pip install -e .
rbac-scope-review examples/sample-assignments.json --output report.json
python -m unittest discover -s tests -v
```

To analyze **your own** Azure subscription, sign into Azure CLI yourself, select the intended subscription, and save its role assignments. The script never invokes Azure CLI or requests credentials:

```bash
az account set --subscription '<subscription ID>'
az role assignment list --all --output json > assignments.json
rbac-scope-review assignments.json --output report.json
```

Review `az account show` first to ensure the intended tenant and subscription. Keep `assignments.json` and `report.json` private: principal names and role scopes may be sensitive. `.gitignore` excludes JSON except the synthetic example. The generated report includes assignment counts by scope plus the broad-role findings. The sample uses fake identities and a zero subscription ID.

## Scope and limits

- This is a prioritization aid, not an access audit. It flags three built-in role names only, not custom roles, PIM eligibility/activation, deny assignments, policy, or data-plane permissions.
- `az role assignment list --all` covers assignments at and below the selected subscription. Inherited management-group assignments are **not necessarily included**; enumerate relevant parent scopes separately. This tool does not fetch them. An empty report does not mean the environment is safe.
- A group assignment does not expand into group members. Principal names may be unresolved, depending on directory permissions. Existing governance may justify broad access; investigate before making changes.
- Duplicate rows are counted as presented; only a valid JSON array with recognizable scope and role fields is accepted. This tool does not verify input completeness or freshness.

Reference: [Microsoft's Azure CLI role-assignment guide](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-list-cli) and [az role assignment CLI reference](https://learn.microsoft.com/en-us/cli/azure/role/assignment?view=azure-cli-latest).
