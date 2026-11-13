"""AZ-PRIVESC-01 privilege_escalation on a scratch RG: role assignment, Key Vault policy, key regen."""
import os

from research.scenarios.base import Expect
from research.scenarios.azure._common import AzureScenario, new_guid

READER = "acdd72a7-3385-48ef-bd42-f606fba81ae7"


class Scenario(AzureScenario):
    id = "AZ-PRIVESC-01"
    impact_class = "privilege_escalation"
    expected = [
        Expect("Microsoft.Authorization/roleAssignments/write", "privilege_escalation", 4),
        Expect("Microsoft.KeyVault/vaults/accessPolicies/write", "privilege_escalation", 4),
        Expect("Microsoft.Storage/storageAccounts/regenerateKey/action", "privilege_escalation", 4),
    ]

    def act(self) -> None:
        oid = os.getenv("AZURE_EXPERIMENT_SP_OBJECT_ID", "")
        if not oid:
            raise RuntimeError("set AZURE_EXPERIMENT_SP_OBJECT_ID (Enterprise app -> Object ID of the experiment SP)")
        self.ensure_rg()
        sa, kv = self.name("btp"), self.name("btkv", 24)
        self.put("storageAccounts/write", f"/providers/Microsoft.Storage/storageAccounts/{sa}", "2023-01-01",
                 {"location": self.location, "kind": "StorageV2", "sku": {"name": "Standard_LRS"}})
        self.call("storageAccounts/regenerateKey", "POST",
                  self.rg_path(f"/providers/Microsoft.Storage/storageAccounts/{sa}/regenerateKey"), "2023-01-01",
                  {"keyName": "key2"})

        # Scratch role assignment (Reader, on the scratch RG only, to the experiment SP itself).
        ra = self.rg_path(f"/providers/Microsoft.Authorization/roleAssignments/{new_guid()}")
        self.call("roleAssignments/write", "PUT", ra, "2022-04-01", {"properties": {
            "roleDefinitionId": f"/subscriptions/{self.sub}/providers/Microsoft.Authorization/roleDefinitions/{READER}",
            "principalId": oid, "principalType": "ServicePrincipal"}})
        self.undo("role assignment", lambda: self.arm.call("DELETE", ra, "2022-04-01", allow=(404,)))

        self.put("vaults/write", f"/providers/Microsoft.KeyVault/vaults/{kv}", "2023-02-01",
                 {"location": self.location, "properties": {"tenantId": self.tenant, "sku": {"family": "A", "name": "standard"},
                                                            "accessPolicies": [], "enableRbacAuthorization": False}})
        self.call("vaults/accessPolicies/write", "PUT",
                  self.rg_path(f"/providers/Microsoft.KeyVault/vaults/{kv}/accessPolicies/add"), "2023-02-01",
                  {"properties": {"accessPolicies": [{"tenantId": self.tenant, "objectId": oid,
                                                      "permissions": {"secrets": ["get", "list"]}}]}})
        # Soft-deleted vaults keep their name reserved; purge after the RG is gone.
        purge = (f"/subscriptions/{self.sub}/providers/Microsoft.KeyVault/locations/{self.location}"
                 f"/deletedVaults/{kv}/purge")
        self.undo("purge key vault", lambda: self._purge(kv, purge))

    def _purge(self, kv: str, purge: str) -> None:
        self.arm.call("DELETE", self.rg_path(), "2021-04-01", allow=(404,))
        self.arm.wait_gone(self.rg_path(), "2021-04-01")
        self._rg_created = False
        self.arm.call("POST", purge, "2023-02-01", allow=(404, 409))


SCENARIO = Scenario
