"""AZ-EXFIL-01 exfiltration: disk snapshot + subscription log export to an 'attacker' store."""
from research.scenarios.base import Expect
from research.scenarios.azure._common import AzureScenario

SNAP = "Microsoft.Compute/snapshots/write"
DIAG = "Microsoft.Insights/diagnosticSettings/write"


class Scenario(AzureScenario):
    id = "AZ-EXFIL-01"
    impact_class = "exfiltration"
    expected = [Expect(SNAP, "exfiltration", 3), Expect(DIAG, "exfiltration", 3)]

    def act(self) -> None:
        self.ensure_rg()
        sa, snap, diag = self.name("bte"), self.name("btsnap", 30), self.name("btdiag", 30)
        sa_path = self.rg_path(f"/providers/Microsoft.Storage/storageAccounts/{sa}")
        self.put("storageAccounts/write", f"/providers/Microsoft.Storage/storageAccounts/{sa}", "2023-01-01",
                 {"location": self.location, "kind": "StorageV2", "sku": {"name": "Standard_LRS"}})
        # Empty 1 GiB snapshot: same control-plane operation as snapshotting a real disk, ~free.
        self.put("snapshots/write", f"/providers/Microsoft.Compute/snapshots/{snap}", "2023-04-02",
                 {"location": self.location, "sku": {"name": "Standard_LRS"},
                  "properties": {"creationData": {"createOption": "Empty"}, "diskSizeGB": 1}})
        diag_path = f"/subscriptions/{self.sub}/providers/Microsoft.Insights/diagnosticSettings/{diag}"
        self.call("diagnosticSettings/write", "PUT", diag_path, "2021-05-01-preview",
                  {"properties": {"storageAccountId": sa_path,
                                  "logs": [{"category": "Administrative", "enabled": True}]}})
        # Subscription-scoped: not removed with the RG, so it must be undone explicitly.
        self.undo("diagnostic setting", lambda: self.arm.call("DELETE", diag_path, "2021-05-01-preview", allow=(404,)))


SCENARIO = Scenario
