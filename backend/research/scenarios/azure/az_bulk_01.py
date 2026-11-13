"""AZ-BULK-01 data_access -> exfiltration: >=5 identical listKeys from one IP."""
import time

from research.scenarios.base import Expect
from research.scenarios.azure._common import AzureScenario

KEYS = "Microsoft.Storage/storageAccounts/listKeys/action"


class Scenario(AzureScenario):
    id = "AZ-BULK-01"
    impact_class = "data_access->exfiltration"
    expected = [Expect(KEYS, "exfiltration", 4)]

    def act(self) -> None:
        self.ensure_rg()
        sa = self.name("btb")
        path = f"/providers/Microsoft.Storage/storageAccounts/{sa}"
        self.put("storageAccounts/write", path, "2023-01-01",
                 {"location": self.location, "kind": "StorageV2", "sku": {"name": "Standard_LRS"}})
        for _ in range(7):  # threshold is 5; extra margin in case an event is delayed
            self.call("storageAccounts/listKeys", "POST", self.rg_path(path + "/listKeys"), "2023-01-01")
            time.sleep(1)


SCENARIO = Scenario
