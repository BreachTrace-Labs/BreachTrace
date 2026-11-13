"""AZ-DATA-01 data_access via control-plane credential listing (observable)."""
from research.scenarios.base import Expect
from research.scenarios.azure._common import AzureScenario

KEYS = "Microsoft.Storage/storageAccounts/listKeys/action"
CREDS = "Microsoft.ContainerRegistry/registries/listCredentials/action"


class Scenario(AzureScenario):
    id = "AZ-DATA-01"
    impact_class = "data_access"
    expected = [Expect(KEYS, "data_access", 4), Expect(CREDS, "data_access", 4)]

    def act(self) -> None:
        self.ensure_rg()
        sa, acr = self.name("btd"), self.name("btacr", 40)
        self.put("storageAccounts/write", f"/providers/Microsoft.Storage/storageAccounts/{sa}", "2023-01-01",
                 {"location": self.location, "kind": "StorageV2", "sku": {"name": "Standard_LRS"}})
        self.call("storageAccounts/listKeys", "POST", self.rg_path(f"/providers/Microsoft.Storage/storageAccounts/{sa}/listKeys"), "2023-01-01")
        self.put("registries/write", f"/providers/Microsoft.ContainerRegistry/registries/{acr}", "2023-07-01",
                 {"location": self.location, "sku": {"name": "Basic"}, "properties": {"adminUserEnabled": True}})
        self.call("registries/listCredentials", "POST", self.rg_path(f"/providers/Microsoft.ContainerRegistry/registries/{acr}/listCredentials"), "2023-07-01")


SCENARIO = Scenario
