"""AZ-RECON-01 reconnaissance. Reads are NOT written to the Activity Log -> expected_blind."""
from research.scenarios.base import Expect
from research.scenarios.azure._common import AzureScenario


class Scenario(AzureScenario):
    id = "AZ-RECON-01"
    impact_class = "reconnaissance"
    mode = "live"
    expected_blind = True
    min_wait_s = 600  # observe 10 min before declaring the log blind
    expected = [
        Expect("Microsoft.Resources/subscriptions/resourceGroups/read", "reconnaissance", 1, optional=True),
        Expect("Microsoft.Storage/storageAccounts/read", "reconnaissance", 1, optional=True),
        Expect("Microsoft.Compute/virtualMachines/read", "reconnaissance", 1, optional=True),
        Expect("Microsoft.Authorization/roleAssignments/read", "reconnaissance", 1, optional=True),
    ]

    def act(self) -> None:
        s = self.sub
        self.call("resourceGroups/read", "GET", f"/subscriptions/{s}/resourcegroups", "2021-04-01")
        self.call("storageAccounts/read", "GET", f"/subscriptions/{s}/providers/Microsoft.Storage/storageAccounts", "2023-01-01")
        self.call("virtualMachines/read", "GET", f"/subscriptions/{s}/providers/Microsoft.Compute/virtualMachines", "2023-09-01")
        self.call("roleAssignments/read", "GET", f"/subscriptions/{s}/providers/Microsoft.Authorization/roleAssignments", "2022-04-01")


SCENARIO = Scenario
