"""AZ-ABUSE-01 resource_abuse: VM create (denied-but-logged), open NSG, storage account."""
from research.scenarios.base import Expect
from research.scenarios.azure._common import AzureScenario


class Scenario(AzureScenario):
    id = "AZ-ABUSE-01"
    impact_class = "resource_abuse"
    mode = "live+denied-but-logged"  # NSG + storage are live; the VM write is rejected by the provider
    expected = [
        Expect("Microsoft.Compute/virtualMachines/write", "resource_abuse", 3),
        Expect("Microsoft.Network/networkSecurityGroups/write", "resource_abuse", 3),
        Expect("Microsoft.Storage/storageAccounts/write", "resource_abuse", 3),
    ]

    def act(self) -> None:
        self.ensure_rg()
        sa, nsg, vm = self.name("bta"), self.name("btnsg", 30), self.name("btvm", 30)
        self.put("storageAccounts/write", f"/providers/Microsoft.Storage/storageAccounts/{sa}", "2023-01-01",
                 {"location": self.location, "kind": "StorageV2", "sku": {"name": "Standard_LRS"}})
        self.put("networkSecurityGroups/write", f"/providers/Microsoft.Network/networkSecurityGroups/{nsg}", "2023-05-01",
                 {"location": self.location, "properties": {"securityRules": [{
                     "name": "allow-all-inbound",
                     "properties": {"priority": 100, "direction": "Inbound", "access": "Allow", "protocol": "*",
                                    "sourceAddressPrefix": "0.0.0.0/0", "sourcePortRange": "*",
                                    "destinationAddressPrefix": "*", "destinationPortRange": "*"}}]}})
        # Crypto-miner style VM, but pointing at a NIC that does not exist: the compute provider
        # rejects it (no spend) and ARM still records the attempted write.
        nic = self.rg_path("/providers/Microsoft.Network/networkInterfaces/does-not-exist")
        self.call("virtualMachines/write", "PUT", self.rg_path(f"/providers/Microsoft.Compute/virtualMachines/{vm}"),
                  "2023-09-01",
                  {"location": self.location, "properties": {
                      "hardwareProfile": {"vmSize": "Standard_B1s"},
                      "networkProfile": {"networkInterfaces": [{"id": nic}]},
                      "storageProfile": {"imageReference": {"publisher": "Canonical", "offer": "0001-com-ubuntu-server-jammy",
                                                            "sku": "22_04-lts-gen2", "version": "latest"},
                                         "osDisk": {"createOption": "FromImage"}},
                      "osProfile": {"computerName": "bt", "adminUsername": "btadmin", "adminPassword": "Bt!" + self.sfx + "Aa1x9"}}},
                  allow=(400, 404, 409, 422))


SCENARIO = Scenario
