"""AZ-COMM-01 communication_abuse: Service Bus + Event Hub namespaces and a send/manage auth rule."""
from research.scenarios.base import Expect
from research.scenarios.azure._common import AzureScenario


class Scenario(AzureScenario):
    id = "AZ-COMM-01"
    impact_class = "communication_abuse"
    expected = [
        Expect("Microsoft.ServiceBus/namespaces/write", "communication_abuse", 2),
        Expect("Microsoft.ServiceBus/namespaces/authorizationRules/write", "communication_abuse", 3),
        Expect("Microsoft.EventHub/namespaces/write", "communication_abuse", 2),
    ]

    def act(self) -> None:
        self.ensure_rg()
        sb, eh = self.name("btsb", 40), self.name("bteh", 40)
        api = "2022-10-01-preview"
        sbp = f"/providers/Microsoft.ServiceBus/namespaces/{sb}"
        self.put("ServiceBus/namespaces/write", sbp, api,
                 {"location": self.location, "sku": {"name": "Basic", "tier": "Basic"}})
        self.call("ServiceBus/authorizationRules/write", "PUT", self.rg_path(sbp + "/authorizationRules/attacker-send"), api,
                  {"properties": {"rights": ["Listen", "Send", "Manage"]}})
        self.put("EventHub/namespaces/write", f"/providers/Microsoft.EventHub/namespaces/{eh}", api,
                 {"location": self.location, "sku": {"name": "Basic", "tier": "Basic", "capacity": 1}})


SCENARIO = Scenario
