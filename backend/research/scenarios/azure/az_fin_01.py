"""AZ-FIN-01 financial_abuse: budget alert tampering (live) + billing-account write (denied-but-logged)."""
import os
from datetime import datetime, timezone

from research.scenarios.base import Expect
from research.scenarios.azure._common import AzureScenario

# Budgets surface in the Activity Log as Microsoft.Consumption/budgets/*, not
# Microsoft.CostManagement/budgets/* - both are in the taxonomy.
BW = "Microsoft.Consumption/budgets/write"
BD = "Microsoft.Consumption/budgets/delete"
BILL = "Microsoft.Billing/billingAccounts/write"


class Scenario(AzureScenario):
    id = "AZ-FIN-01"
    impact_class = "financial_abuse"
    mode = "live+denied-but-logged"
    expected = [
        Expect(BW, "financial_abuse", 3),
        Expect(BD, "financial_abuse", 3),
        Expect(BILL, "financial_abuse", 4, optional=True),
    ]

    def _budget(self, amount: int) -> dict:
        start = datetime.now(timezone.utc).replace(day=1).strftime("%Y-%m-%dT00:00:00Z")
        email = os.getenv("AZURE_ALERT_EMAIL", "alerts@example.com")
        return {"properties": {"category": "Cost", "amount": amount, "timeGrain": "Monthly",
                               "timePeriod": {"startDate": start},
                               "notifications": {"warn80": {"enabled": True, "operator": "GreaterThan", "threshold": 80,
                                                            "contactEmails": [email]}}}}

    def act(self) -> None:
        name = f"breachtrace-scenario-budget-{self.sfx}"
        path = f"/subscriptions/{self.sub}/providers/Microsoft.Consumption/budgets/{name}"
        self.undo("budget", lambda: self.arm.call("DELETE", path, "2023-05-01", allow=(404,)))
        self.call("budgets/write (create)", "PUT", path, "2023-05-01", self._budget(10))
        self.call("budgets/write (inflate cap)", "PUT", path, "2023-05-01", self._budget(1_000_000))
        self.call("budgets/delete", "DELETE", path, "2023-05-01")
        self.call("billingAccounts/write", "PATCH", "/providers/Microsoft.Billing/billingAccounts/0000000:0000-00",
                  "2020-05-01", {"properties": {"displayName": "attacker"}}, allow=(400, 401, 403, 404))


SCENARIO = Scenario
