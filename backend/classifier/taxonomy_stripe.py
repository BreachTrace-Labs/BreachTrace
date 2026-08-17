"""Stripe event-type taxonomy (S3-S4).

Keys are Stripe Events API `type` values — dot-separated, past tense:
  "charge.succeeded", "payout.created", "customer.updated"

Same dict shape as taxonomy_aws / taxonomy_gcp / taxonomy_azure:
  {event_type: {"category": str, "severity": int, "label": str}}

Categories (must match classifier/rules.py exactly):
  reconnaissance (1) · data_access (2) · resource_abuse (3)
  financial_abuse (3-4) · privilege_escalation (4) · exfiltration (4)

--------------------------------------------------------------------------
IMPORTANT FORENSIC LIMITATION — read this before quoting Stripe coverage
--------------------------------------------------------------------------
The Stripe Events API records **state changes only**. A `GET /v1/customers`
that dumps every customer record generates NO event, so read-only data
exfiltration through the Stripe API is invisible to this collector.

Consequences, which the paper must state rather than paper over:

  * Stripe is Tier 1 for *write* activity (charges, payouts, refunds, account
    changes) and effectively blind to *read* activity.
  * Absence of Stripe events is NOT evidence the key went unused.
  * The `customer.*` read-style entries below exist only so that events
    surfaced through other means (e.g. a future Stripe Sigma or request-log
    integration) classify consistently. The Events API will not emit them.

This mirrors the Azure Activity Log control-plane/data-plane split and belongs
in paper §7, "Forensic Observability as a Platform Property".

Severity rationale
------------------
Money movement outranks everything else here. A leaked Stripe key that creates
a charge or redirects a payout is immediate, irreversible financial harm, so
those sit at 4 alongside AWS privilege escalation. Refunds are 3 rather than 4:
damaging and hard to reverse, but bounded by the original charge amount.
`account.updated` is privilege escalation because it is how an attacker
redirects payouts to their own bank account — the highest-value Stripe attack.
"""

VALID_CATEGORIES: set[str] = {
    "reconnaissance",
    "data_access",
    "exfiltration",
    "resource_abuse",
    "financial_abuse",
    "privilege_escalation",
}

VALID_SEVERITIES: set[int] = {1, 2, 3, 4}


STRIPE_API_TAXONOMY: dict[str, dict] = {
    # ================= PRIVILEGE ESCALATION (4) =================
    # Redirecting payouts is the single highest-value Stripe attack: the
    # attacker changes the destination bank account and drains real balance.
    "account.updated": {"category": "privilege_escalation", "severity": 4, "label": "Account Settings Changed"},
    "account.external_account.created": {"category": "privilege_escalation", "severity": 4, "label": "Bank Account Added"},
    "account.external_account.updated": {"category": "privilege_escalation", "severity": 4, "label": "Bank Account Changed"},
    "account.application.authorized": {"category": "privilege_escalation", "severity": 4, "label": "Application Authorized"},
    "capability.updated": {"category": "privilege_escalation", "severity": 3, "label": "Capability Changed"},

    # ================= FINANCIAL ABUSE (3-4) =================
    # Charges — card testing and fraudulent billing.
    "charge.succeeded": {"category": "financial_abuse", "severity": 4, "label": "Charge Succeeded"},
    "charge.captured": {"category": "financial_abuse", "severity": 4, "label": "Charge Captured"},
    "charge.updated": {"category": "financial_abuse", "severity": 3, "label": "Charge Updated"},
    # Failed charges in volume are the signature of card-testing abuse.
    "charge.failed": {"category": "financial_abuse", "severity": 3, "label": "Charge Failed"},
    "charge.expired": {"category": "financial_abuse", "severity": 2, "label": "Charge Expired"},

    "payment_intent.succeeded": {"category": "financial_abuse", "severity": 4, "label": "Payment Succeeded"},
    "payment_intent.created": {"category": "financial_abuse", "severity": 3, "label": "Payment Created"},
    "payment_intent.payment_failed": {"category": "financial_abuse", "severity": 3, "label": "Payment Failed"},
    "payment_intent.canceled": {"category": "financial_abuse", "severity": 2, "label": "Payment Canceled"},

    # Payouts — moving the balance out of the account.
    "payout.created": {"category": "financial_abuse", "severity": 4, "label": "Payout Created"},
    "payout.paid": {"category": "financial_abuse", "severity": 4, "label": "Payout Paid"},
    "payout.updated": {"category": "financial_abuse", "severity": 3, "label": "Payout Updated"},
    "payout.failed": {"category": "financial_abuse", "severity": 2, "label": "Payout Failed"},
    "transfer.created": {"category": "financial_abuse", "severity": 4, "label": "Transfer Created"},
    "transfer.updated": {"category": "financial_abuse", "severity": 3, "label": "Transfer Updated"},

    # Refunds — bounded by the original charge, so 3 rather than 4.
    "refund.created": {"category": "financial_abuse", "severity": 3, "label": "Refund Created"},
    "refund.updated": {"category": "financial_abuse", "severity": 2, "label": "Refund Updated"},
    "charge.refunded": {"category": "financial_abuse", "severity": 3, "label": "Charge Refunded"},
    "charge.refund.updated": {"category": "financial_abuse", "severity": 2, "label": "Refund Updated"},

    # Disputes — a downstream signal that fraudulent charges already landed.
    "charge.dispute.created": {"category": "financial_abuse", "severity": 4, "label": "Dispute Opened"},
    "charge.dispute.funds_withdrawn": {"category": "financial_abuse", "severity": 4, "label": "Dispute Funds Withdrawn"},

    # Invoices and subscriptions — recurring billing abuse.
    "invoice.created": {"category": "financial_abuse", "severity": 2, "label": "Invoice Created"},
    "invoice.paid": {"category": "financial_abuse", "severity": 3, "label": "Invoice Paid"},
    "invoice.payment_succeeded": {"category": "financial_abuse", "severity": 3, "label": "Invoice Payment Succeeded"},
    "invoice.finalized": {"category": "financial_abuse", "severity": 2, "label": "Invoice Finalized"},
    "customer.subscription.created": {"category": "financial_abuse", "severity": 3, "label": "Subscription Created"},
    "customer.subscription.updated": {"category": "financial_abuse", "severity": 2, "label": "Subscription Updated"},

    # ================= RESOURCE ABUSE (3) =================
    # Creating billable objects without directly moving money.
    "customer.created": {"category": "resource_abuse", "severity": 2, "label": "Customer Created"},
    "customer.updated": {"category": "resource_abuse", "severity": 3, "label": "Customer Modified"},
    "customer.deleted": {"category": "resource_abuse", "severity": 3, "label": "Customer Deleted"},
    "product.created": {"category": "resource_abuse", "severity": 2, "label": "Product Created"},
    "price.created": {"category": "resource_abuse", "severity": 2, "label": "Price Created"},
    "checkout.session.completed": {"category": "financial_abuse", "severity": 3, "label": "Checkout Completed"},
    "payment_link.created": {"category": "resource_abuse", "severity": 3, "label": "Payment Link Created"},

    # ================= DATA ACCESS (2) =================
    # See the limitation note above: the Events API does NOT emit these. They
    # exist so that events sourced elsewhere classify consistently.
    "customer.retrieved": {"category": "data_access", "severity": 2, "label": "Customer Retrieved"},
    "payment_method.attached": {"category": "data_access", "severity": 3, "label": "Payment Method Attached"},
    "payment_method.updated": {"category": "data_access", "severity": 2, "label": "Payment Method Updated"},
    "setup_intent.succeeded": {"category": "data_access", "severity": 2, "label": "Setup Intent Succeeded"},
    "customer.source.created": {"category": "data_access", "severity": 3, "label": "Card Added To Customer"},

    # ================= RECONNAISSANCE (1) =================
    "balance.available": {"category": "reconnaissance", "severity": 1, "label": "Balance Checked"},
    "customer.list": {"category": "reconnaissance", "severity": 1, "label": "List Customers"},
    "charge.list": {"category": "reconnaissance", "severity": 1, "label": "List Charges"},
    "product.list": {"category": "reconnaissance", "severity": 1, "label": "List Products"},
}
