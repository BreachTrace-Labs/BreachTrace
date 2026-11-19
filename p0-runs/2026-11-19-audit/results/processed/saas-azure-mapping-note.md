# Azure, Stripe and Twilio fixture mapping

Nine constructed records were mapped and persisted: two Azure Activity Log, two Stripe Events, two Twilio messages, two Twilio calls and one Twilio Monitor. Every example retains its example source ID somewhere in raw evidence, while normalized source_record_id is empty. Principal fields have different meanings: Azure caller, Stripe request ID, Twilio account SID for calls/messages, and Twilio actor SID for Monitor. These are not interchangeable and none identifies the key used in these examples.

Azure with missing status, Twilio message with missing status, and Twilio Monitor with no outcome field each mapped to success=True. This is a mapper/default observation on constructed inputs, not a claim that real activity succeeded. Stripe outcomes in this fixture are inferred from event type; the CSV column explicit_source_status means an outcome indicator was supplied, not that a separate status property existed for Stripe. Failed Stripe and Twilio call examples mapped to success=False.

This is a development fixture. Provider collection, pagination, permissions, raw native exports, independent action truth, exact-key evidence, and blinded review were not measured. No prevalence or field-completeness rate may be inferred.
