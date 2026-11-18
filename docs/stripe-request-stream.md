# Run the Stripe request-log stream

BreachTrace uses the Stripe CLI's sandbox request-log stream to capture new API calls, including GETs. The worker can run alongside the backend locally or as a persistent service on an always-on host. Stripe documents this CLI stream as real-time and sandbox-only; it does not backfill earlier calls or stream live-mode logs.

## Configure the credentials

Create a dedicated **test-mode restricted key** in the same Stripe sandbox as the incident. Give it the Stripe CLI session permission required by your account to open a request-log stream. Do not use the exposed key as the worker's credential. The CLI accepts API keys from its environment, which avoids an interactive browser login on a server. See [Stripe CLI API-key configuration](https://github.com/stripe/stripe-cli/wiki/Using-Stripe-API-Keys) and [Stripe's request-log stream](https://docs.stripe.com/cli/logs/tail). If Stripe rejects the key, follow the missing permission named in its error message.

Generate an independent random token for BreachTrace's internal ingestion endpoint. Put these values in a gitignored environment file or your hosting provider's secret manager; do not put real values in `.env.example` or commit them:

```dotenv
STRIPE_INCIDENT_ID=<incident UUID from BreachTrace>
STRIPE_CLI_API_KEY=<dedicated restricted test key>
STRIPE_LOG_INGEST_TOKEN=<random shared token>
BREACHTRACE_API_URL=http://127.0.0.1:8000
```

Set `STRIPE_LOG_INGEST_TOKEN` on the backend as well. The stream worker sends it as a bearer token; remote requests to the ingestion endpoint are rejected without it. Use the same token for both services. If the backend runs in the same Docker Compose project, set `BREACHTRACE_API_URL=http://backend:8000`. If the backend is hosted elsewhere, set its private HTTPS URL and store the same token in both services.

## Start a local capture

The local backend started with `scripts/local_dev.py backend` listens only on `127.0.0.1`. Run the worker directly on the Mac so it can reach that loopback address. Install the [Stripe CLI](https://docs.stripe.com/stripe-cli) first, then run:

```bash
.venv/bin/python scripts/stripe_request_logs.py --confirm-sandbox
```

The worker reads `.env.testing.local`, including the incident ID and dedicated restricted test key. It runs until stopped with Ctrl+C. Restart the backend after changing its `STRIPE_LOG_INGEST_TOKEN`, so it loads the same token.

The Docker image and Compose sidecar are for a backend reachable over the Docker network or a private HTTPS address. They are not connected to the current native loopback-only backend.

It monitors the single incident named by `STRIPE_INCIDENT_ID`. To monitor a different incident, update that setting and restart the worker. Requests are account activity from the selected sandbox; Stripe's stream does not identify which API key made each request. The UI labels them accordingly. Refresh the incident after capture to include the stored request records in its report.

## Move it to an always-on host

Deploy the same `Dockerfile.stripe-logs` image as a persistent worker service on the server that hosts BreachTrace, or on a host with private network access to it. Set the four variables above in the host's secret manager. Set `BREACHTRACE_API_URL` to the backend's private service URL and expose the same `STRIPE_LOG_INGEST_TOKEN` to both services. Configure the platform to restart the worker on failure and after host reboot. For capture while the Mac is off, this always-on host is required; a local process or Docker container stops with the laptop. The included Compose service can also run on that host with `docker compose --env-file <secrets-file> -f docker-compose.stripe.yml up -d --build`.

The stream only captures calls while connected and cannot recover earlier requests. Stripe CLI streaming is not supported for live-mode request logs; this worker intentionally refuses live credentials.
