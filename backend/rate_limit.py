"""Login rate limiting keyed by the direct client IP address."""
from slowapi import Limiter
from slowapi.util import get_remote_address

# In-memory storage is per worker. Use a shared backend when running more than
# one backend process; do not trust forwarded headers without proxy controls.
limiter = Limiter(key_func=get_remote_address, default_limits=[])
