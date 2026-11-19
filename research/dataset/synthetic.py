"""Create a clearly identified synthetic pilot with no credential values on disk."""
import hashlib
import secrets
import string

from research.dataset.schema import CORPUS, append_jsonl
from research.scoring import score_finding, DEFAULT_WEIGHTS

ALPHABET = string.ascii_letters + string.digits
SERVICES = ('openai', 'anthropic', 'github', 'stripe', 'sendgrid', 'slack', 'google_api', 'azure_client_secret', 'aws')


def token(service):
    rand = lambda n: ''.join(secrets.choice(ALPHABET) for _ in range(n))
    return {'openai': lambda: 'sk-proj-' + rand(48),
            'anthropic': lambda: 'sk-ant-api03-' + rand(93) + 'AA',
            'github': lambda: 'ghp_' + rand(36),
            'stripe': lambda: 'sk_test_' + rand(32),
            'sendgrid': lambda: 'SG.' + rand(22) + '.' + rand(43),
            'slack': lambda: 'xoxb-' + rand(24),
            'google_api': lambda: 'AIza' + rand(35),
            'azure_client_secret': lambda: rand(8) + '~' + rand(31),
            'aws': lambda: 'AKIA' + ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))}[service]()


def generate():
    output = CORPUS / 'synthetic-labeled.jsonl'
    # Separate file; replace our own previous generation, never unrelated labels.
    output.unlink(missing_ok=True)
    positive = ('API_KEY = "{}"', '{{"api_key": "{}"}}', 'config.set("key", "{}")')
    negative = ('# fake key for testing: {}', 'placeholder = "{}"  # replace me',
                'EXAMPLE_KEY = "{}"', 'test_token = "{}"')
    for i in range(50):
        service = SERVICES[i % len(SERVICES)]
        value = token(service)
        group = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
        for label, templates in (('TP', positive), ('FP', negative)):
            line = templates[i % len(templates)].format(value)
            scored = score_finding(value, line, line, weights=DEFAULT_WEIGHTS)
            append_jsonl(output, {'candidate_id': hashlib.sha256((group + label).encode()).hexdigest(),
                                  'repository': 'synthetic:' + group, 'service': service,
                                  'source': 'synthetic_tp' if label == 'TP' else 'synthetic_fp',
                                  'label': label, **scored})
    print('Generated 100 synthetic feature records in a separate file; no generated strings saved.')


if __name__ == '__main__':
    generate()
