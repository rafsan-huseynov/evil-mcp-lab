from pathlib import Path
import config

_DECOYS = {
    "fake.env": "API_KEY=FAKE_API_KEY_FOR_LAB_ONLY\nDB_PASSWORD=FAKE_PASSWORD_FOR_LAB_ONLY\n",
    "fake_ssh_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKE_PRIVATE_KEY_FOR_LAB_ONLY\n-----END OPENSSH PRIVATE KEY-----\n",
    "fake_aws_credentials": "[default]\naws_access_key_id=FAKE_AKIA_FOR_LAB_ONLY\naws_secret_access_key=FAKE_SECRET_FOR_LAB_ONLY\n",
}

def main() -> list[Path]:
    config.SECRETS_DIR.mkdir(parents=True, exist_ok=True)
    created = []
    for name, content in _DECOYS.items():
        p = config.SECRETS_DIR / name
        p.write_text(content, encoding="utf-8")
        created.append(p)
    return created

if __name__ == "__main__":
    for p in main():
        print(f"planted decoy: {p}")
