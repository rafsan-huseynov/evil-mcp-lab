import config
from lab.setup_lab import main

def test_setup_creates_decoys():
    created = main()
    assert (config.SECRETS_DIR / "fake.env").exists()
    assert (config.SECRETS_DIR / "fake_ssh_key").exists()
    assert (config.SECRETS_DIR / "fake_aws_credentials").exists()
    # decoys are obviously fake
    for p in created:
        assert "FOR_LAB_ONLY" in p.read_text()
