import config

def test_config_defaults():
    assert config.HTTP_PORT == 8124
    assert str(config.SINK_URL).startswith("http://127.0.0.1:")
    assert config.LAB_ROOT.name == "lab"
    assert isinstance(config.ATTACKS_ENABLED, dict)
