from __future__ import annotations

import pytest
import yaml
from vuln_deserialization import parse_configuration


def test_legit_config():
    res = parse_configuration("{server: {port: 8080}}")
    assert res == {"server": {"port": 8080}}


def test_unsafe_yaml_tag_rejected():
    # Before repair: yaml.load with Loader=yaml.Loader permits python object tags.
    # After repair: Loader=yaml.SafeLoader raises constructor error.
    with pytest.raises(yaml.YAMLError):
        parse_configuration("!!python/object/apply:os.system ['echo 1']")

