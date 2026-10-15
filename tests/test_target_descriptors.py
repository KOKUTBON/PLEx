from __future__ import annotations

from plex.target import TargetDescriptor, TargetScope


def test_target_descriptor_defaults_and_deterministic_id():
    desc1 = TargetDescriptor(kind="source_tree", path="src/plex")
    desc2 = TargetDescriptor(kind="source_tree", path="src/plex")
    desc3 = TargetDescriptor(kind="artifact", path="dist/plex.whl")

    assert desc1.schema_version == 1
    assert desc1.id.startswith("target:")
    assert desc1.id == desc2.id
    assert desc1.id != desc3.id


def test_target_descriptor_explicit_id():
    desc = TargetDescriptor(id="custom-target-id", kind="endpoint", url="https://api.example.com")
    assert desc.id == "custom-target-id"
    assert desc.url == "https://api.example.com"


def test_target_descriptor_serialization_roundtrip():
    desc = TargetDescriptor(
        kind="endpoint",
        path="/api/v1",
        url="https://example.com/api/v1",
        snapshot_digest="sha256:1234567890abcdef",
        metadata={"auth_required": True, "tier": "production"},
    )
    data = desc.to_dict()
    assert data["schema_version"] == 1
    assert data["id"] == desc.id
    assert data["metadata"]["tier"] == "production"

    restored = TargetDescriptor.from_dict(data)
    assert restored == desc


def test_target_scope_defaults_and_boundaries():
    desc = TargetDescriptor(path=".")
    scope = TargetScope(target=desc)

    assert scope.target == desc
    assert scope.include_patterns == ("**/*",)
    assert scope.exclude_patterns == ()
    assert scope.max_files == 200
    assert scope.network_restricted is True


def test_target_scope_serialization_roundtrip():
    desc = TargetDescriptor(kind="source_tree", path="src")
    scope = TargetScope(
        target=desc,
        include_patterns=("src/**/*.py", "tests/**/*.py"),
        exclude_patterns=("**/*_test.py",),
        max_files=500,
        network_restricted=False,
        metadata={"environment": "staging"},
    )
    data = scope.to_dict()
    assert data["max_files"] == 500
    assert data["network_restricted"] is False
    assert data["include_patterns"] == ["src/**/*.py", "tests/**/*.py"]

    restored = TargetScope.from_dict(data)
    assert restored == scope
