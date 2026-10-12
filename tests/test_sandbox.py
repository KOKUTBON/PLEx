from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from plex.sandbox import (
    ContainerSandbox,
    DisposableCopyError,
    InProcessSandbox,
    SubprocessSandbox,
    clean_env,
    create_disposable_copy,
    disposable_workspace,
    is_sensitive_env_key,
)


def test_is_sensitive_env_key():
    assert is_sensitive_env_key("AWS_SECRET_ACCESS_KEY")
    assert is_sensitive_env_key("GITHUB_TOKEN")
    assert is_sensitive_env_key("STRIX_LLM_API_KEY")
    assert is_sensitive_env_key("DATABASE_PASSWORD")
    assert is_sensitive_env_key("AUTH_BEARER_TOKEN")
    assert is_sensitive_env_key("PRIVATE_RSA_KEY")

    assert not is_sensitive_env_key("PATH")
    assert not is_sensitive_env_key("LANG")
    assert not is_sensitive_env_key("PYTHONPATH")
    assert not is_sensitive_env_key("USER")


def test_clean_env_scrubs_secrets_and_retains_allowlist():
    tainted = {
        "PATH": "/usr/bin:/bin",
        "LANG": "en_US.UTF-8",
        "AWS_SECRET_ACCESS_KEY": "super_secret_aws_token",
        "GITHUB_TOKEN": "ghp_1234567890abcdef",
        "OPENAI_API_KEY": "sk-12345",
        "ARBITRARY_UNALLOWED_VAR": "some_value",
    }

    cleaned = clean_env(base_env=tainted)
    assert cleaned["PATH"] == "/usr/bin:/bin"
    assert cleaned["LANG"] == "en_US.UTF-8"
    assert cleaned["PYTHONHASHSEED"] == "0"

    # All credentials and unallowlisted keys must be absent
    assert "AWS_SECRET_ACCESS_KEY" not in cleaned
    assert "GITHUB_TOKEN" not in cleaned
    assert "OPENAI_API_KEY" not in cleaned
    assert "ARBITRARY_UNALLOWED_VAR" not in cleaned


def test_clean_env_with_extra_overrides():
    cleaned = clean_env(
        base_env={"PATH": "/bin"},
        extra_env={"CUSTOM_SETTING": "enabled", "PYTHONHASHSEED": "42"},
    )
    assert cleaned["CUSTOM_SETTING"] == "enabled"
    assert cleaned["PYTHONHASHSEED"] == "42"


def test_disposable_copy_basic_and_exclusions(tmp_path: Path):
    src = tmp_path / "source"
    src.mkdir()
    (src / "app.py").write_text("print('hello')")
    (src / ".env").write_text("SECRET=123")
    (src / ".git").mkdir()
    (src / ".git" / "config").write_text("[core]")
    (src / "pkg").mkdir()
    (src / "pkg" / "module.py").write_text("x = 1")
    (src / "pkg" / "__pycache__").mkdir()
    (src / "pkg" / "__pycache__" / "module.cpython-314.pyc").write_bytes(b"byte")

    disposable = create_disposable_copy(src)
    try:
        assert (disposable / "app.py").exists()
        assert (disposable / "pkg" / "module.py").exists()

        # Excluded items must not exist in copy
        assert not (disposable / ".env").exists()
        assert not (disposable / ".git").exists()
        assert not (disposable / "pkg" / "__pycache__").exists()
    finally:
        import shutil

        shutil.rmtree(disposable, ignore_errors=True)


def test_disposable_copy_symlink_boundary_escape_rejected(tmp_path: Path):
    outside = tmp_path / "outside_dir"
    outside.mkdir()
    secret_file = outside / "secret.txt"
    secret_file.write_text("confidential")

    src = tmp_path / "src_repo"
    src.mkdir()
    (src / "safe.py").write_text("safe = True")
    # Create symlink pointing outside source tree
    escape_link = src / "leak_symlink"
    try:
        escape_link.symlink_to(secret_file)
    except OSError:
        pytest.skip("Symlink creation not permitted in test environment")

    with pytest.raises(DisposableCopyError, match="points outside source tree"):
        create_disposable_copy(src)


def test_disposable_copy_file_budget_enforced(tmp_path: Path):
    src = tmp_path / "large_repo"
    src.mkdir()
    for i in range(10):
        (src / f"file_{i}.txt").write_text(f"content {i}")

    with pytest.raises(DisposableCopyError, match="exceeded maximum file limit"):
        create_disposable_copy(src, max_files=5)


def test_disposable_workspace_context_manager_cleanup(tmp_path: Path):
    src = tmp_path / "repo"
    src.mkdir()
    (src / "code.py").write_text("val = 42")

    target_path = None
    with disposable_workspace(src) as workspace:
        target_path = workspace
        assert workspace.is_dir()
        assert (workspace / "code.py").exists()

    # Workspace directory must be deleted after exiting context
    assert target_path is not None
    assert not target_path.exists()


def test_subprocess_sandbox_capabilities_and_env_isolation(tmp_path: Path):
    sandbox = SubprocessSandbox(default_timeout=10.0)

    assert InProcessSandbox().isolation == "none"
    assert sandbox.isolation == "process"
    assert sandbox.supports("process") is True
    assert sandbox.supports("none") is True
    assert sandbox.supports("container") is False

    # Set secret in current process os.environ
    os.environ["SECRET_CI_PASSWORD"] = "should_not_leak"

    script = tmp_path / "check_env.py"
    script.write_text(
        "import os, sys\n"
        "assert 'SECRET_CI_PASSWORD' not in os.environ, 'Secret leaked!'\n"
        "assert os.environ.get('PYTHONHASHSEED') == '0', 'Missing hash seed'\n"
        "print('PASS')\n"
    )

    try:
        result = sandbox.execute(
            cmd=[sys.executable, str(script)],
            cwd=tmp_path,
        )
        assert result.returncode == 0
        assert "PASS" in result.stdout
    finally:
        os.environ.pop("SECRET_CI_PASSWORD", None)


def test_subprocess_sandbox_execute_in_disposable_copy(tmp_path: Path):
    src = tmp_path / "repo"
    src.mkdir()
    (src / "data.txt").write_text("initial")

    sandbox = SubprocessSandbox()

    def build_cmd(workspace: Path) -> list[str]:
        # Script that mutates workspace file
        return [
            sys.executable,
            "-c",
            f"open('{workspace / 'data.txt'}', 'w').write('mutated')",
        ]

    res = sandbox.execute_in_disposable_copy(src, build_cmd)
    assert res.returncode == 0

    # Original repository file must NOT be mutated
    assert (src / "data.txt").read_text() == "initial"


def test_container_sandbox_capabilities_and_preflight():
    sandbox = ContainerSandbox(runtime="nonexistent_docker_binary_xyz")

    assert sandbox.isolation == "container"
    assert sandbox.supports("container") is True
    assert sandbox.supports("process") is True
    assert sandbox.supports("none") is True

    ready, limitations = sandbox.preflight()
    assert ready is False
    assert any("not found in PATH" in lim for lim in limitations)


def test_dynamic_verify_probe_uses_clean_env(tmp_path: Path):
    from plex.analyze.dynamic_verify import _run_probe

    target_file = tmp_path / "module.py"
    target_file.write_text(
        "import os\n"
        "def compute(n: int) -> int:\n"
        "    assert 'LEAKED_CI_TOKEN' not in os.environ, 'Token leaked to dynamic probe!'\n"
        "    return sum(range(n))\n"
    )

    os.environ["LEAKED_CI_TOKEN"] = "token_abc_123"
    try:
        probe = _run_probe(
            repo_root=tmp_path,
            path=target_file,
            qualname="compute",
            sizes=[10, 50, 100],
            timeout_seconds=5.0,
            trials=2,
            warmups=1,
            memory_limit_mb=None,
        )
        assert probe.error is None
        assert len(probe.times) == 3
    finally:
        os.environ.pop("LEAKED_CI_TOKEN", None)
