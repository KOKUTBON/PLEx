"""Unit and integration tests for XML External Entity (XXE) rule, recipe, and fixer."""

from __future__ import annotations

import ast
from pathlib import Path

from plex.providers import AnalysisTask, XBoundaryProvider, run_providers
from plex.repair.coordinator import RemediationCoordinator
from plex.repair.xxe import XXEFixer
from plex.validate.http import HttpExchange, ScopedHttpClient, make_exchange
from plex.validate.recipes.base import ValidationHypothesis
from plex.validate.recipes.xxe import XXE_CANARY, XXERecipe
from plex.validate.scope import NetworkScope


def test_xxe_rule_detects_unsafe_etree_parsing(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "parser.py").write_text(
        "import xml.etree.ElementTree as ET\n\n"
        "def parse_xml_payload(xml_data):\n"
        "    root = ET.fromstring(xml_data)\n"
        "    return root.tag\n",
        encoding="utf-8",
    )

    outcome = run_providers(AnalysisTask(repo_root=repo), [XBoundaryProvider()])
    xxe_findings = [f for f in outcome.findings if f.rule_id == "xbnd.xxe"]
    assert len(xxe_findings) == 1
    assert xxe_findings[0].cwe == ["CWE-611"]


def test_xxe_rule_ignores_defusedxml_parsing(tmp_path: Path) -> None:
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "parser.py").write_text(
        "import defusedxml.ElementTree as ET\n\n"
        "def parse_xml_payload(xml_data):\n"
        "    root = ET.fromstring(xml_data)\n"
        "    return root.tag\n",
        encoding="utf-8",
    )

    outcome = run_providers(AnalysisTask(repo_root=repo), [XBoundaryProvider()])
    xxe_findings = [f for f in outcome.findings if f.rule_id == "xbnd.xxe"]
    assert len(xxe_findings) == 0


def test_xxe_fixer_migrates_etree_to_defusedxml() -> None:
    src = (
        "import xml.etree.ElementTree as ET\n\n"
        "def parse_doc(doc):\n"
        "    return ET.fromstring(doc)\n"
    )
    fixer = XXEFixer()
    fixed, changes = fixer.fix(src, "parser.py")

    assert "import defusedxml.ElementTree as ET" in fixed
    assert "xml.etree.ElementTree" not in fixed
    assert len(changes) == 1
    assert changes[0].rule_id == "xbnd.xxe"
    ast.parse(fixed)


def test_xxe_fixer_propose_patch() -> None:
    src = "import xml.etree.ElementTree as ET\n"
    fixer = XXEFixer()
    patch = fixer.propose_patch(src, "parser.py", finding_ids=("find:xxe_01",))

    assert patch is not None
    assert patch.rule_id == "xbnd.xxe"
    assert patch.engine == "xboundary"
    assert patch.generator == "plex.repair.xxe"
    assert "defusedxml.ElementTree" in patch.diff
    assert patch.rollback_diff != ""


def test_xxe_coordinator_end_to_end_verification(tmp_path: Path) -> None:
    repo = tmp_path / "service"
    repo.mkdir()
    (repo / "app.py").write_text(
        "import xml.etree.ElementTree as ET\n\n"
        "def handle_xml(content):\n"
        "    return ET.fromstring(content)\n",
        encoding="utf-8",
    )

    coordinator = RemediationCoordinator()
    plan = coordinator.plan_and_verify(repo, check_performance=False)

    xxe_findings = [f for f in plan.findings if f.rule_id == "xbnd.xxe"]
    assert len(xxe_findings) == 1
    assert len(plan.repairs) == 1
    # No behavioral test command was supplied, so the repair cannot be "verified",
    # and the fixer is proposal-only, so it is never written automatically.
    assert plan.repairs[0].status == "inconclusive"
    assert not plan.has_failures
    assert plan.applicable_repairs == ()


def test_xxe_recipe_reproduced_entity_expansion() -> None:
    recipe = XXERecipe()
    hyp = ValidationHypothesis(
        id="hyp-xxe-1",
        rule_id="xbnd.xxe",
        finding_id="f-xxe-01",
        target_url="http://127.0.0.1:5000/api/xml",
        method="POST",
    )

    class VulnerableXmlClient(ScopedHttpClient):
        def request(
            self,
            method: str,
            url: str,
            headers: dict[str, str] | None = None,
            data: str | bytes | None = None,
            timeout: float = 10.0,
        ) -> HttpExchange:
            body_str = str(data or "")
            if "canary" in body_str:
                return make_exchange(
                    method,
                    url,
                    headers or {},
                    body_str,
                    200,
                    {},
                    f"<result>{XXE_CANARY}</result>",
                    5.0,
                )
            return make_exchange(method, url, headers or {}, body_str, 200, {}, "<result>ok</result>", 5.0)

    client = VulnerableXmlClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is True
    assert result.status == "verified"
    assert XXE_CANARY in result.message


def test_xxe_recipe_reproduced_dtd_error() -> None:
    recipe = XXERecipe()
    hyp = ValidationHypothesis(
        id="hyp-xxe-2",
        rule_id="xbnd.xxe",
        finding_id="f-xxe-02",
        target_url="http://127.0.0.1:5000/api/upload",
        method="POST",
    )

    class DtdErrorXmlClient(ScopedHttpClient):
        def request(
            self,
            method: str,
            url: str,
            headers: dict[str, str] | None = None,
            data: str | bytes | None = None,
            timeout: float = 10.0,
        ) -> HttpExchange:
            body_str = str(data or "")
            if "SYSTEM" in body_str:
                return make_exchange(
                    method,
                    url,
                    headers or {},
                    body_str,
                    500,
                    {},
                    "XMLSyntaxError: failed to load external entity 'file:///plex_nonexistent_probe'",
                    5.0,
                )
            return make_exchange(method, url, headers or {}, body_str, 200, {}, "<result>ok</result>", 5.0)

    client = DtdErrorXmlClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is True
    assert result.status == "verified"
    assert "failed to load external entity" in result.message


def test_xxe_recipe_refuted_on_defused_endpoint() -> None:
    recipe = XXERecipe()
    hyp = ValidationHypothesis(
        id="hyp-xxe-3",
        rule_id="xbnd.xxe",
        finding_id="f-xxe-03",
        target_url="http://127.0.0.1:5000/api/safe",
        method="POST",
    )

    class SafeXmlClient(ScopedHttpClient):
        def request(
            self,
            method: str,
            url: str,
            headers: dict[str, str] | None = None,
            data: str | bytes | None = None,
            timeout: float = 10.0,
        ) -> HttpExchange:
            return make_exchange(method, url, headers or {}, str(data or ""), 200, {}, "<result>ok</result>", 5.0)

    client = SafeXmlClient(scope=NetworkScope(allowed_hosts={"127.0.0.1"}))
    result = recipe.execute(hyp, client)

    assert result.reproduced is False
    assert result.status == "refuted"
    assert "does not expand XML entities" in result.message


def test_validate_engine_xxe_recipe_wiring() -> None:
    from plex.validate.engine import RECIPES

    assert "xbnd.xxe" in RECIPES
    assert "val.xxe" in RECIPES
    assert isinstance(RECIPES["xbnd.xxe"], XXERecipe)
