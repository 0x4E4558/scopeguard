"""
tests/test_capability_map.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Unit tests for the capability taxonomy and Nex module mapping.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from nex.capability_map import (
    Capability,
    CATEGORY_TO_CAPABILITIES,
    CAPABILITY_TO_NEX_MODULES,
    TAXONOMY_VERSION,
    categories_to_capabilities,
    capabilities_to_modules,
    category_capability_matrix,
)
from nex.models import TechniqueCategory


# ─── Taxonomy integrity ────────────────────────────────────────────────────────

class TestTaxonomyIntegrity:
    def test_every_capability_has_module_mapping(self):
        """Every Capability value must have at least one Nex module."""
        for cap in Capability:
            assert cap.value in CAPABILITY_TO_NEX_MODULES, (
                f"Capability {cap.value!r} has no Nex module mapping"
            )

    def test_every_capability_has_at_least_one_module(self):
        for cap in Capability:
            modules = CAPABILITY_TO_NEX_MODULES[cap.value]
            assert len(modules) >= 1, (
                f"Capability {cap.value!r} must map to at least one Nex module"
            )

    def test_every_technique_category_is_mapped(self):
        """Every TechniqueCategory value must appear in CATEGORY_TO_CAPABILITIES."""
        for cat in TechniqueCategory:
            assert cat.value in CATEGORY_TO_CAPABILITIES, (
                f"TechniqueCategory {cat.value!r} is not mapped in "
                "CATEGORY_TO_CAPABILITIES"
            )

    def test_module_ids_follow_naming_convention(self):
        """Module IDs must match the pattern nex.<domain>.<name>@<version>."""
        import re
        pattern = re.compile(r"^nex\.[a-z_]+\.[a-z_]+@\d+\.\d+$")
        for cap, modules in CAPABILITY_TO_NEX_MODULES.items():
            for mod in modules:
                assert pattern.match(mod), (
                    f"Module {mod!r} (under {cap!r}) does not follow the "
                    "nex.<domain>.<name>@<semver> naming convention"
                )

    def test_taxonomy_version_is_semver(self):
        parts = TAXONOMY_VERSION.split(".")
        assert len(parts) == 3
        for part in parts:
            assert part.isdigit(), f"TAXONOMY_VERSION part {part!r} is not numeric"

    def test_capability_module_lists_are_sorted(self):
        """Module lists must be sorted for deterministic output."""
        for cap, modules in CAPABILITY_TO_NEX_MODULES.items():
            assert list(modules) == sorted(modules), (
                f"Module list for {cap!r} is not sorted"
            )


# ─── categories_to_capabilities ───────────────────────────────────────────────

class TestCategoriesToCapabilities:
    def test_known_category_returns_capabilities(self):
        caps = categories_to_capabilities(["reconnaissance"])
        assert "RECONNAISSANCE" in caps
        assert "ENUMERATION" in caps

    def test_output_is_sorted(self):
        caps = categories_to_capabilities(["exploitation", "reconnaissance"])
        assert caps == sorted(caps)

    def test_output_is_deduplicated(self):
        caps = categories_to_capabilities(["reconnaissance", "reconnaissance"])
        assert len(caps) == len(set(caps))

    def test_unknown_category_is_skipped(self):
        caps = categories_to_capabilities(["totally_unknown_category"])
        assert caps == []

    def test_empty_input_returns_empty(self):
        assert categories_to_capabilities([]) == []

    def test_multiple_categories(self):
        caps = categories_to_capabilities(["reconnaissance", "exploitation"])
        assert "RECONNAISSANCE" in caps
        assert "EXPLOITATION" in caps

    def test_vuln_scanning_maps_to_three_capabilities(self):
        caps = categories_to_capabilities(["vuln_scanning"])
        assert "SCAN_PORTS" in caps
        assert "SCAN_WEB" in caps
        assert "VULN_SCANNING" in caps


# ─── capabilities_to_modules ──────────────────────────────────────────────────

class TestCapabilitiesToModules:
    def test_known_capability_returns_modules(self):
        modules = capabilities_to_modules(["RECONNAISSANCE"])
        assert "nex.recon.dns_enum@1.0" in modules
        assert "nex.recon.host_discovery@1.0" in modules

    def test_output_is_sorted(self):
        modules = capabilities_to_modules(["SCAN_PORTS", "RECONNAISSANCE"])
        assert modules == sorted(modules)

    def test_output_is_deduplicated(self):
        modules = capabilities_to_modules(["SCAN_PORTS", "SCAN_PORTS"])
        assert len(modules) == len(set(modules))

    def test_unknown_capability_is_skipped(self):
        modules = capabilities_to_modules(["TOTALLY_UNKNOWN"])
        assert modules == []

    def test_empty_input_returns_empty(self):
        assert capabilities_to_modules([]) == []


# ─── category_capability_matrix ───────────────────────────────────────────────

class TestCategoryCapabilityMatrix:
    def test_returns_dict_keyed_by_category(self):
        matrix = category_capability_matrix(["reconnaissance"])
        assert "reconnaissance" in matrix
        assert isinstance(matrix["reconnaissance"], list)

    def test_values_are_sorted(self):
        matrix = category_capability_matrix(["exploitation", "reconnaissance"])
        for caps in matrix.values():
            assert caps == sorted(caps)

    def test_unknown_category_excluded(self):
        matrix = category_capability_matrix(["unknown_cat"])
        assert matrix == {}

    def test_duplicate_categories_deduplicated(self):
        matrix = category_capability_matrix(["reconnaissance", "reconnaissance"])
        assert len(matrix) == 1
