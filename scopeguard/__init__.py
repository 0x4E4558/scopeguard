"""ScopeGuard — Penetration Test Scope & ROE Builder"""
from .finding import Finding, FindingList, Severity
from .models import Engagement
from .validator import Validator
from .schema_loader import SchemaLoader
from .canonicalize import canonical_json, canonical_json_bytes
from .capability_map import (
    Capability,
    TAXONOMY_VERSION,
    categories_to_capabilities,
    capabilities_to_modules,
    category_capability_matrix,
)
from .scope_compiler import ScopeArtifact, ScopeCompilationError, compile_scope
from .scope_token import generate_scope_token, verify_scope_token

__all__ = [
    # Core
    "Finding", "FindingList", "Severity",
    "Engagement", "Validator", "SchemaLoader",
    # Canonicalization
    "canonical_json", "canonical_json_bytes",
    # Capability taxonomy
    "Capability", "TAXONOMY_VERSION",
    "categories_to_capabilities", "capabilities_to_modules",
    "category_capability_matrix",
    # Scope compilation
    "ScopeArtifact", "ScopeCompilationError", "compile_scope",
    # Scope token
    "generate_scope_token", "verify_scope_token",
]
