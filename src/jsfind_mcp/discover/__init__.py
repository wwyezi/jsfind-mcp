"""Discovery layer: extractors that turn page and script bodies into queue items."""

from .astapi import analyze_js
from .astparams import params_from_ast
from .basepath import base_path_names, normalize_base_path, scan_base_path_text
from .dynamic import fold_template, from_dynamic
from .hosts import classify as classify_host
from .hosts import host_from_url, hosts_from_text
from .html import parse_html
from .javascript import from_javascript, spa_evidence
from .jsparser import parser_available, parser_error
from .jsonshape import json_field_names
from .license import is_third_party_bundle, library_name
from .manifest import (
    MANIFEST_PATHS,
    find_manifest_references,
    parse_manifest,
)
from .openapi import (
    SPEC_PATHS,
    ApiSpec,
    SpecOperation,
    find_spec_references,
    parse_spec,
)
from .protocols import GraphQLOperation, from_protocols
from .requirejs import from_requirejs
from .routes import (
    DEFAULT_ROUTE_BUDGET,
    Route,
    collect_routes,
    renderable_paths,
    routes_from_source,
)
from .sourcemap import parse_source_map, source_map_reference
from .types import (
    BasePathCandidate,
    Candidate,
    HTMLResult,
    JSResult,
    Kind,
    SPAEvidence,
)
from .webpack import from_webpack
from .webpackast import webpack_ast_extract

__all__ = [
    "BasePathCandidate",
    "Candidate",
    "HTMLResult",
    "JSResult",
    "Kind",
    "SPAEvidence",
    "analyze_js",
    "ApiSpec",
    "collect_routes",
    "DEFAULT_ROUTE_BUDGET",
    "find_manifest_references",
    "find_spec_references",
    "from_protocols",
    "GraphQLOperation",
    "MANIFEST_PATHS",
    "parse_manifest",
    "parse_spec",
    "renderable_paths",
    "Route",
    "routes_from_source",
    "SPEC_PATHS",
    "SpecOperation",
    "base_path_names",
    "classify_host",
    "fold_template",
    "from_dynamic",
    "from_javascript",
    "from_requirejs",
    "from_webpack",
    "host_from_url",
    "hosts_from_text",
    "is_third_party_bundle",
    "json_field_names",
    "library_name",
    "normalize_base_path",
    "params_from_ast",
    "parse_html",
    "parse_source_map",
    "parser_available",
    "parser_error",
    "scan_base_path_text",
    "source_map_reference",
    "spa_evidence",
    "webpack_ast_extract",
]
