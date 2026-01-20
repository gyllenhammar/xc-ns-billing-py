#!/usr/bin/env python3
"""
F5 XC Billing (BillingContext + BillableSource pattern, dynamic fields, WAF-restricted requests)

Outputs two reports for a selected time window:
- Per-namespace combined: HTTP requests (WAF and/or non-WAF) + feature-based LB counts/costs
- Per-cost-center summary: aggregated totals and costs

Billing Model:
- HTTP requests are billed in 1-million-request chunks. Partial chunks round up (ceiling).
  Example: 2.4 million requests = 3 chunks billed.
- WAF requests follow the same chunk-based model.
- Feature-based billables (public LBs, API Discovery, etc.) are per-unit flat fees.

Highlights:
- BillableSource declares produced_fields and cost_fields so schemas and total_cost are dynamic.
- FeatureCountBillable collapses multiple inventory-based billables (public LBs, API Discovery, Bot Protection, etc.)
  into one parameterized class—add new billables with one line in the sources list.
- compose_namespace_rows builds CSV fieldnames dynamically and computes total_cost by summing all cost fields.
- BillingContext caches shared calls (namespaces, inventory, graph results keyed by window + group_by).
- HttpWafRequestsBillable restricts requests to public LBs with WAF enabled, matched via vhost prefix.

Adjust endpoints/auth to your tenant. Use .env to override config.
"""

import os
import re
import csv
import json
import time
import logging
import argparse
import math
from typing import Any, Dict, List, Tuple
from datetime import datetime, timezone
from collections import defaultdict

from dotenv import load_dotenv
import requests
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import io
import tempfile
import os as os_module

# ------------------------------------------------------------------------------
# Argument parsing
# ------------------------------------------------------------------------------
parser = argparse.ArgumentParser(
    description="F5 XC Billing Report Generator",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog="""
Examples:
  python main.py                           # Last 30 days (default)
  python main.py --start 2025-11-01 --end 2025-11-30  # Specific date range
  python main.py --namespace prod-acme    # Only prod-acme namespace
  python main.py --cost-center "Team A"   # Only Team A cost center
  python main.py --format csv              # CSV only (no JSON)
  python main.py --validate                # Pre-flight checks only
  python main.py --dry-run                 # Show what would be calculated (no files)
  python main.py --log DEBUG               # Detailed diagnostics
""")

# Time window arguments
time_group = parser.add_argument_group('time window')
time_group.add_argument('--start', '--start-date',
                        help='Start date (YYYY-MM-DD). Default: 30 days ago',
                        metavar='YYYY-MM-DD')
time_group.add_argument('--end', '--end-date',
                        help='End date (YYYY-MM-DD). Default: today',
                        metavar='YYYY-MM-DD')

# Filtering arguments
filter_group = parser.add_argument_group('filtering')
filter_group.add_argument('--namespace',
                          help='Filter to specific namespace (comma-separated for multiple)',
                          metavar='NAME')
filter_group.add_argument('--cost-center',
                          help='Filter to specific cost center (comma-separated for multiple)',
                          metavar='NAME')

# Output arguments
output_group = parser.add_argument_group('output')
output_group.add_argument('--format', default='both', choices=['csv', 'json', 'both'],
                          help='Output format (default: both)')
output_group.add_argument('--no-metadata', action='store_true',
                          help='Omit metadata headers in CSV files')
output_group.add_argument('--pdf', action='store_true',
                          help='Generate PDF report with graphs for cost centers')

# Mode arguments
mode_group = parser.add_argument_group('mode')
mode_group.add_argument('--validate', action='store_true',
                        help='Run pre-flight validation checks only (no billing calculation)')
mode_group.add_argument('--dry-run', action='store_true',
                        help='Calculate billing but do not write output files')
mode_group.add_argument('--log', default='INFO',
                        choices=['DEBUG', 'INFO',
                                 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Set the logging level (default: INFO)')

args = parser.parse_args()

# ------------------------------------------------------------------------------
# Logging configuration
# ------------------------------------------------------------------------------
logging.basicConfig(level=args.log.upper(),
                    format="%(asctime)s %(levelname)s %(message)s")

# ------------------------------------------------------------------------------
# Load config from .env (override defaults via environment)
# ------------------------------------------------------------------------------
load_dotenv()

API_BASE = os.getenv("F5XC_API_BASE", "").rstrip("/")

# Validate API_BASE early
if not API_BASE or not API_BASE.startswith(("http://", "https://")):
    raise RuntimeError(
        "F5XC_API_BASE must be set to a valid HTTP(S) URL in .env or environment. "
        "Example: F5XC_API_BASE=https://f5-emea-ent.console.ves.volterra.io/api"
    )

API_TOKEN = os.getenv("F5XC_API_TOKEN", "")

# Pricing (support both REQUEST_PRICE_PER_MILLION and PRICE_PER_MILLION; first one wins)
REQUEST_PRICE_PER_MILLION = float(
    os.getenv("REQUEST_PRICE_PER_MILLION", os.getenv("PRICE_PER_MILLION", "0.0")))
WAF_REQUEST_PRICE_PER_MILLION = float(
    os.getenv("WAF_REQUEST_PRICE_PER_MILLION", "10.0"))
PRICE_PER_PUBLIC_LB = float(os.getenv("PRICE_PER_PUBLIC_LB", "100.0"))
PRICE_PER_API_DISCOVERY_LB = float(
    os.getenv("PRICE_PER_API_DISCOVERY_LB", "200.0"))
PRICE_PER_BOT_PROTECTION_LB = float(
    os.getenv("PRICE_PER_BOT_PROTECTION_LB", "150.0"))

# Endpoints (adjust per tenant; override in .env as needed)
NAMESPACES_ENDPOINT = os.getenv(
    "F5XC_NAMESPACES_ENDPOINT", f"{API_BASE}/web/namespaces")
GRAPH_ENDPOINT = os.getenv(
    "F5XC_GRAPH_ENDPOINT", f"{API_BASE}/data/namespaces/system/graph/all_ns_service")
APP_OBJECTS_ENDPOINT = os.getenv(
    "F5XC_APP_OBJECTS_ENDPOINT", f"{API_BASE}/config/namespaces/system/all_application_inventory")

# Graph Service filters and grouping
VHOST_TYPE = os.getenv("F5XC_VHOST_TYPE", "HTTP_LOAD_BALANCER")
GROUP_BY_DIM = os.getenv("F5XC_GROUP_BY", "NAMESPACE")
VHOST_DIM = os.getenv("F5XC_VHOST_DIM", "VHOST")
VHOST_PREFIX = os.getenv("F5XC_VHOST_PREFIX", "ves-io-http-loadbalancer-")

# Cost center tag configuration
# Key can be customized via env variable (default: "cost_center")
# Format: {{key:value}} where key and value are configurable
COST_CENTER_TAG_KEY = os.getenv("F5XC_COST_CENTER_TAG_KEY", "cost_center")
COST_CENTER_TAG_REGEX = re.compile(
    r"\{\{\s*" + re.escape(COST_CENTER_TAG_KEY) + r"\s*:\s*([A-Za-z0-9._\- ]+)\s*\}\}", re.IGNORECASE)

# HTTP retry controls
MAX_RETRIES = int(os.getenv("F5XC_MAX_RETRIES", "3"))
RETRY_BACKOFF_SECONDS = float(os.getenv("F5XC_RETRY_BACKOFF", "2"))

# Output folder (relative to current working directory)
OUTPUT_FOLDER = os.getenv("F5XC_OUTPUT_FOLDER", "./billing_reports")

# ------------------------------------------------------------------------------
# Output folder helpers
# ------------------------------------------------------------------------------


def ensure_output_folder() -> str:
    """
    Create the output folder if it doesn't exist and return its absolute path.
    Validates write permissions before returning.
    """
    try:
        if not os.path.exists(OUTPUT_FOLDER):
            os.makedirs(OUTPUT_FOLDER, exist_ok=True)
            logging.debug(f"Created output folder: {OUTPUT_FOLDER}")

        # Verify we have write access
        if not os.access(OUTPUT_FOLDER, os.W_OK):
            raise PermissionError(
                f"No write permission for directory: {OUTPUT_FOLDER}")

        return os.path.abspath(OUTPUT_FOLDER)
    except (OSError, PermissionError) as e:
        raise RuntimeError(
            f"Failed to prepare output folder '{OUTPUT_FOLDER}': {e}. "
            f"Check that the path exists and you have write permissions."
        )


def get_output_path(filename: str) -> str:
    """
    Return the full path for an output file in the output folder.
    """
    return os.path.join(ensure_output_folder(), filename)

# ------------------------------------------------------------------------------
# CLI argument parsing helpers
# ------------------------------------------------------------------------------


def parse_date_arg(date_str: str | None, default: datetime | None = None) -> datetime:
    """
    Parse a CLI date argument (YYYY-MM-DD format) into a datetime at UTC midnight.
    Returns the provided default if date_str is None.
    """
    if date_str is None:
        if default is None:
            raise ValueError("No date provided and no default available")
        return default
    try:
        parsed = datetime.strptime(date_str, "%Y-%m-%d")
        return parsed.replace(tzinfo=timezone.utc)
    except ValueError as e:
        raise ValueError(
            f"Invalid date format '{date_str}'. Use YYYY-MM-DD format.") from e


def parse_namespace_filter(namespace_arg: str | None) -> set[str] | None:
    """
    Parse the --namespace argument into a set of namespace names.
    Returns None if no filter is provided.
    """
    if not namespace_arg:
        return None
    return {ns.strip() for ns in namespace_arg.split(",") if ns.strip()}


def parse_cost_center_filter(cost_center_arg: str | None) -> set[str] | None:
    """
    Parse the --cost-center argument into a set of cost center names.
    Returns None if no filter is provided.
    """
    if not cost_center_arg:
        return None
    return {cc.strip() for cc in cost_center_arg.split(",") if cc.strip()}


def filter_rows_by_namespace(rows: List[Dict[str, Any]], namespaces: set[str]) -> List[Dict[str, Any]]:
    """
    Filter rows to only those in the provided namespace set.
    """
    return [r for r in rows if r.get("namespace") in namespaces]


def filter_rows_by_cost_center(rows: List[Dict[str, Any]], cost_centers: set[str]) -> List[Dict[str, Any]]:
    """
    Filter rows to only those in the provided cost center set.
    """
    return [r for r in rows if r.get("cost_center") in cost_centers]


def validate_configuration() -> bool:
    """
    Run pre-flight validation checks. Returns True if all checks pass.
    Raises RuntimeError if critical checks fail.
    """
    logging.info("Running pre-flight validation checks...")

    # Check API credentials
    if not API_BASE or not API_TOKEN:
        raise RuntimeError(
            "F5XC_API_BASE and F5XC_API_TOKEN must be set in .env or environment")
    logging.info("✓ API credentials configured")

    # Check API connectivity
    try:
        resp = request_with_retries("GET", NAMESPACES_ENDPOINT, timeout=10)
        resp.raise_for_status()
        logging.info("✓ API connectivity OK")
    except Exception as e:
        raise RuntimeError(f"Failed to connect to API: {e}")

    # Check output folder
    try:
        ensure_output_folder()
        logging.info("✓ Output folder is writable")
    except Exception as e:
        raise RuntimeError(f"Output folder check failed: {e}")

    logging.info("✓ All validation checks passed")
    return True

# ------------------------------------------------------------------------------
# Billing helpers
# ------------------------------------------------------------------------------


def calculate_cost_by_chunks(request_count: int, price_per_million: float, chunk_size: int = 1_000_000) -> float:
    """
    Calculate cost based on 1-million-request chunks (or custom chunk_size).
    Partial chunks are rounded up (ceiling).

    Example:
      - 2,400,000 requests @ $10/million = 3 chunks * $10 = $30
      - 1 request @ $10/million = 1 chunk * $10 = $10
      - 1,000,000 requests @ $10/million = 1 chunk * $10 = $10
    """
    chunks_needed = math.ceil(request_count / chunk_size)
    return chunks_needed * price_per_million

# ------------------------------------------------------------------------------
# API helpers
# ------------------------------------------------------------------------------


def auth_headers() -> Dict[str, str]:
    """
    Build headers for F5 XC API calls.
    IMPORTANT: Confirm the Authorization scheme for your tenant:
      - Some tenants use "Authorization: Api-Token <token>"
      - Others use "Authorization: APIToken <token>"
    """
    if not API_TOKEN:
        raise RuntimeError("Set F5XC_API_TOKEN in your environment or .env")
    return {
        # "Authorization": f"Api-Token {API_TOKEN}",  # try this if APIToken fails
        "Authorization": f"APIToken {API_TOKEN}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def request_with_retries(method: str, url: str, timeout: int = 60, **kwargs) -> requests.Response:
    """
    Perform an HTTP request with retries/backoff on non-2xx responses.
    Raises on final failure.
    """
    for attempt in range(1, MAX_RETRIES + 1):
        resp = requests.request(
            method, url, headers=auth_headers(), timeout=timeout, **kwargs)
        if 200 <= resp.status_code < 300:
            return resp
        logging.warning(
            f"{method} {url} failed (attempt {attempt}) {resp.status_code}: {resp.text}")
        if attempt < MAX_RETRIES:
            time.sleep(RETRY_BACKOFF_SECONDS * attempt)
    resp.raise_for_status()
    return resp

# ------------------------------------------------------------------------------
# Time window helpers
# ------------------------------------------------------------------------------


def last_30_days_range(now: datetime | None = None) -> Tuple[int, int]:
    """
    Returns (start_epoch_s, end_epoch_s) for the last 30 days in UTC.
    """
    now = now or datetime.now(timezone.utc)
    end_s = int(now.timestamp())
    start_s = end_s - 30 * 86400
    return start_s, end_s


def format_period_labels(start_s: int, end_s: int) -> Tuple[str, str, str, str]:
    """
    Return (period_start_iso, period_end_iso, start_label, end_label) for a given window.
    """
    period_start_iso = datetime.fromtimestamp(
        start_s, tz=timezone.utc).isoformat()
    period_end_iso = datetime.fromtimestamp(end_s, tz=timezone.utc).isoformat()
    start_label = datetime.fromtimestamp(
        start_s, tz=timezone.utc).strftime("%Y-%m-%d")
    end_label = datetime.fromtimestamp(
        end_s, tz=timezone.utc).strftime("%Y-%m-%d")
    return period_start_iso, period_end_iso, start_label, end_label

# ------------------------------------------------------------------------------
# Namespace helpers
# ------------------------------------------------------------------------------


def list_namespaces() -> List[Dict[str, Any]]:
    """
    Fetch a list of namespace dicts; normalize to a list.
    """
    resp = request_with_retries("GET", NAMESPACES_ENDPOINT)
    data = resp.json()
    count = len(data.get("items", [])) if isinstance(
        data, dict) and "items" in data else (len(data) if isinstance(data, list) else 1)
    logging.debug(f"list_namespaces: got {count} namespaces")
    if isinstance(data, dict) and "items" in data:
        return data["items"]
    elif isinstance(data, list):
        return data
    else:
        return [data]


def safe_ns_name_and_desc(ns: Dict[str, Any]) -> Tuple[str | None, str]:
    """
    Safely read namespace name and description from varied object shapes.
    """
    if not isinstance(ns, dict):
        return None, ""
    metadata = ns.get("metadata") or {}
    spec = ns.get("spec") or {}
    nid = ns.get("id") or {}
    ns_name = (
        ns.get("name")
        or metadata.get("name")
        or ns.get("namespace")
        or spec.get("namespace")
        or nid.get("namespace")
    )
    desc = ns.get("description")
    if desc is None:
        desc = metadata.get("description") or spec.get("description") or ""
    return ns_name, desc


def parse_cost_center_from_description(description: str | None) -> str | None:
    """
    Parse the '{{key:value}}' tag from a namespace description (case-insensitive).
    Key is configurable via F5XC_COST_CENTER_TAG_KEY env variable (default: "cost_center").
    Example: "Production env {{cost_center: Acme Corp}}" -> "Acme Corp"
    """
    if not description:
        return None
    m = COST_CENTER_TAG_REGEX.search(description)
    if m:
        return m.group(1).strip()
    return None


def get_ns_to_cost_center(namespaces: List[Dict[str, Any]] | None = None) -> Dict[str, str]:
    """
    Build a mapping {namespace_name: cost_center_name} by scanning namespace descriptions.
    """
    if namespaces is None:
        namespaces = list_namespaces()
    ns_to_cost_center: Dict[str, str] = {}
    for ns in namespaces:
        if not isinstance(ns, dict):
            continue
        ns_name, desc = safe_ns_name_and_desc(ns)
        if not ns_name:
            continue
        ns_to_cost_center[ns_name] = parse_cost_center_from_description(
            desc) or "Unassigned"
    logging.debug(
        f"get_ns_to_cost_center: mapped {len(ns_to_cost_center)} namespaces to cost centers")
    return ns_to_cost_center

# ------------------------------------------------------------------------------
# Graph Service helpers
# ------------------------------------------------------------------------------


def parse_step_to_seconds(step_str: str | None) -> int:
    """
    Parse step strings like '5m', '1440m', '1h', '86400s' into seconds. Default 86400 on failure.
    """
    if not step_str:
        return 86400
    try:
        num, unit = "", ""
        for ch in step_str:
            if ch.isdigit():
                num += ch
            else:
                unit += ch
        n = int(num) if num else 0
        unit = unit.lower()
        if unit in ("s", "sec", "secs"):
            return n
        if unit in ("m", "min", "mins"):
            return n * 60
        if unit in ("h", "hr", "hrs"):
            return n * 3600
        if unit in ("d", "day", "days"):
            return n * 86400
    except Exception as e:
        logging.warning(
            f"parse_step_to_seconds: Failed to parse step string '{step_str}': {e}. "
            f"Using default 86400s (1 day). This may affect request count accuracy."
        )
    return 86400


def query_http_requests(
    start_epoch_s: int,
    end_epoch_s: int,
    group_by_dims: list,  # e.g., ["NAMESPACE"] or ["NAMESPACE", "VHOST"]
) -> dict:
    """
    Generic Graph Service query grouped by the requested dimensions.
    Sums HTTP_REQUEST_RATE (req/s) across the window by multiplying each point by bucket_seconds.

    Returns:
      - If group_by_dims == ["NAMESPACE"], a dict {namespace: total_requests}
      - If group_by_dims == ["NAMESPACE", "VHOST"], a dict {(namespace, vhost): total_requests}
    """
    body = {
        "field_selector": {"node": {"metric": {"downstream": ["HTTP_REQUEST_RATE"]}}},
        "step": "auto",
        "namespace": "system",  # keep/remove based on your tenant; examples use "system"
        "end_time": str(end_epoch_s),
        "start_time": str(start_epoch_s),
        "label_filter": [{"label": "LABEL_VHOST_TYPE", "op": "EQ", "value": VHOST_TYPE}],
        "group_by": group_by_dims,
    }
    logging.debug(
        f"query_http_requests: group_by={group_by_dims}, window=({start_epoch_s},{end_epoch_s})")
    resp = request_with_retries("POST", GRAPH_ENDPOINT, json=body)
    payload = resp.json()

    step_str = payload.get("step")
    bucket_seconds = parse_step_to_seconds(step_str)
    nodes = payload.get("data", {}).get("nodes", [])
    logging.debug(
        f"query_http_requests: step='{step_str}' => {bucket_seconds}s buckets, nodes={len(nodes)}")

    if not nodes:
        logging.warning(
            f"query_http_requests: No nodes found in Graph Service response. "
            f"Check label_filter, endpoint, and time window. "
            f"Response keys: {list(payload.keys())}"
        )

    totals = {}

    def _id_value(node_id: dict, dim: str) -> str | None:
        # Try lowercase then uppercase
        val = node_id.get(dim.lower())
        if val is None:
            val = node_id.get(dim.upper())
        return str(val) if val is not None else None

    for node in nodes:
        node_id = node.get("id", {}) or {}
        key_parts = []
        for dim in group_by_dims:
            val = _id_value(node_id, dim)
            if val is None:
                key_parts = []
                break
            key_parts.append(val)
        if not key_parts:
            continue
        key = key_parts[0] if len(key_parts) == 1 else tuple(key_parts)

        total_requests = 0.0
        downstream = (node.get("data") or {}).get(
            "metric", {}).get("downstream", [])
        for series in downstream:
            if series.get("type") == "HTTP_REQUEST_RATE":
                raw_points = (series.get("value") or {}).get("raw", [])
                for p in raw_points:
                    try:
                        rate = float(p.get("value", "0") or "0")
                    except Exception:
                        rate = 0.0
                    total_requests += rate * bucket_seconds

        totals[key] = totals.get(key, 0) + int(round(total_requests))

    logging.debug(
        f"query_http_requests: produced {len(totals)} grouped totals")
    return totals

# ------------------------------------------------------------------------------
# Inventory fetch + extraction
# ------------------------------------------------------------------------------


def query_application_objects_inventory() -> List[Dict[str, Any]]:
    """
    General-purpose inventory fetcher. Returns a normalized list (no filtering).
    """
    body = {
        "http_load_balancer_filter": {},
        "tcp_load_balancer_filter": {},
        "cdn_load_balancer_filter": {},
        "bigip_load_balancer_filter": {},
    }
    resp = request_with_retries("POST", APP_OBJECTS_ENDPOINT, json=body)
    data = resp.json()

    if isinstance(data, dict) and "items" in data:
        items = data["items"]
    elif isinstance(data, list):
        items = data
    else:
        items = [data]

    logging.debug(f"query_application_objects_inventory: entries={len(items)}")
    if not items:
        logging.warning(
            "query_application_objects_inventory: No inventory items returned. "
            "This may result in zero counts for feature-based billables (public LBs, API Discovery, Bot Protection). "
            "Check API endpoint, filters, and tenant configuration."
        )
    if items:
        logging.debug(
            f"inventory sample: {json.dumps(items[0], indent=2)[:2000]}...")
    return items


def _is_feature_enabled(val: Any) -> bool:
    """
    Normalize 'enabled' flags that may be boolean or empty objects/lists:
    Treat as enabled if val is not None/False/""/0. Empty dict/list are considered enabled.
    """
    return val not in (None, False, "", 0)


def _normalize_lb_record(lb_obj: Dict[str, Any], lb_kind: str | None = None) -> Dict[str, Any]:
    """
    Normalize a raw LB record into a canonical dict with consistent fields and booleans.

    Returns at least:
      - lb_kind: str (HTTP/TCP/CDN/BIGIP/etc. if known)
      - name: str
      - namespace: str
      - vip_type: str (e.g., "Public" or "Private")
      - domains: List[str] (empty if not applicable to the kind)
      - public_advertisment_enabled: bool  (handles the misspelling)
      - private_advertisement_enabled: bool
      - waf_enabled: bool
      - is_public: bool  (derived from vip_type OR public_advertisment_enabled)
      - is_private: bool (derived from private_advertisement_enabled)
      - plus normalized booleans for any keys ending with '_enabled' found in the raw record.
    """
    rec: Dict[str, Any] = {}
    rec["lb_kind"] = lb_kind or str(lb_obj.get("lb_kind") or "")

    # Identity / basics
    rec["name"] = str(lb_obj.get("name") or "")
    rec["namespace"] = str(lb_obj.get("namespace") or "")
    rec["vip_type"] = str(lb_obj.get("vip_type") or "")

    # Domains might be absent for non-HTTP LBs; normalize to a list
    raw_domains = lb_obj.get("domains")
    rec["domains"] = [str(d) for d in (raw_domains or [])] if isinstance(
        raw_domains, (list, tuple)) else []

    # Normalize all *_enabled flags heuristically
    for key, val in lb_obj.items():
        if isinstance(key, str) and key.endswith("_enabled"):
            rec[key] = _is_feature_enabled(val)

    # Common frequently used flags
    rec["waf_enabled"] = _is_feature_enabled(lb_obj.get("waf_enabled"))

    # Public/private advertisement (supports misspelling)
    public_adv = lb_obj.get("public_advertisment_enabled")
    private_adv = lb_obj.get("private_advertisement_enabled") or lb_obj.get(
        "private_advertisment_enabled")
    rec["public_advertisment_enabled"] = _is_feature_enabled(public_adv)
    rec["private_advertisement_enabled"] = _is_feature_enabled(private_adv)

    # Derived booleans
    rec["is_public"] = (rec["vip_type"].strip().lower() ==
                        "public") or rec["public_advertisment_enabled"]
    rec["is_private"] = rec["private_advertisement_enabled"]

    return rec


def extract_loadbalancers_normalized(
    inventory: Any,
    required_all: List[str] | None = None,
    required_equals: Dict[str, Any] | None = None,
    include_fields: List[str] | None = None,
    lb_kinds: List[str] | None = None,
    wrapper_map: Dict[str, str] | None = None,
) -> List[Dict[str, Any]]:
    """
    Generic normalized extractor for load balancers across families (HTTP, TCP, CDN, BIGIP).

    - Reads known wrapper blocks (e.g., "http_loadbalancers": {"httplb_results": [...]}) and direct LB records.
    - Normalizes each raw LB record to a canonical shape via _normalize_lb_record.
    - Filters records by required_all (truthy AND) and required_equals (exact matches).
    - Returns base fields plus optional include_fields from the normalized record.
    - Tags each row with lb_kind so downstream logic is aware.

    Adjust wrapper_map keys/arrays to match your tenant’s schema for non-HTTP families.
    """
    wrapper_map = wrapper_map or {
        "http_loadbalancers": "httplb_results",
        # adjust if your tenant uses different key
        "tcp_loadbalancers": "tcplb_results",
        "cdn_loadbalancers": "cdn_results",       # adjust if needed
        "bigip_loadbalancers": "bigip_results",   # adjust if needed
    }

    entries = inventory if isinstance(inventory, list) else [inventory]
    results: List[Dict[str, Any]] = []
    raw_lb_count = 0
    filtered_count = 0

    def _matches_filters(norm: Dict[str, Any]) -> bool:
        if required_all:
            for attr in required_all:
                if not bool(norm.get(attr)):
                    return False
        if required_equals:
            for attr, expected in required_equals.items():
                if norm.get(attr) != expected:
                    return False
        return True

    def _emit_row(norm: Dict[str, Any]):
        out = {
            "lb_kind": norm.get("lb_kind", ""),
            "name": norm["name"],
            "namespace": norm["namespace"],
            "vip_type": norm["vip_type"],
            "domains": norm["domains"],
        }
        if include_fields:
            for fld in include_fields:
                if fld in norm:
                    out[fld] = norm[fld]
        results.append(out)

    def _process_lb(lb_obj: Dict[str, Any], lb_kind: str | None):
        nonlocal raw_lb_count, filtered_count
        if not isinstance(lb_obj, dict):
            return
        raw_lb_count += 1
        norm = _normalize_lb_record(lb_obj, lb_kind=lb_kind)
        if not norm["name"] or not norm["namespace"]:
            logging.warning(
                f"extract_loadbalancers_normalized: Skipping LB with missing name or namespace. "
                f"lb_kind={lb_kind}, name={norm.get('name')}, namespace={norm.get('namespace')}"
            )
            return
        if not _matches_filters(norm):
            return
        _emit_row(norm)
        filtered_count += 1

    for entry in entries:
        if not isinstance(entry, dict):
            continue

        # Wrapper families
        for family_key, array_key in wrapper_map.items():
            if lb_kinds and family_key not in lb_kinds:
                continue
            block = entry.get(family_key)
            if block is not None and not isinstance(block, dict):
                logging.warning(
                    f"extract_loadbalancers_normalized: '{family_key}' found but not a dict "
                    f"(got {type(block).__name__}). Check API response schema."
                )
                continue
            if isinstance(block, dict):
                lbs = block.get(array_key) or []
                for lb in lbs:
                    _process_lb(lb, lb_kind=family_key)

        # Direct LB record (heuristic)
        if {"name", "namespace", "vip_type"} <= set(entry.keys()):
            _process_lb(entry, lb_kind="direct")

    logging.debug(
        "extract_loadbalancers_normalized: raw LBs=%d, matched=%d, required_all=%s, required_equals=%s, include_fields=%s, lb_kinds=%s",
        raw_lb_count, filtered_count, required_all, required_equals, include_fields, lb_kinds,
    )
    if results:
        logging.debug(
            "extract_loadbalancers_normalized: sample=%s", results[:3])
    return results


def group_lbs_by_namespace(
    lbs: List[Dict[str, Any]],
    dedupe: bool = True,
) -> Dict[str, Dict[str, Any]]:
    """
    Group load-balancer records by namespace. No filtering is performed here.

    Input expectations per record (normalized upstream):
      - name: str
      - namespace: str
      - domains: List[str] (may be empty)
      - lb_kind: str (optional; e.g., "http_loadbalancers", "tcp_loadbalancers", ...)
      - waf_enabled: bool (optional; only meaningful for HTTP LBs)

    Output per namespace:
      {
        "lb_count": int,
        "waf_count": int,                 # number of LBs with waf_enabled == True (if present; else 0)
        "by_kind": { kind: count, ... },  # per-family breakdown
        "lb_names": [ ... ],
        "domains": [ ... ],
      }
    """
    groups: Dict[str, Dict[str, Any]] = {}
    name_sets: Dict[str, set] = defaultdict(set)
    domain_sets: Dict[str, set] = defaultdict(set)

    for lb in lbs:
        if not isinstance(lb, dict):
            continue

        ns = lb.get("namespace") or ""
        if not ns:
            continue

        g = groups.setdefault(ns, {
            "lb_count": 0,
            "waf_count": 0,
            "by_kind": defaultdict(int),
            "lb_names": [],
            "domains": [],
        })

        g["lb_count"] += 1
        kind = lb.get("lb_kind") or "unknown"
        g["by_kind"][kind] += 1

        if lb.get("waf_enabled"):
            g["waf_count"] += 1

        name = lb.get("name")
        if name:
            name_sets[ns].add(str(name))
        for d in lb.get("domains") or []:
            if d:
                domain_sets[ns].add(str(d))

    for ns, g in groups.items():
        names = name_sets[ns]
        domains = domain_sets[ns]
        g["lb_names"] = sorted(names) if dedupe else list(names)
        g["domains"] = sorted(domains) if dedupe else list(domains)
        g["by_kind"] = dict(g["by_kind"])

    logging.debug("group_lbs_by_namespace: grouped namespaces=%d", len(groups))
    return groups

# ------------------------------------------------------------------------------
# BillingContext (shared caches for a single run)
# ------------------------------------------------------------------------------


class BillingContext:
    """
    Lazily cached shared data for one billing run.

    Caches:
    - namespaces
    - ns_to_cost_center mapping
    - inventory
    - graph requests keyed by (start_s, end_s, group_by_dims)
    """

    def __init__(self):
        self._namespaces: List[Dict[str, Any]] | None = None
        self._ns_to_cost_center: Dict[str, str] | None = None
        self._inventory: List[Dict[str, Any]] | None = None
        self._graph_requests_cache: Dict[Tuple[int,
                                               int, Tuple[str, ...]], dict] = {}

    def get_namespaces(self) -> List[Dict[str, Any]]:
        if self._namespaces is None:
            self._namespaces = list_namespaces()
        return self._namespaces

    def get_ns_to_cost_center(self) -> Dict[str, str]:
        if self._ns_to_cost_center is None:
            self._ns_to_cost_center = get_ns_to_cost_center(
                self.get_namespaces())
        return self._ns_to_cost_center

    def get_inventory(self) -> List[Dict[str, Any]]:
        if self._inventory is None:
            self._inventory = query_application_objects_inventory()
        return self._inventory

    def get_http_requests_grouped(self, start_s: int, end_s: int, group_by_dims: List[str]) -> dict:
        key = (start_s, end_s, tuple(group_by_dims))
        if key not in self._graph_requests_cache:
            logging.debug(f"BillingContext: cache miss for key={key}")
            self._graph_requests_cache[key] = query_http_requests(
                start_s, end_s, group_by_dims)
        else:
            logging.debug(f"BillingContext: cache hit for key={key}")
        return self._graph_requests_cache[key]

# ------------------------------------------------------------------------------
# BillableSource pattern (dynamic fields)
# ------------------------------------------------------------------------------


class BillableSource:
    """
    Base class for a pluggable billable source.
    Subclasses implement gather(start_s, end_s, ctx) -> Dict[namespace, Dict[metric/cost]].

    Also declare:
      - produced_fields: list of field names this source adds to each row
      - cost_fields: subset of produced_fields that should be summed into total_cost
    """
    name: str = "base"

    @property
    def produced_fields(self) -> List[str]:
        return []

    @property
    def cost_fields(self) -> List[str]:
        return []

    def gather(self, start_s: int, end_s: int, ctx: BillingContext) -> Dict[str, Dict[str, Any]]:
        raise NotImplementedError


class HttpRequestsBillable(BillableSource):
    """
    Billable source for all HTTP requests (via Graph Service), grouped by namespace.
    """
    name = "http_requests"

    @property
    def produced_fields(self) -> List[str]:
        return ["http_requests", "request_cost"]

    @property
    def cost_fields(self) -> List[str]:
        return ["request_cost"]

    def gather(self, start_s: int, end_s: int, ctx: BillingContext) -> Dict[str, Dict[str, Any]]:
        ns_totals = ctx.get_http_requests_grouped(
            start_s, end_s, ["NAMESPACE"])
        out = {
            ns: {
                "http_requests": int(total),
                "request_cost": calculate_cost_by_chunks(int(total), REQUEST_PRICE_PER_MILLION),
            }
            for ns, total in ns_totals.items()
        }
        logging.debug(
            f"{self.name}.gather: namespaces={len(out)} (first few: {list(out)[:5]})")
        return out


class HttpWafRequestsBillable(BillableSource):
    """
    Billable source for HTTP requests (via Graph Service), restricted to public WAF-enabled LBs.
    """
    name = "http_waf_requests"

    @property
    def produced_fields(self) -> List[str]:
        return ["http_waf_requests", "waf_request_cost"]

    @property
    def cost_fields(self) -> List[str]:
        return ["waf_request_cost"]

    def gather(self, start_s: int, end_s: int, ctx: BillingContext) -> Dict[str, Dict[str, Any]]:
        inv = ctx.get_inventory()
        waf_public_lbs = extract_loadbalancers_normalized(
            inv,
            lb_kinds=["http_loadbalancers"],
            required_all=["is_public", "waf_enabled"],
            include_fields=["is_public", "waf_enabled"]
        )

        # Build allowed vhost names using the known prefix pattern.
        allowed_vhosts_by_ns: Dict[str, set] = {}
        for lb in waf_public_lbs:
            ns = lb["namespace"]
            vhost_name = f"{VHOST_PREFIX}{lb['name']}"
            allowed_vhosts_by_ns.setdefault(ns, set()).add(vhost_name)

        sample_allowed = {ns: sorted(list(vs))[:3] for ns, vs in list(
            allowed_vhosts_by_ns.items())[:3]}
        logging.debug("%s.gather: allowed vhosts by ns (sample) = %s",
                      self.name, sample_allowed)

        # Graph: {(ns, vhost): total_requests}
        ns_vhost_totals = ctx.get_http_requests_grouped(
            start_s, end_s, ["NAMESPACE", "VHOST"])
        if not ns_vhost_totals:
            logging.debug(
                "%s.gather: graph returned no ns+vhost totals in window. Check label_filter and endpoint.", self.name)

        matched = sum(1 for ((ns, vhost), _) in ns_vhost_totals.items()
                      if vhost in allowed_vhosts_by_ns.get(ns, set()))
        logging.debug("%s.gather: matched ns+vhost pairs=%d",
                      self.name, matched)

        sample_keys = list(ns_vhost_totals.keys())[:10]
        logging.debug("%s.gather: ns+vhost keys sample = %s",
                      self.name, sample_keys)

        per_ns_requests: Dict[str, int] = {}
        for (ns, vhost), total in ns_vhost_totals.items():
            allowed_set = allowed_vhosts_by_ns.get(ns)
            if not allowed_set:
                continue
            if vhost in allowed_set:
                per_ns_requests[ns] = per_ns_requests.get(ns, 0) + int(total)

        sample_per_ns = list(per_ns_requests.items())[:5]
        logging.debug("%s.gather: per-ns WAF requests (sample) = %s",
                      self.name, sample_per_ns)

        out = {
            ns: {
                "http_waf_requests": int(reqs),
                "waf_request_cost": calculate_cost_by_chunks(int(reqs), WAF_REQUEST_PRICE_PER_MILLION),
            }
            for ns, reqs in per_ns_requests.items()
        }
        return out


class FeatureCountBillable(BillableSource):
    """
    Generic inventory-based billable:
    - Filters normalized LB records by required_all (truthy flags).
    - Restricts to lb_kinds (families) if provided.
    - Groups by namespace and emits a count and optional cost.

    Constructor:
      - name: unique source name (used in logs)
      - lb_kinds: list of wrapper family keys (e.g., ["http_loadbalancers", "tcp_loadbalancers"])
      - required_all: normalized flags that must be truthy (e.g., ["is_public", "waf_enabled"])
      - unit_price: float price per LB (set 0.0 if you only want counts)
      - count_field: name for the count field (e.g., "public_lb_count")
      - cost_field: optional field name for cost (e.g., "public_lb_cost"); if None, no cost emitted
      - include_fields: optional normalized fields to include in output rows (useful for debugging)
    """

    def __init__(self,
                 name: str,
                 lb_kinds: List[str],
                 required_all: List[str],
                 unit_price: float,
                 count_field: str,
                 cost_field: str | None,
                 include_fields: List[str] | None = None):
        self.name = name
        self._lb_kinds = lb_kinds
        self._required_all = required_all
        self._unit_price = unit_price
        self._count_field = count_field
        self._cost_field = cost_field
        self._include_fields = include_fields or []

    @property
    def produced_fields(self) -> List[str]:
        fields = [self._count_field]
        if self._cost_field:
            fields.append(self._cost_field)
        return fields

    @property
    def cost_fields(self) -> List[str]:
        return [self._cost_field] if self._cost_field else []

    def gather(self, start_s: int, end_s: int, ctx: BillingContext) -> Dict[str, Dict[str, Any]]:
        inv = ctx.get_inventory()
        lbs = extract_loadbalancers_normalized(
            inv,
            lb_kinds=self._lb_kinds,
            required_all=self._required_all,
            include_fields=self._include_fields
        )
        logging.debug("%s.gather: filtered LBs=%d (first few: %s)",
                      self.name, len(lbs), lbs[:3] if lbs else [])

        groups = group_lbs_by_namespace(lbs)
        out: Dict[str, Dict[str, Any]] = {}
        for ns, g in groups.items():
            count = int(g.get("lb_count", 0))
            row = {self._count_field: count}
            if self._cost_field:
                row[self._cost_field] = count * self._unit_price
            out[ns] = row

        logging.debug("%s.gather: namespaces=%d (first few: %s)",
                      self.name, len(out), list(out)[:5])
        return out

# ------------------------------------------------------------------------------
# Composition (dynamic fieldnames and total_cost) and aggregation
# ------------------------------------------------------------------------------


def compose_namespace_rows(start_s: int, end_s: int, sources: List[BillableSource]) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Compose per-namespace rows and return (rows, fieldnames) dynamically.

    - Merge all sources' outputs by namespace.
    - Compute total_cost as the sum of all declared cost_fields present in each row.
    - Build CSV fieldnames from base columns + all produced_fields (in plugin order) + any extras + total_cost.
    """
    period_start_iso, period_end_iso, _, _ = format_period_labels(
        start_s, end_s)
    ctx = BillingContext()

    # Namespace -> cost_center
    ns_to_cost_center = ctx.get_ns_to_cost_center()

    # Gather data from each source
    merged: Dict[str, Dict[str, Any]] = {}
    for src in sources:
        try:
            data = src.gather(start_s, end_s, ctx)
            logging.debug(
                f"compose: source '{src.name}' produced {len(data)} namespaces")
        except Exception as e:
            logging.warning(f"Billable source '{src.name}' gather failed: {e}")
            data = {}
        for ns, vals in data.items():
            merged.setdefault(ns, {}).update(vals)

    # Collect cost fields and produced fields from all sources
    cost_field_names: List[str] = []
    produced_field_names: List[str] = []
    for src in sources:
        for f in src.cost_fields:
            if f not in cost_field_names:
                cost_field_names.append(f)
        for f in src.produced_fields:
            if f not in produced_field_names:
                produced_field_names.append(f)

    base_cols = ["period_start", "period_end", "namespace", "cost_center"]
    rows: List[Dict[str, Any]] = []

    # Union of namespaces known from mapping and produced by sources
    all_ns = sorted(set(merged.keys()) | set(ns_to_cost_center.keys()))
    logging.debug(f"compose: building rows for namespaces={len(all_ns)}")

    for ns in all_ns:
        vals = merged.get(ns, {})
        cost_center = ns_to_cost_center.get(ns, "Unassigned")

        # Compute total cost by summing all cost fields present
        total_cost = 0.0
        for cf in cost_field_names:
            try:
                total_cost += float(vals.get(cf, 0.0))
            except Exception:
                pass

        row = {
            "period_start": period_start_iso,
            "period_end": period_end_iso,
            "namespace": ns,
            "cost_center": cost_center,
            "total_cost": round(total_cost, 4),
        }

        # Add known produced fields in stable order
        for f in produced_field_names:
            if f in vals:
                if f.endswith("cost"):
                    row[f] = round(float(vals[f]), 4)
                else:
                    row[f] = vals[f]

        # Add any extra fields returned by sources
        for k, v in vals.items():
            if k not in row:
                row[k] = v

        rows.append(row)

    # Build dynamic fieldnames: base + produced + extras + total_cost
    extras = []
    seen = set(base_cols + produced_field_names + ["total_cost"])
    for r in rows:
        for k in r.keys():
            if k not in seen:
                extras.append(k)
                seen.add(k)
    fieldnames = base_cols + produced_field_names + extras + ["total_cost"]

    logging.debug(f"compose: final fieldnames={fieldnames}")
    logging.debug(f"compose: produced {len(rows)} namespace rows")
    return rows, fieldnames


def aggregate_cost_centers_dynamic(combined_rows: List[Dict[str, Any]], period_start_iso: str, period_end_iso: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Aggregate per-namespace rows into per-cost-center totals dynamically:
      - Sums all numeric fields (int/float).
      - Ignores non-numeric fields like lb_names/domains.
      - Returns (rows, fieldnames) with dynamic numeric columns.
    """
    by_cost_center: Dict[str, Dict[str, float]] = {}
    numeric_keys: set = set()

    for r in combined_rows:
        cost_center = r.get("cost_center", "Unassigned")
        agg = by_cost_center.setdefault(cost_center, {})
        for k, v in r.items():
            if k in ("period_start", "period_end", "namespace", "cost_center"):
                continue
            if isinstance(v, (int, float)):
                agg[k] = agg.get(k, 0.0) + float(v)
                numeric_keys.add(k)

    ordered_numeric: List[str] = []
    for suffix in ("requests", "count", "cost"):
        for k in sorted(numeric_keys):
            if k not in ordered_numeric and k.endswith(suffix):
                ordered_numeric.append(k)
    for k in sorted(numeric_keys):
        if k not in ordered_numeric:
            ordered_numeric.append(k)

    rows: List[Dict[str, Any]] = []
    for cost_center, totals in by_cost_center.items():
        out = {
            "period_start": period_start_iso,
            "period_end": period_end_iso,
            "cost_center": cost_center,
        }
        for k in ordered_numeric:
            if k in totals:
                val = totals[k]
                if k.endswith("cost"):
                    out[k] = round(val, 4)
                else:
                    out[k] = int(val) if abs(
                        val - int(val)) < 1e-9 else round(val, 4)
        rows.append(out)

    fieldnames = ["period_start", "period_end",
                  "cost_center"] + ordered_numeric
    logging.debug(
        f"aggregate_cost_centers_dynamic: numeric columns={ordered_numeric}")
    logging.debug(
        f"aggregate_cost_centers_dynamic: produced {len(rows)} cost center rows")
    return rows, fieldnames

# ------------------------------------------------------------------------------
# Optional: inventory family summary (helps verify wrapper_map keys)
# ------------------------------------------------------------------------------


def summarize_inventory_families(items: List[Dict[str, Any]]) -> None:
    """
    Log how many LB records we found per wrapper family (HTTP/TCP/CDN/BIGIP).
    Adjust array keys here if your tenant uses different names.
    """
    fam_counts = defaultdict(int)
    for entry in items:
        if not isinstance(entry, dict):
            continue
        for fam_key, arr_key in {
            "http_loadbalancers": "httplb_results",
            "tcp_loadbalancers": "tcplb_results",
            "cdn_loadbalancers": "cdn_results",
            "bigip_loadbalancers": "bigip_results",
        }.items():
            block = entry.get(fam_key)
            if isinstance(block, dict):
                arr = block.get(arr_key)
                if isinstance(arr, list):
                    fam_counts[(fam_key, arr_key)] += len(arr)
    logging.debug("inventory family summary: %s", dict(fam_counts))

# ------------------------------------------------------------------------------
# Output helpers
# ------------------------------------------------------------------------------


def write_csv(filename: str, rows: List[Dict[str, Any]], fieldnames: List[str], metadata: Dict[str, str] | None = None) -> None:
    """
    Write a CSV file to the output folder with optional metadata headers.
    The provided fieldnames must include all keys in row dicts.

    Args:
        filename: Output filename
        rows: List of data rows to write
        fieldnames: Column names for the CSV
        metadata: Optional dict of metadata to write as comment lines before data
                 (e.g., {"Generated": "2025-12-10", "Tenant": "f5-emea"})
    """
    filepath = get_output_path(filename)
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        # Write metadata headers as comments
        if metadata:
            for key, value in metadata.items():
                f.write(f"# {key}: {value}\n")

        # Write CSV data
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    logging.info(f"Wrote CSV: {filepath} (rows={len(rows)})")


def write_json(filename: str, data: Any) -> None:
    """
    Write JSON with indentation to the output folder.
    """
    filepath = get_output_path(filename)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    logging.info(f"Wrote JSON: {filepath}")


def generate_cost_center_pdf(cost_center_rows: List[Dict[str, Any]],
                             period_start_iso: str, period_end_iso: str,
                             start_label: str, end_label: str) -> None:
    """
    Generate a PDF report with cost-center visualizations using ReportLab and matplotlib.
    Creates charts for:
      - Total cost by cost center (bar chart)
      - Cost distribution (pie chart)
      - Cost breakdown by cost type (stacked bar chart)

    Uses pure Python: matplotlib for charts → PNG → ReportLab for PDF (no browser needed)
    """
    try:
        df = pd.DataFrame(cost_center_rows)

        if df.empty:
            logging.warning("No cost center data to visualize for PDF")
            return

        # Use non-interactive backend for matplotlib (works in headless environments)
        matplotlib.use('Agg')

        # Sort by cost center name for consistency
        df = df.sort_values('cost_center')

        # Identify cost columns (fields ending in '_cost')
        cost_columns = [col for col in df.columns if col.endswith(
            '_cost') and col != 'total_cost']

        # Get total cost column (prefer total_cost, fallback to first cost column)
        total_cost_col = 'total_cost' if 'total_cost' in df.columns else (
            cost_columns[0] if cost_columns else None)

        if total_cost_col is None:
            logging.warning("No cost columns found in data for PDF")
            return

        # Create temporary directory for chart images
        with tempfile.TemporaryDirectory() as tmpdir:
            chart_files = []

            # Chart 1: Bar chart - Total cost by cost center (with value labels)
            fig1, ax1 = plt.subplots(figsize=(12, 6), facecolor='white')
            colors_bar = ['#0173B2', '#029E73',
                          '#DE8F05', '#CC78BC', '#CA9161'][:len(df)]
            bars = ax1.bar(df['cost_center'], df[total_cost_col], color=colors_bar,
                           edgecolor='white', linewidth=2, alpha=0.95)

            # Add value labels on top of each bar
            for bar in bars:
                height = bar.get_height()
                ax1.text(bar.get_x() + bar.get_width()/2., height,
                         f'${height:,.0f}',
                         ha='center', va='bottom', fontsize=10, fontweight='bold', color='#333')

            ax1.set_xlabel('Cost Center', fontsize=12,
                           fontweight='bold', color='#333')
            ax1.set_ylabel('Cost (USD)', fontsize=12,
                           fontweight='bold', color='#333')
            ax1.set_title('Total Cost by Cost Center', fontsize=13,
                          fontweight='bold', color='#333', pad=15)
            ax1.grid(axis='y', alpha=0.2, linestyle='-',
                     linewidth=0.5, color='#e0e0e0')
            ax1.set_axisbelow(True)
            plt.setp(ax1.xaxis.get_majorticklabels(), rotation=45,
                     ha='right', fontsize=11, color='#333')
            plt.setp(ax1.yaxis.get_majorticklabels(),
                     fontsize=10, color='#333')
            ax1.spines['top'].set_visible(False)
            ax1.spines['right'].set_visible(False)
            ax1.spines['left'].set_color('#e0e0e0')
            ax1.spines['bottom'].set_color('#e0e0e0')
            fig1.tight_layout()

            chart1_path = os_module.path.join(tmpdir, 'chart1_bar.png')
            fig1.savefig(chart1_path, dpi=150,
                         bbox_inches='tight', facecolor='white')
            plt.close(fig1)
            chart_files.append(chart1_path)

            # Chart 2: Pie chart - Cost distribution
            fig2, ax2 = plt.subplots(figsize=(10, 8), facecolor='white')
            colors_pie = ['#0173B2', '#029E73',
                          '#DE8F05', '#CC78BC', '#CA9161'][:len(df)]

            # Create pie chart without shadow/depth
            wedges, texts, autotexts = ax2.pie(df[total_cost_col],
                                               labels=None,
                                               autopct='%1.1f%%',
                                               startangle=90,
                                               colors=colors_pie,
                                               wedgeprops={'edgecolor': 'white', 'linewidth': 2})

            # Create legend
            ax2.legend(df['cost_center'], loc='center left', bbox_to_anchor=(1, 0, 0.5, 1),
                       fontsize=11, frameon=False)
            ax2.set_title('Cost Distribution Across Cost Centers', fontsize=13, fontweight='bold',
                          color='#333', pad=15)

            # Style percentage labels
            for autotext in autotexts:
                autotext.set_color('white')
                autotext.set_fontweight('bold')
                autotext.set_fontsize(11)

            fig2.tight_layout()

            chart2_path = os_module.path.join(tmpdir, 'chart2_pie.png')
            fig2.savefig(chart2_path, dpi=150,
                         bbox_inches='tight', facecolor='white')
            plt.close(fig2)
            chart_files.append(chart2_path)

            # Chart 3: Stacked bar chart - Cost breakdown by type (if multiple cost types)
            if cost_columns and len(cost_columns) > 1:
                # Fill NaN values with 0 to ensure all bars render properly in stacked chart
                df_stacked = df.copy()
                for col in cost_columns:
                    if col in df_stacked.columns:
                        df_stacked[col] = df_stacked[col].fillna(0)

                fig3, ax3 = plt.subplots(figsize=(16, 7), facecolor='white')
                bottom = pd.Series([0] * len(df_stacked),
                                   index=df_stacked.index)
                colors_breakdown = ['#0173B2', '#029E73', '#DE8F05', '#CC78BC', '#CA9161',
                                    '#ECE133', '#56B4E9', '#F0E442', '#D55E00', '#009E73'][:len(cost_columns)]

                for idx, cost_col in enumerate(sorted(cost_columns)):
                    ax3.bar(df_stacked['cost_center'], df_stacked[cost_col], bottom=bottom,
                            label=cost_col.replace('_', ' ').title(),
                            color=colors_breakdown[idx], edgecolor='white', linewidth=1.5, alpha=0.95)
                    bottom += df_stacked[cost_col]

                ax3.set_xlabel('Cost Center', fontsize=12,
                               fontweight='bold', color='#333')
                ax3.set_ylabel('Cost (USD)', fontsize=12,
                               fontweight='bold', color='#333')
                ax3.set_title('Cost Breakdown by Type', fontsize=13,
                              fontweight='bold', color='#333', pad=15)
                ax3.legend(loc='upper left', fontsize=10, frameon=False)
                ax3.grid(axis='y', alpha=0.2, linestyle='-',
                         linewidth=0.5, color='#e0e0e0')
                ax3.set_axisbelow(True)

                # Rotate labels
                plt.setp(ax3.xaxis.get_majorticklabels(), rotation=45,
                         ha='right', fontsize=11, color='#333')
                plt.setp(ax3.yaxis.get_majorticklabels(),
                         fontsize=10, color='#333')
                ax3.spines['top'].set_visible(False)
                ax3.spines['right'].set_visible(False)
                ax3.spines['left'].set_color('#e0e0e0')
                ax3.spines['bottom'].set_color('#e0e0e0')

                # Add extra space at bottom for rotated labels
                fig3.subplots_adjust(bottom=0.2, left=0.08, right=0.95)

                chart3_path = os_module.path.join(tmpdir, 'chart3_stacked.png')
                # Remove tight_layout to preserve margins, use savefig params only
                fig3.savefig(chart3_path, dpi=150,
                             bbox_inches='tight', pad_inches=0.4)
                plt.close(fig3)
                chart_files.append(chart3_path)

            # Create summary table
            summary_data = [['Cost Center', 'Total Cost (USD)']]
            for _, row in df.iterrows():
                summary_data.append(
                    [row['cost_center'], f"${row[total_cost_col]:.2f}"])

            # Add totals row
            total = df[total_cost_col].sum()
            summary_data.append(['TOTAL', f"${total:.2f}"])

            # Build PDF using ReportLab (landscape for better chart display)
            pdf_filename = f"billing_cost_centers_{start_label}_to_{end_label}.pdf"
            pdf_filepath = get_output_path(pdf_filename)

            # Use portrait orientation (standard letter size)
            doc = SimpleDocTemplate(pdf_filepath, pagesize=letter,
                                    rightMargin=0.5*inch, leftMargin=0.5*inch,
                                    topMargin=0.5*inch, bottomMargin=0.5*inch)

            # Define styles
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=18,
                textColor=colors.HexColor('#1f77b4'),
                spaceAfter=6,
                fontName='Helvetica-Bold'
            )
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=13,
                textColor=colors.HexColor('#2c5aa0'),
                spaceAfter=6,
                spaceBefore=12,
                fontName='Helvetica-Bold'
            )

            # Build document elements
            elements = []

            # Title
            period_str = f"{start_label} to {end_label}"
            title = Paragraph(
                f"Cost Center Billing Report<br/>{period_str}", title_style)
            elements.append(title)
            elements.append(Spacer(1, 0.3*inch))

            # Chart 1: Bar chart (with margins)
            elements.append(
                Paragraph("Total Cost by Cost Center", heading_style))
            elements.append(Spacer(1, 0.1*inch))
            img1 = Image(chart_files[0], width=6.5*inch, height=3.25*inch)
            elements.append(img1)
            elements.append(Spacer(1, 0.3*inch))

            # Page break before second chart to give it room
            elements.append(PageBreak())

            # Chart 2: Pie chart
            elements.append(Paragraph("Cost Distribution", heading_style))
            elements.append(Spacer(1, 0.1*inch))
            img2 = Image(chart_files[1], width=6*inch, height=4.5*inch)
            elements.append(img2)
            elements.append(Spacer(1, 0.3*inch))

            # Chart 3: Stacked bar (if exists)
            if len(chart_files) > 2:
                elements.append(PageBreak())
                elements.append(
                    Paragraph("Cost Breakdown by Type", heading_style))
                elements.append(Spacer(1, 0.1*inch))
                # Scale for portrait orientation - smaller to match other charts
                img3 = Image(chart_files[2], width=6.5*inch, height=3.25*inch)
                elements.append(img3)
                elements.append(Spacer(1, 0.2*inch))

                # Add cost breakdown table below stacked chart - per cost center
                # Create abbreviations for cost types to fit in table
                cost_abbrev = {
                    'api_discovery_lb_cost': 'API Disc',
                    'bot_protection_lb_cost': 'Bot Prot',
                    'public_lb_cost': 'Public LB',
                    'request_cost': 'Requests',
                    'waf_request_cost': 'WAF Req'
                }

                breakdown_data = [['Cost Center'] + [cost_abbrev.get(col, col.replace(
                    '_', ' ').title()) for col in sorted(cost_columns)] + ['Total']]
                for _, row in df.iterrows():
                    row_data = [row['cost_center']]
                    row_total = 0
                    for cost_col in sorted(cost_columns):
                        cost_val = row[cost_col] if cost_col in row.index else 0
                        cost_val = cost_val if pd.notna(cost_val) else 0
                        row_data.append(f"${cost_val:,.2f}")
                        row_total += cost_val
                    row_data.append(f"${row_total:,.2f}")
                    breakdown_data.append(row_data)

                # Add totals row
                totals_row = ['Total']
                grand_total = 0
                for cost_col in sorted(cost_columns):
                    col_total = df[cost_col].fillna(0).sum()
                    totals_row.append(f"${col_total:,.2f}")
                    grand_total += col_total
                totals_row.append(f"${grand_total:,.2f}")
                breakdown_data.append(totals_row)

                # Create table with dynamic column widths - use abbreviations for better fit
                num_cost_types = len(cost_columns)
                # Calculate available width for cost type columns
                available_width = 6.5 * inch - 1.5 * inch - 0.9 * inch  # Total - name - total
                col_width = available_width / num_cost_types if num_cost_types > 0 else 0.9 * inch

                breakdown_table = Table(breakdown_data, colWidths=[
                                        1.5*inch] + [col_width]*num_cost_types + [0.9*inch])
                breakdown_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0173B2')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'RIGHT'),
                    ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 7),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 3),
                    ('TOPPADDING', (0, 0), (-1, 0), 3),
                    ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor('#e8e8e8')),
                    ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#d0d0d0')),
                    ('FONTSIZE', (0, 1), (-1, -1), 7),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -2),
                     [colors.white, colors.HexColor('#f9f9f9')]),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('LEFTPADDING', (0, 0), (-1, -1), 2),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 2),
                ]))
                elements.append(breakdown_table)
                elements.append(Spacer(1, 0.3*inch))

            # Summary table
            elements.append(PageBreak())
            elements.append(Paragraph("Cost Center Summary", heading_style))

            table = Table(summary_data, colWidths=[5*inch, 3*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f77b4')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor('#e6e6e6')),
                ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
                ('TOPPADDING', (0, -1), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -2),
                 [colors.white, colors.HexColor('#f5f5f5')]),
                ('FONTSIZE', (0, 1), (-1, -1), 10),
            ]))
            elements.append(table)

            # Build PDF
            doc.build(elements)
            logging.info(f"Wrote PDF: {pdf_filepath}")

    except Exception as e:
        logging.error(f"Failed to generate PDF: {e}")
        import traceback
        traceback.print_exc()

# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------


def main() -> None:
    """
    Entrypoint:
      - Handle --validate mode (pre-flight checks only)
      - Parse CLI date range arguments (or use default 30 days)
      - Compose per-namespace rows dynamically using BillableSource plugins
      - Apply namespace/cost-center filters if provided
      - Aggregate per cost center dynamically
      - Write reports (or skip if --dry-run)
    """
    if not API_BASE or not API_TOKEN:
        raise RuntimeError("Set F5XC_API_BASE and F5XC_API_TOKEN in your .env")

    # Handle --validate mode
    if args.validate:
        validate_configuration()
        logging.info("Validation passed. Exiting.")
        return

    logging.info("Effective unit prices: request=%.4f, waf_request=%.4f, public_lb=%.4f, api_discovery_lb=%.4f, bot_protection_lb=%.4f",
                 REQUEST_PRICE_PER_MILLION, WAF_REQUEST_PRICE_PER_MILLION, PRICE_PER_PUBLIC_LB, PRICE_PER_API_DISCOVERY_LB, PRICE_PER_BOT_PROTECTION_LB)

    # Parse date arguments or use default (last 30 days)
    try:
        from datetime import timedelta
        now = datetime.now(timezone.utc)
        if args.start and args.end:
            # Both provided
            start_dt = parse_date_arg(args.start)
            end_dt = parse_date_arg(args.end)
        elif args.start:
            # Only start provided; use today as end
            start_dt = parse_date_arg(args.start)
            end_dt = now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif args.end:
            # Only end provided; use 30 days before as start
            end_dt = parse_date_arg(args.end)
            start_dt = end_dt - timedelta(days=30)
        else:
            # Neither provided; use last 30 days
            start_s, end_s = last_30_days_range(now)
            start_dt = datetime.fromtimestamp(start_s, tz=timezone.utc)
            end_dt = datetime.fromtimestamp(end_s, tz=timezone.utc)
    except ValueError as e:
        logging.error(f"Date parsing error: {e}")
        raise

    start_s = int(start_dt.timestamp())
    end_s = int(end_dt.timestamp())
    period_start_iso, period_end_iso, start_label, end_label = format_period_labels(
        start_s, end_s)

    logging.info(f"Billing period: {period_start_iso} to {period_end_iso}")

    # Parse filters
    namespace_filter = parse_namespace_filter(args.namespace)
    cost_center_filter = parse_cost_center_filter(args.cost_center)

    if namespace_filter:
        logging.info(f"Filtering to namespaces: {sorted(namespace_filter)}")
    if cost_center_filter:
        logging.info(
            f"Filtering to cost centers: {sorted(cost_center_filter)}")

    # Build context to log inventory family summary once (optional)
    ctx = BillingContext()
    summarize_inventory_families(ctx.get_inventory())

    # Add/Remove billable sources as needed; columns and total_cost adapt automatically.
    sources: List[BillableSource] = [
        # Graph-based billables
        HttpRequestsBillable(),
        HttpWafRequestsBillable(),

        # Inventory-based billables via FeatureCountBillable
        FeatureCountBillable(
            name="public_http_lb",
            lb_kinds=["http_loadbalancers", "tcp_loadbalancers"],
            required_all=["is_public"],
            unit_price=PRICE_PER_PUBLIC_LB,
            count_field="public_lb_count",
            cost_field="public_lb_cost",
            include_fields=["is_public"]
        ),
        FeatureCountBillable(
            name="public_waf_http_lb",
            lb_kinds=["http_loadbalancers"],
            required_all=["is_public", "waf_enabled"],
            unit_price=0.0,
            count_field="public_waf_lb_count",
            cost_field=None,
            include_fields=["is_public", "waf_enabled"]
        ),
        FeatureCountBillable(
            name="api_discovery_lb",
            lb_kinds=["http_loadbalancers"],
            # ensure this matches your tenant
            required_all=["api_discovery_enabled"],
            unit_price=PRICE_PER_API_DISCOVERY_LB,
            count_field="api_discovery_lb_count",
            cost_field="api_discovery_lb_cost",
            include_fields=["api_discovery_enabled"]
        ),
        FeatureCountBillable(
            name="bot_protection_lb",
            lb_kinds=["http_loadbalancers"],
            required_all=["bot_protection_enabled"],
            unit_price=PRICE_PER_BOT_PROTECTION_LB,
            count_field="bot_protection_lb_count",
            cost_field="bot_protection_lb_cost",
            include_fields=["bot_protection_enabled"]
        ),
    ]

    # Per-namespace rows + dynamic fieldnames
    combined_rows, ns_fieldnames = compose_namespace_rows(
        start_s, end_s, sources)
    logging.debug(
        f"First 3 namespace rows: {json.dumps(combined_rows[:3], indent=2)}")

    # Apply namespace filter if provided
    if namespace_filter:
        combined_rows = filter_rows_by_namespace(
            combined_rows, namespace_filter)
        logging.info(f"After namespace filter: {len(combined_rows)} rows")

    # Per-cost-center dynamic aggregation + fieldnames
    cost_center_rows, cost_center_fieldnames = aggregate_cost_centers_dynamic(
        combined_rows, period_start_iso, period_end_iso)
    logging.debug(
        f"First 3 cost center rows: {json.dumps(cost_center_rows[:3], indent=2)}")

    # Apply cost center filter if provided
    if cost_center_filter:
        cost_center_rows = filter_rows_by_cost_center(
            cost_center_rows, cost_center_filter)
        logging.info(f"After cost center filter: {len(cost_center_rows)} rows")

    # Summary
    total_cost = sum(float(r.get("total_cost", 0.0)) for r in combined_rows)
    logging.info(
        f"Calculated billing: {len(combined_rows)} namespaces, total cost: ${total_cost:,.2f}")

    # Early exit if --dry-run
    if args.dry_run:
        logging.info("--dry-run mode: skipping file writes")
        return

    # Filenames
    ns_csv = f"billing_namespace_combined_{start_label}_to_{end_label}.csv"
    ns_json = f"billing_namespace_combined_{start_label}_to_{end_label}.json"
    cc_csv = f"billing_cost_centers_{start_label}_to_{end_label}.csv"
    cc_json = f"billing_cost_centers_{start_label}_to_{end_label}.json"

    # Build metadata for CSV headers
    generation_time = datetime.now(timezone.utc).isoformat()
    ns_metadata = None
    cc_metadata = None

    if not args.no_metadata:
        ns_metadata = {
            "Generated": generation_time,
            "Period Start": period_start_iso,
            "Period End": period_end_iso,
            "Namespace Count": str(len(combined_rows)),
        }
        cc_metadata = {
            "Generated": generation_time,
            "Period Start": period_start_iso,
            "Period End": period_end_iso,
            "Cost Center Count": str(len(cost_center_rows)),
        }

    # Write files based on --format argument
    if args.format in ("csv", "both"):
        write_csv(ns_csv, combined_rows, ns_fieldnames, metadata=ns_metadata)
        write_csv(cc_csv, cost_center_rows,
                  cost_center_fieldnames, metadata=cc_metadata)

    if args.format in ("json", "both"):
        write_json(ns_json, combined_rows)
        write_json(cc_json, cost_center_rows)

    # Generate PDF report if requested
    if args.pdf:
        generate_cost_center_pdf(cost_center_rows, period_start_iso,
                                 period_end_iso, start_label, end_label)

    logging.info(f"Done. Window {period_start_iso} .. {period_end_iso}")


if __name__ == "__main__":
    main()
