"""
MCP Server: E-commerce Live Price Scraper
==========================================

A production-ready Model Context Protocol (MCP) server exposing a single
tool, `scrape_live_prices`, that fetches product title / price / currency /
availability data from e-commerce product pages (Amazon, Shopify stores,
generic storefronts using JSON-LD or OpenGraph metadata).

Transport:
    Runs over Streamable HTTP / SSE via FastMCP, so it can be deployed
    behind any ASGI server (uvicorn) or invoked directly with `mcp dev`.

Run:
    pip install -r requirements.txt
    python server.py                     # stdio (local dev / Claude Desktop)
    python server.py --transport sse     # SSE server on :8000
    python server.py --transport http    # Streamable HTTP server on :8000
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from mcp.server.fastmcp import FastMCP

# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("ecommerce-scraper-mcp")

# --------------------------------------------------------------------------
# Constants / Config
# --------------------------------------------------------------------------

REQUEST_TIMEOUT_SECONDS = 12
MAX_RETRIES = 2

# Rotating pool of realistic desktop browser User-Agents.
USER_AGENTS: list[str] = [
    # Chrome - Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Chrome - macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Firefox - Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 "
    "Firefox/125.0",
    # Safari - macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    # Edge - Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.2420.81",
    # Chrome - Android
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
]

ACCEPT_LANGUAGES = ["en-US,en;q=0.9", "en-GB,en;q=0.8", "en-IN,en;q=0.9,hi;q=0.8"]

# Patterns that hint a request was blocked by anti-bot / WAF / dynamic JS gate.
BLOCK_SIGNATURES = [
    "captcha",
    "robot check",
    "are you a human",
    "access denied",
    "request blocked",
    "verify you are a human",
    "unusual traffic",
    "cf-browser-verification",
    "px-captcha",
    "perimeterx",
    "akamai",
    "/errors/validatecaptcha",
]

CURRENCY_SYMBOL_MAP = {
    "$": "USD",
    "₹": "INR",
    "Rs.": "INR",
    "Rs": "INR",
    "€": "EUR",
    "£": "GBP",
    "¥": "JPY",
    "₩": "KRW",
}


# --------------------------------------------------------------------------
# Result data model
# --------------------------------------------------------------------------

@dataclass
class ScrapeResult:
    status: str  # "success" | "error"
    url: str
    title: Optional[str] = None
    price_raw: Optional[str] = None
    price_value: Optional[float] = None
    currency: Optional[str] = None
    availability: Optional[str] = None
    source_domain: Optional[str] = None
    http_status: Optional[int] = None
    error_type: Optional[str] = None
    error_message: Optional[str] = None
    warnings: list[str] = field(default_factory=list)

    def to_json_dict(self) -> dict[str, Any]:
        # Drop None values for a clean, minimal payload but keep required keys.
        payload = {
            "status": self.status,
            "url": self.url,
            "source_domain": self.source_domain,
            "data": {
                "title": self.title,
                "price_raw": self.price_raw,
                "price_value": self.price_value,
                "currency": self.currency,
                "availability": self.availability,
            },
            "http_status": self.http_status,
            "warnings": self.warnings,
        }
        if self.status == "error":
            payload["error"] = {
                "type": self.error_type,
                "message": self.error_message,
            }
        return payload


# --------------------------------------------------------------------------
# HTTP fetch layer (rotating headers, retries, block detection)
# --------------------------------------------------------------------------

class FetchError(Exception):
    """Raised for any network/HTTP failure we want surfaced as a clean error."""

    def __init__(self, error_type: str, message: str, http_status: Optional[int] = None):
        super().__init__(message)
        self.error_type = error_type
        self.message = message
        self.http_status = http_status


def _build_headers() -> dict[str, str]:
    ua = random.choice(USER_AGENTS)
    return {
        "User-Agent": ua,
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,*/*;q=0.8"
        ),
        "Accept-Language": random.choice(ACCEPT_LANGUAGES),
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "max-age=0",
        "DNT": "1",
        "Referer": "https://www.google.com/",
    }


def _validate_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise FetchError(
            "invalid_url",
            f"'{url}' is not a valid absolute http(s) URL.",
        )
    return parsed.netloc


def _looks_blocked(html: str, status_code: int) -> Optional[str]:
    if status_code in (403, 429, 503):
        return f"HTTP {status_code} returned — likely rate-limited or blocked by anti-bot protection."
    lowered = html.lower()
    for sig in BLOCK_SIGNATURES:
        if sig in lowered:
            return f"Detected anti-bot / CAPTCHA challenge marker ('{sig}') in response body."
    # Heuristic: legit product pages are rarely this small.
    if len(html.strip()) < 600:
        return "Response body suspiciously small — page likely requires JavaScript rendering or was blocked."
    return None


def fetch_html(url: str) -> tuple[str, int]:
    """
    Fetch raw HTML with rotating headers and retry/backoff.
    Raises FetchError on network failure, bad status, or detected block page.
    """
    domain = _validate_url(url)
    last_exc: Optional[Exception] = None

    session = requests.Session()

    for attempt in range(1, MAX_RETRIES + 2):  # initial try + retries
        headers = _build_headers()
        try:
            logger.info("Fetching %s (attempt %d, UA=%s...)", url, attempt, headers["User-Agent"][:30])
            resp = session.get(
                url,
                headers=headers,
                timeout=REQUEST_TIMEOUT_SECONDS,
                allow_redirects=True,
            )
        except requests.exceptions.Timeout as exc:
            last_exc = exc
            logger.warning("Timeout on attempt %d for %s", attempt, url)
            continue
        except requests.exceptions.SSLError as exc:
            raise FetchError("ssl_error", f"SSL verification failed for {domain}: {exc}") from exc
        except requests.exceptions.ConnectionError as exc:
            last_exc = exc
            logger.warning("Connection error on attempt %d for %s: %s", attempt, url, exc)
            continue
        except requests.exceptions.RequestException as exc:
            raise FetchError("request_exception", f"Unexpected request failure: {exc}") from exc

        block_reason = _looks_blocked(resp.text, resp.status_code)
        if block_reason:
            if attempt <= MAX_RETRIES:
                logger.warning("Blocked signal on attempt %d: %s — retrying with new identity", attempt, block_reason)
                continue
            raise FetchError("blocked_by_target", block_reason, http_status=resp.status_code)

        if resp.status_code >= 400:
            if attempt <= MAX_RETRIES and resp.status_code in (502, 504):
                continue
            raise FetchError(
                "http_error",
                f"Target server returned HTTP {resp.status_code}.",
                http_status=resp.status_code,
            )

        return resp.text, resp.status_code

    raise FetchError(
        "network_failure",
        f"Failed to fetch URL after {MAX_RETRIES + 1} attempts: {last_exc}",
    )


# --------------------------------------------------------------------------
# Parsing layer
# --------------------------------------------------------------------------

def _clean_text(text: Optional[str]) -> Optional[str]:
    if not text:
        return None
    cleaned = re.sub(r"\s+", " ", text).strip()
    return cleaned or None


def _parse_price_value(raw: str) -> Optional[float]:
    if not raw:
        return None
    match = re.search(r"[\d,]+\.?\d*", raw)
    if not match:
        return None
    numeric = match.group(0).replace(",", "")
    try:
        return float(numeric)
    except ValueError:
        return None


def _detect_currency(raw_price: Optional[str], meta_currency: Optional[str]) -> Optional[str]:
    if meta_currency:
        return meta_currency.upper()
    if not raw_price:
        return None
    for symbol, code in CURRENCY_SYMBOL_MAP.items():
        if symbol in raw_price:
            return code
    return None


def _extract_jsonld_product(soup: BeautifulSoup) -> dict[str, Any]:
    """Look for schema.org Product data inside <script type="application/ld+json">."""
    for tag in soup.find_all("script", attrs={"type": "application/ld+json"}):
        try:
            data = json.loads(tag.string or "{}")
        except (json.JSONDecodeError, TypeError):
            continue

        candidates = data if isinstance(data, list) else [data]
        for entry in candidates:
            if not isinstance(entry, dict):
                continue
            graph = entry.get("@graph")
            sub_candidates = graph if isinstance(graph, list) else [entry]
            for item in sub_candidates:
                if not isinstance(item, dict):
                    continue
                item_type = item.get("@type")
                types = item_type if isinstance(item_type, list) else [item_type]
                if "Product" in types:
                    offers = item.get("offers", {})
                    if isinstance(offers, list):
                        offers = offers[0] if offers else {}
                    return {
                        "title": item.get("name"),
                        "price_raw": str(offers.get("price")) if offers.get("price") is not None else None,
                        "currency": offers.get("priceCurrency"),
                        "availability": offers.get("availability"),
                    }
    return {}


def _extract_via_meta_tags(soup: BeautifulSoup) -> dict[str, Any]:
    """Fallback to OpenGraph / common meta tags (works broadly on Shopify)."""
    def meta(prop_name: str, attr: str = "property") -> Optional[str]:
        tag = soup.find("meta", attrs={attr: prop_name})
        return tag.get("content") if tag else None

    return {
        "title": meta("og:title") or (soup.title.string if soup.title else None),
        "price_raw": meta("og:price:amount") or meta("product:price:amount"),
        "currency": meta("og:price:currency") or meta("product:price:currency"),
        "availability": meta("og:availability") or meta("product:availability"),
    }


def _extract_via_common_selectors(soup: BeautifulSoup) -> dict[str, Any]:
    """Last-resort CSS-selector heuristics covering Amazon & generic Shopify markup."""
    title_selectors = ["#productTitle", "h1.product-title", "h1.product__title", "h1"]
    price_selectors = [
        ".a-price .a-offscreen",
        "#priceblock_ourprice",
        "#priceblock_dealprice",
        ".price-item--regular",
        ".price__regular .price-item",
        "span.price",
        ".product-price",
        "[itemprop='price']",
    ]
    availability_selectors = [
        "#availability span",
        ".product__inventory",
        "[itemprop='availability']",
        ".stock",
    ]

    def first_match(selectors: list[str]) -> Optional[str]:
        for sel in selectors:
            el = soup.select_one(sel)
            if el:
                text = el.get("content") or el.get_text(strip=True)
                if text:
                    return text
        return None

    return {
        "title": first_match(title_selectors),
        "price_raw": first_match(price_selectors),
        "currency": None,
        "availability": first_match(availability_selectors),
    }


def parse_product_page(html: str) -> dict[str, Any]:
    soup = BeautifulSoup(html, "lxml")

    # Layer 1: structured JSON-LD (most reliable)
    extracted = _extract_jsonld_product(soup)

    # Layer 2: OpenGraph / meta tags fill any gaps
    if not all(extracted.get(k) for k in ("title", "price_raw")):
        meta_extracted = _extract_via_meta_tags(soup)
        for key, value in meta_extracted.items():
            extracted.setdefault(key, None)
            if not extracted.get(key) and value:
                extracted[key] = value

    # Layer 3: CSS-selector heuristics fill remaining gaps
    if not all(extracted.get(k) for k in ("title", "price_raw")):
        selector_extracted = _extract_via_common_selectors(soup)
        for key, value in selector_extracted.items():
            if not extracted.get(key) and value:
                extracted[key] = value

    title = _clean_text(extracted.get("title"))
    price_raw = _clean_text(extracted.get("price_raw"))
    currency = _detect_currency(price_raw, extracted.get("currency"))
    availability_raw = _clean_text(extracted.get("availability"))

    availability = None
    if availability_raw:
        low = availability_raw.lower()
        if "instock" in low.replace(" ", "") or "in stock" in low:
            availability = "In Stock"
        elif "outofstock" in low.replace(" ", "") or "out of stock" in low or "unavailable" in low:
            availability = "Out of Stock"
        elif "preorder" in low.replace(" ", ""):
            availability = "Pre-Order"
        else:
            availability = availability_raw

    return {
        "title": title,
        "price_raw": price_raw,
        "price_value": _parse_price_value(price_raw) if price_raw else None,
        "currency": currency,
        "availability": availability,
    }


# --------------------------------------------------------------------------
# MCP Server (FastMCP) — Streamable HTTP / SSE / stdio capable
# --------------------------------------------------------------------------

mcp = FastMCP(
    name="ecommerce-price-scraper",
    instructions=(
        "Provides the 'scrape_live_prices' tool for extracting live product "
        "title, price, currency, and availability data from e-commerce "
        "product pages (Amazon, Shopify, and generic storefronts)."
    ),
)


@mcp.tool(
    name="scrape_live_prices",
    description=(
        "Scrape a live e-commerce product page (e.g. Amazon, Shopify store) "
        "and return its title, raw price text, parsed numeric price, "
        "currency, and availability status as a structured JSON object. "
        "Uses rotating User-Agent headers to reduce trivial bot-blocking. "
        "Always returns a JSON dict, including a graceful error state if "
        "the target site blocks the request or the page cannot be parsed."
    ),
)
def scrape_live_prices(url: str) -> dict[str, Any]:
    """
    Args:
        url: Full absolute URL of the product page to scrape.

    Returns:
        A JSON-serializable dict with keys: status, url, source_domain,
        data {title, price_raw, price_value, currency, availability},
        http_status, warnings, and (on failure) an `error` object.
    """
    logger.info("Tool invoked: scrape_live_prices(url=%r)", url)

    try:
        domain = _validate_url(url)
    except FetchError as exc:
        result = ScrapeResult(
            status="error",
            url=url,
            source_domain=None,
            error_type=exc.error_type,
            error_message=exc.message,
        )
        return result.to_json_dict()

    try:
        html, status_code = fetch_html(url)
    except FetchError as exc:
        logger.error("Fetch failed for %s: [%s] %s", url, exc.error_type, exc.message)
        result = ScrapeResult(
            status="error",
            url=url,
            source_domain=domain,
            http_status=exc.http_status,
            error_type=exc.error_type,
            error_message=exc.message,
        )
        return result.to_json_dict()
    except Exception as exc:  # noqa: BLE001 - final safety net, never let the tool crash
        logger.exception("Unhandled exception while fetching %s", url)
        result = ScrapeResult(
            status="error",
            url=url,
            source_domain=domain,
            error_type="unhandled_exception",
            error_message=f"{type(exc).__name__}: {exc}",
        )
        return result.to_json_dict()

    try:
        parsed = parse_product_page(html)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Parsing failure for %s", url)
        result = ScrapeResult(
            status="error",
            url=url,
            source_domain=domain,
            http_status=status_code,
            error_type="parse_error",
            error_message=f"Failed to parse product page: {type(exc).__name__}: {exc}",
        )
        return result.to_json_dict()

    warnings: list[str] = []
    if not parsed.get("title"):
        warnings.append("Title not found — selectors may not match this site's markup.")
    if not parsed.get("price_raw"):
        warnings.append("Price not found — page may render pricing via client-side JavaScript.")
    if not parsed.get("availability"):
        warnings.append("Availability status not found on page.")

    result = ScrapeResult(
        status="success",
        url=url,
        source_domain=domain,
        http_status=status_code,
        title=parsed.get("title"),
        price_raw=parsed.get("price_raw"),
        price_value=parsed.get("price_value"),
        currency=parsed.get("currency"),
        availability=parsed.get("availability"),
        warnings=warnings,
    )
    return result.to_json_dict()


# --------------------------------------------------------------------------
# Entrypoint — supports stdio (default), SSE, and Streamable HTTP transports
# --------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="E-commerce Price Scraper MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "http"],
        default="stdio",
        help="Transport protocol to serve the MCP server over (default: stdio).",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind for sse/http transports.")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind for sse/http transports.")
    args = parser.parse_args()

    if args.transport == "stdio":
        logger.info("Starting MCP server over stdio transport.")
        mcp.run(transport="stdio")
    elif args.transport == "sse":
        mcp.settings.host = args.host
        mcp.settings.port = args.port
        logger.info("Starting MCP server over SSE transport on %s:%s", args.host, args.port)
        mcp.run(transport="sse")
    elif args.transport == "http":
        mcp.settings.host = args.host
        mcp.settings.port = args.port
        logger.info("Starting MCP server over Streamable HTTP transport on %s:%s", args.host, args.port)
        mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
