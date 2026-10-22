"""Lightweight Flask application security controls for Tigran Mods.

This module reduces common application-layer abuse. It is NOT a network DDoS
mitigation service; use a CDN/WAF and host-level controls for volumetric attacks.
"""
from collections import defaultdict, deque
from threading import Lock
from time import time
from flask import request, jsonify
import os

_LOCK = Lock()
_BUCKETS = defaultdict(deque)
_MAX_TRACKED_IPS = int(os.environ.get("SECURITY_MAX_TRACKED_IPS", "12000"))
_ENABLED = os.environ.get("APP_SECURITY_ENABLED", "1").lower() not in {"0", "false", "no"}

# Conservative per-IP windows. AI endpoints already have their own budget limit.
_RULES = (
    ("/api/ai/", 18, 60),
    ("/api/", 90, 60),
    ("/", 180, 60),
)
_BLOCKED_PATH_PREFIXES = ("/.git", "/.env", "/wp-admin", "/wp-login", "/phpmyadmin", "/vendor/phpunit")


def _client_ip():
    # app.py installs Werkzeug ProxyFix when TRUST_PROXY=1. Use the resolved
    # remote_addr here rather than trusting a raw user-supplied forwarding header.
    return request.remote_addr or "unknown"


def _rule_for(path):
    if path.startswith("/api/ai/"):
        return _RULES[0]
    if path.startswith("/api/"):
        return _RULES[1]
    return _RULES[2]


def install_security(app):
    """Install bounded in-memory rate limiting and baseline response headers."""
    @app.before_request
    def _security_guard():
        if not _ENABLED:
            return None
        path = request.path.lower()
        if any(path == prefix or path.startswith(prefix + "/") for prefix in _BLOCKED_PATH_PREFIXES):
            return jsonify({"error": "Not found"}), 404
        if request.method in {"POST", "PUT", "PATCH"} and request.content_length is not None:
            if request.content_length > app.config.get("MAX_CONTENT_LENGTH", 2 * 1024 * 1024):
                return jsonify({"error": "Request body too large"}), 413
        ip = _client_ip()
        prefix, limit, window = _rule_for(path)
        key = f"{ip}:{prefix}"
        now = time()
        with _LOCK:
            bucket = _BUCKETS[key]
            while bucket and now - bucket[0] > window:
                bucket.popleft()
            if len(bucket) >= limit:
                response = jsonify({"error": "Too many requests. Please slow down."})
                response.status_code = 429
                response.headers["Retry-After"] = str(max(1, int(window - (now - bucket[0]))))
                return response
            bucket.append(now)
            # Bound memory under IP churn. Evict expired/oldest buckets when necessary.
            if len(_BUCKETS) > _MAX_TRACKED_IPS:
                for old_key in list(_BUCKETS.keys())[:max(1, _MAX_TRACKED_IPS // 10)]:
                    _BUCKETS.pop(old_key, None)
        return None

    @app.after_request
    def _security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), geolocation=(), microphone=(self)")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-site")
        response.headers.setdefault("X-Permitted-Cross-Domain-Policies", "none")
        # HSTS is safe only when the public site is served exclusively over HTTPS.
        if request.is_secure or request.headers.get("X-Forwarded-Proto", "").split(",", 1)[0].strip() == "https":
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response
