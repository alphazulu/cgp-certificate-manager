"""Explicit DNS provider selection and the compatible Cloudflare implementation.

Selection and credential paths are pure configuration data. Only this fixed
registry is supported: no account lookup, dynamic import or credential read is
performed by selection. The legacy Cloudflare transport remains in ``core``;
its callable is resolved when used so existing callers and test seams remain
compatible. Fixed hooks retain their historical unowned-record lifecycle.
"""
from pathlib import Path
import re
from urllib.error import HTTPError

from . import core


_MISSING = object()


class ProviderError(core.Error):
    """A deliberately secret-free provider/configuration failure."""


class ProviderRejected(ProviderError):
    """A validated provider rejection proves a create request had no result."""


def provider_name(cfg):
    """Select the supported provider without reading credentials or mutating cfg."""
    if not isinstance(cfg, dict):
        raise ProviderError("DNS configuration must be an object")
    name = cfg.get("dns_provider", "cloudflare")
    if type(name) is not str or name not in ("cloudflare", "rfc2136"):
        raise ProviderError("Unsupported DNS provider")
    return name


def credentials(cfg, absolute=False):
    """Return ordered configured paths, preserving legacy account precedence."""
    if provider_name(cfg) == "rfc2136":
        return get_provider(cfg).credentials(cfg, absolute=absolute)
    accounts = cfg.get("cloudflare_accounts") or [{"credentials": cfg.get("cloudflare_credentials")}]
    if not isinstance(accounts, list):
        raise ProviderError("Invalid DNS credentials configuration")
    paths = []
    for account in accounts:
        path = account.get("credentials") if isinstance(account, dict) else None
        if not isinstance(path, str) or not path:
            raise ProviderError("Invalid DNS credentials configuration")
        paths.append(str(Path(path).absolute()) if absolute else path)
    return tuple(paths)


def get_provider(cfg, transport=None):
    """Resolve a static backend; the optional HTTP transport is Cloudflare-only."""
    if provider_name(cfg) == "rfc2136":
        from . import rfc2136, rfc2136_config
        try:
            return rfc2136.RFC2136Provider(cfg)
        except rfc2136_config.ConfigError:
            raise ProviderError("Invalid RFC2136 configuration") from None
    return CloudflareProvider(transport)


class CloudflareProvider:
    name = provider_id = "cloudflare"
    capabilities = frozenset({"zone_discovery", "fixed_native", "fixed_hooks", "owned_txt"})

    def __init__(self, transport=None):
        self._transport = transport

    def require(self, capability):
        if type(capability) is not str or capability not in self.capabilities:
            raise ProviderError("DNS provider capability unavailable")

    def credentials(self, cfg, absolute=False):
        return credentials(cfg, absolute=absolute)

    def fixed_cleanup_credentials(self, cfg):
        """Retain the legacy hook's active-plus-fallback credential allowlist."""
        paths = self.credentials(cfg)
        fallback = cfg.get("cloudflare_credentials")
        if isinstance(fallback, str) and fallback and fallback not in paths:
            return paths + (fallback,)
        return paths

    def validate_credentials(self, cfg):
        for path in self.credentials(cfg):
            core.token(path)

    def validate_binding(self, record):
        """Cloudflare path/zone/server binding is checked by the shared ledger."""
        return None

    def native_arguments(self, path, seconds):
        self.require("fixed_native")
        return ["--dns-cloudflare", "--dns-cloudflare-credentials", path,
                "--dns-cloudflare-propagation-seconds", str(seconds)]

    def _call(self, path, endpoint, method="GET", params=None, data=None, record_lookup=False):
        try:
            request = core.cf if self._transport is None else self._transport
            return request(path, endpoint, method=method, params=params, data=data)
        except core.CloudflareRejected:
            if method == "POST":
                raise ProviderRejected("DNS provider explicitly rejected creation") from None
            raise ProviderError("DNS provider operation failed") from None
        except HTTPError as error:
            try:
                error.close()
            except Exception:
                raise ProviderError("DNS provider operation failed") from None
            if method == "GET" and record_lookup and error.code == 404:
                return _MISSING
            raise ProviderError("DNS provider operation failed") from None
        except Exception:
            raise ProviderError("DNS provider operation failed") from None

    def zones(self, cfg):
        self.require("zone_discovery")
        result = {}
        for path in self.credentials(cfg):
            page = 1
            while True:
                response = self._call(path, "zones", params={"status": "active", "page": page, "per_page": 50})
                for zone in response["result"]:
                    name, _ = core.dns_name(zone["name"])
                    if name:
                        result.setdefault(name, {"id": zone["id"], "credentials": path,
                                                 "ns": zone.get("name_servers", [])})
                if page >= response.get("result_info", {}).get("total_pages", 1):
                    break
                page += 1
        return result

    def fixed_create(self, path, zone, name, value):
        self.require("fixed_hooks")
        response = self._call(path, "zones/" + zone + "/dns_records", method="POST",
                              data={"type": "TXT", "name": name, "content": value, "ttl": 120})
        return response["result"]["id"]

    def fixed_delete(self, path, zone, record_id):
        self.require("fixed_hooks")
        # The legacy hook treats transport success as completion. It has no
        # durable ownership receipt and must not acquire the owned-TXT contract.
        self._call(path, "zones/" + zone + "/dns_records/" + record_id, method="DELETE")

    @staticmethod
    def valid_zone_id(value):
        return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{32}", value) is not None

    valid_record_id = valid_zone_id

    def record_id(self, remote):
        identifier = remote.get("id") if isinstance(remote, dict) else None
        if not self.valid_record_id(identifier):
            raise ProviderError("Invalid DNS provider record identity")
        return identifier

    @staticmethod
    def matches(remote, receipt, owned=False):
        return (remote.get("type") == "TXT" and remote.get("name") == receipt["name"]
                and remote.get("content") in (receipt["value"], '"' + receipt["value"] + '"')
                and (not owned or remote.get("comment") == receipt["owner"]))

    def _api(self, receipt, method="GET", record_id=None, params=None, data=None, zone=False):
        self.require("owned_txt")
        endpoint = "zones/" + receipt["zone"]
        if not zone:
            endpoint += "/dns_records"
        if record_id is not None:
            endpoint += "/" + record_id
        response = self._call(receipt["credentials"], endpoint, method=method, params=params,
                              data=data, record_lookup=record_id is not None)
        if response is _MISSING:
            return None
        if not isinstance(response, dict):
            raise ProviderError("Invalid DNS provider response")
        return response

    def list_records(self, receipt, exact_name=True, require_complete=False):
        require_complete = require_complete or not exact_name
        records = []
        page = 1
        expected_pages = None
        expected_count = None
        while True:
            params = {"page": page, "per_page": 100}
            if exact_name:
                params.update(type="TXT", name=receipt["name"])
            response = self._api(receipt, params=params)
            values = response.get("result")
            info = response.get("result_info", {})
            pages = info.get("total_pages", 1) if isinstance(info, dict) else None
            if (not isinstance(values, list) or any(not isinstance(value, dict) for value in values)
                    or type(pages) is not int or not 0 <= pages <= 100):
                raise ProviderError("Invalid DNS provider response")
            if pages == 0:
                if (page != 1 or values
                        or any(type(info.get(key)) is not int for key in ("page", "count", "total_count"))
                        or (info["page"], info["count"], info["total_count"]) != (1, 0, 0)):
                    raise ProviderError("Invalid empty DNS provider listing")
                pages = 1
            if require_complete:
                count = info.get("total_count")
                if ("total_pages" not in info or type(info.get("page")) is not int
                        or type(info.get("count")) is not int
                        or info["page"] != page or info["count"] != len(values)
                        or type(count) is not int or count < 0
                        or (expected_pages is not None and pages != expected_pages)
                        or (expected_count is not None and count != expected_count)):
                    raise ProviderError("Incomplete DNS provider listing")
                expected_pages, expected_count = pages, count
            records.extend(values)
            if page >= pages:
                if require_complete and (len(records) != expected_count or
                        len({self.record_id(remote) for remote in records}) != len(records)):
                    raise ProviderError("Incomplete DNS provider listing")
                return records
            page += 1

    def get_record(self, receipt):
        response = self._api(receipt, record_id=receipt["record"])
        if response is None:
            return None
        remote = response.get("result")
        self.record_id(remote)
        return remote

    def create_txt(self, receipt):
        response = self._api(receipt, method="POST", data={"type": "TXT", "name": receipt["name"],
                             "content": '"' + receipt["value"] + '"', "ttl": 120, "comment": receipt["owner"]})
        return response.get("result")

    def delete_record(self, receipt):
        response = self._api(receipt, method="DELETE", record_id=receipt["record"])
        if self.record_id(response.get("result")) != receipt["record"]:
            raise ProviderError("DNS challenge deletion remains unresolved")

    def confirm_absent(self, receipt):
        # Record GET 404 can hide lack of access. Prove the exact zone and use
        # a complete unfiltered listing so renamed/foreign rows still count.
        response = self._api(receipt, zone=True)
        if self.record_id(response.get("result")) != receipt["zone"]:
            raise ProviderError("DNS challenge zone is unavailable")
        if any(remote["id"] == receipt["record"] for remote in self.list_records(receipt, exact_name=False)):
            raise ProviderError("DNS challenge deletion remains unresolved")
