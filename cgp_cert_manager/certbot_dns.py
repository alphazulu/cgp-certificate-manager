"""Certbot authenticator for supervised, adaptive Cloudflare DNS challenges."""

from acme import challenges
from certbot import errors, interfaces
from certbot.plugins import common

from . import certbot_runner, core, dnsauth, dnschecks, dnsconfig


class Authenticator(common.Plugin, interfaces.Authenticator):
    """Use Certbot's batch authenticator boundary to stop before ACME answer."""

    description = "Managed Cloudflare DNS challenges with adaptive propagation checks"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session = None

    @classmethod
    def add_parser_arguments(cls, add):
        # Configuration belongs to the manager's secure configuration file;
        # no API secrets or ownership metadata are accepted as CLI arguments.
        pass

    def more_info(self):
        return self.description

    def get_chall_pref(self, identifier):
        return [challenges.DNS01]

    def _config(self):
        cfg = certbot_runner.require_context()
        policy = dnsconfig.validate(cfg)
        if policy["mode"] != "adaptive":
            raise core.Error("Adaptive DNS mode is required")
        return cfg, policy

    def prepare(self):
        try:
            cfg, _ = self._config()
            dnsauth.cleanup_pending(cfg)
        except Exception:
            raise errors.PluginError("Adaptive DNS initialization failed; inspect DNS challenge receipts") from None

    def _requested_names(self, batch):
        # ACME authorizations represent wildcard identifiers by their base
        # name.  Certbot's annotated challenge consequently loses the star;
        # CAA policy must still use the original requested certificate names.
        requested = getattr(self.config, "domains", None)
        if not isinstance(requested, (list, tuple)) or not requested:
            raise core.Error("Requested certificate identifiers are unavailable")
        names = []
        for raw in requested:
            name, error = core.dns_name(raw)
            if error:
                raise core.Error("Invalid requested certificate identifier")
            names.append(name)
        bases = {name.removeprefix("*.") for name in names}
        if any(dnsauth.challenge_name(name, value)[16:] not in bases for name, value in batch):
            raise core.Error("DNS challenge does not match requested certificate")
        return list(dict.fromkeys(names))

    def perform(self, achalls):
        try:
            cfg, policy = self._config()
            if self.session is not None:
                raise core.Error("A DNS challenge batch is already active")
            batch = []
            for achall in achalls:
                if not isinstance(achall.chall, challenges.DNS01):
                    raise core.Error("Unsupported DNS challenge type")
                identifier = (achall.identifier.value if hasattr(achall, "identifier") else achall.domain)
                value = achall.validation(achall.account_key)
                dnsauth.challenge_name(identifier, value)
                batch.append((identifier, value))
            if not batch:
                return []
            names = self._requested_names(batch)
            zones = core.zones(cfg)
            domain = {"names": names, "unavailable": [],
                      "cgp_domain": batch[0][0].removeprefix("*.")}
            dnschecks.require_ready(domain, zones, cfg)
            self.session = dnsauth.Session(cfg)
            for identifier, value in batch:
                self.session.create(identifier, value, zones)
            dnschecks.wait_for_txt(batch, zones, policy["timeout_seconds"],
                                   policy["poll_interval_seconds"])
            return [achall.response(achall.account_key) for achall in achalls]
        except Exception:
            raise errors.PluginError("DNS challenge setup or propagation failed; cleanup may be pending") from None

    def cleanup(self, achalls):
        if self.session is None:
            return
        try:
            certbot_runner.require_context()
            self.session.cleanup()
            self.session = None
        except Exception:
            raise errors.PluginError("DNS challenge cleanup is pending") from None
