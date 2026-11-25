"""Pure validation shared by DNS diagnostics, issuance, hooks and setup."""
from . import core, dnsproviders


class DNSConfigError(core.Error, ValueError):
    """A fixed, secret-safe configuration error usable by CLI and wizard."""


def validate(cfg):
    """Return normalized options without changing an existing configuration."""
    if not isinstance(cfg, dict):
        raise DNSConfigError('DNS configuration must be an object')
    try:
        provider = dnsproviders.get_provider(cfg)
    except dnsproviders.ProviderError:
        raise DNSConfigError('Unsupported DNS provider') from None
    propagation = cfg.get('dns_propagation', {})
    if not isinstance(propagation, dict) or set(propagation) - {'mode', 'timeout_seconds', 'poll_interval_seconds'}:
        raise DNSConfigError('Invalid DNS propagation options')
    mode = propagation.get('mode', 'fixed')
    if mode not in ('fixed', 'adaptive'):
        raise DNSConfigError('DNS propagation mode must be fixed or adaptive')
    result = {'mode': mode, 'preflight': cfg.get('dns_preflight', True),
              'propagation_seconds': cfg.get('propagation_seconds', 60),
              'timeout_seconds': propagation.get('timeout_seconds', 300),
              'poll_interval_seconds': propagation.get('poll_interval_seconds', 5)}
    for name, low, high in (('propagation_seconds', 10, 3600),
                            ('timeout_seconds', 30, 3600),
                            ('poll_interval_seconds', 1, 60)):
        if type(result[name]) is not int or not low <= result[name] <= high:
            raise DNSConfigError('Invalid DNS option: ' + name)
    if type(result['preflight']) is not bool:
        raise DNSConfigError('dns_preflight must be a boolean')
    if result['poll_interval_seconds'] >= result['timeout_seconds']:
        raise DNSConfigError('DNS polling interval must be less than timeout')
    if mode == 'adaptive' and not result['preflight']:
        raise DNSConfigError('Adaptive DNS propagation requires preflight')
    if mode == 'adaptive':
        try:
            provider.require('owned_txt')
        except dnsproviders.ProviderError:
            raise DNSConfigError('DNS provider lacks required capability') from None
    return result
