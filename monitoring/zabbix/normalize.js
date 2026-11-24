// Zabbix 7.0 preprocessing body; input is native PROMETHEUS_TO_JSON output.
// ES5 only. Unknown measurements are omitted, never manufactured as zero.
try {
    function requireValue(condition) {
        if (!condition) {
            throw 'Invalid value';
        }
    }
    function own(object, name) {
        return Object.prototype.hasOwnProperty.call(object, name);
    }
    function identifier(name) {
        return name.length <= 253 &&
            /^[A-Za-z0-9][A-Za-z0-9.-]*$/.test(name) &&
            name.indexOf('..') === -1 && name.charAt(name.length - 1) !== '.';
    }
    function number(text) {
        requireValue(typeof text === 'string' &&
            /^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$/.test(text));
        var parsed = Number(text);
        requireValue(isFinite(parsed));
        return parsed;
    }
    function key(name, labels) {
        return name + '\n' + JSON.stringify(Object.keys(labels).sort().map(function (label) {
            return [label, labels[label]];
        }));
    }
    function binary(value) {
        requireValue(value === 0 || value === 1);
        return value;
    }
    function nonnegative(value, integer) {
        requireValue(value >= 0);
        if (integer) {
            requireValue(Math.floor(value) === value && value <= 9007199254740991);
        }
        return value;
    }
    requireValue(typeof value === 'string' && value.length <= 16777216);
    var input = JSON.parse(value);
    requireValue(Array.isArray(input) && input.length <= 20000);
    var prefix = 'cgp_manager_';
    var sources = ['config', 'inventory', 'state', 'transactions', 'resolutions', 'dns_challenges', 'lock'];
    var sourceStates = ['ok', 'missing', 'error', 'busy'];
    var pendingKinds = ['transactions', 'resolutions', 'dns_challenges'];
    var certificateStates = ['ok', 'missing', 'error'];
    var definitions = {
        collection_success: [], collection_timestamp_seconds: [],
        source_status: ['source', 'status'], pending_artifacts: ['kind'],
        domain_info: ['cert_name', 'domain'], domain_enabled: ['domain'],
        domain_in_inventory: ['domain'], local_certificate_status: ['domain', 'status'],
        local_certificate_not_after_timestamp_seconds: ['domain'],
        last_success_timestamp_seconds: ['domain'], recorded_failures: ['domain'],
        retry_timestamp_seconds: ['domain']
    };
    var series = Object.create(null);
    var selected = [];
    var domainInfo = [];
    input.forEach(function (row) {
        requireValue(row !== null && typeof row === 'object' && !Array.isArray(row));
        requireValue(typeof row.name === 'string' && /^[A-Za-z_:][A-Za-z0-9_:]*$/.test(row.name));
        var labels = row.labels === undefined ? {} : row.labels;
        requireValue(labels !== null && typeof labels === 'object' && !Array.isArray(labels));
        Object.keys(labels).forEach(function (label) {
            requireValue(typeof labels[label] === 'string');
        });
        var seriesKey = key(row.name, labels);
        requireValue(!own(series, seriesKey));
        var item = {labels: labels, value: number(row.value)};
        series[seriesKey] = item;
        var suffix = row.name.slice(prefix.length);
        if (row.name.indexOf(prefix) === 0 && own(definitions, suffix)) {
            requireValue(Object.keys(labels).sort().join('\n') === definitions[suffix].join('\n'));
            requireValue(row.type === undefined || row.type === 'gauge');
            item.name = suffix;
            selected.push(item);
            if (suffix === 'domain_info') {
                domainInfo.push(item);
            }
        }
    });
    function metric(name, labels, required) {
        var seriesKey = key(prefix + name, labels);
        if (!own(series, seriesKey)) {
            requireValue(!required);
            return undefined;
        }
        return series[seriesKey].value;
    }
    function oneHot(name, dimension, identity, states) {
        var sum = 0;
        var active;
        states.forEach(function (state, index) {
            var labels = {status: state};
            labels[dimension] = identity;
            var bit = binary(metric(name, labels, true));
            sum += bit;
            if (bit === 1) {
                active = index;
            }
        });
        requireValue(sum === 1);
        return active;
    }
    var result = {collection_success: binary(metric('collection_success', {}, true)),
        generated_at: nonnegative(metric('collection_timestamp_seconds', {}, true), false),
        sources: {}, pending: {}, domains: Object.create(null)};
    sources.forEach(function (source) {
        result.sources[source] = oneHot('source_status', 'source', source, sourceStates);
        if (result.collection_success === 1) {
            requireValue(result.sources[source] === 0);
        }
    });
    pendingKinds.forEach(function (kind) {
        var known = result.sources[kind] === 0;
        var count = metric('pending_artifacts', {kind: kind}, known);
        if (count !== undefined) {
            requireValue(known);
            result.pending[kind] = nonnegative(count, true);
        }
    });
    requireValue(domainInfo.length <= 1000);
    domainInfo.forEach(function (item) {
        var domain = item.labels.domain;
        requireValue(identifier(domain) && identifier(item.labels.cert_name));
        requireValue(result.sources.config === 0 && item.value === 1 && !own(result.domains, domain));
        var labels = {domain: domain};
        var row = {cert_name: item.labels.cert_name, observed_at: result.generated_at,
            enabled: binary(metric('domain_enabled', labels, true)),
            certificate_status: oneHot('local_certificate_status', 'domain', domain, certificateStates)};
        if (result.collection_success === 1) {
            requireValue(row.certificate_status !== 2);
        }
        var inventoryKnown = result.sources.inventory === 0;
        var inInventory = metric('domain_in_inventory', labels, inventoryKnown);
        if (inInventory !== undefined) {
            requireValue(inventoryKnown);
            row.in_inventory = binary(inInventory);
        }
        var readable = row.certificate_status === 0;
        var expiry = metric('local_certificate_not_after_timestamp_seconds', labels, readable);
        if (expiry !== undefined) {
            requireValue(readable);
            row.not_after = expiry;
        }
        [['last_success_timestamp_seconds', 'last_success'], ['recorded_failures', 'failures'],
         ['retry_timestamp_seconds', 'retry_at']].forEach(function (field) {
            var observed = metric(field[0], labels, false);
            if (observed !== undefined) {
                requireValue(result.sources.state === 0);
                row[field[1]] = nonnegative(observed, field[1] === 'failures');
            }
        });
        row.failures_known = own(row, 'failures') ? 1 : 0;
        result.domains[domain] = row;
    });
    selected.forEach(function (item) {
        if (own(item.labels, 'domain')) {
            requireValue(own(result.domains, item.labels.domain));
        }
        if (item.name === 'source_status') {
            requireValue(sources.indexOf(item.labels.source) !== -1 && sourceStates.indexOf(item.labels.status) !== -1);
        }
        if (item.name === 'pending_artifacts') {
            requireValue(pendingKinds.indexOf(item.labels.kind) !== -1);
        }
        if (item.name === 'local_certificate_status') {
            requireValue(certificateStates.indexOf(item.labels.status) !== -1);
        }
    });
    return JSON.stringify(result);
} catch (error) {
    throw 'Invalid CGP monitoring metrics';
}
