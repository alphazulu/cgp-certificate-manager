// The master is the validated fresh snapshot, not a raw domain-only query.
try {
    var data = JSON.parse(value);
    if (data.collection_success !== 1 || !data.operational) {
        throw 'Incomplete observation';
    }
    return JSON.stringify(Object.keys(data.operational.domains).sort().map(function (domain) {
        var row = data.operational.domains[domain];
        return {'{#CGP_DOMAIN}': domain, '{#CGP_CERT_NAME}': row.cert_name, '{#CGP_ENABLED}': row.enabled};
    }));
} catch (error) {
    throw 'CGP monitoring discovery is incomplete';
}
