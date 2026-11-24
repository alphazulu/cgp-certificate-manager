// Numeric seconds only: Zabbix substitutes these administrator-owned macros.
// This stage never replaces a missing or stale operational value with zero.
try {
    var maxAge = '{$CGP.MAX.AGE.SECONDS}';
    var futureSkew = '{$CGP.FUTURE.SKEW.SECONDS}';
    if (!/^[0-9]{1,8}$/.test(maxAge) || Number(maxAge) < 1 || !/^[0-9]{1,8}$/.test(futureSkew)) {
        throw 'Invalid threshold';
    }
    var data = JSON.parse(value);
    if (data === null || typeof data !== 'object' || typeof data.generated_at !== 'number' || !isFinite(data.generated_at)) {
        throw 'Invalid observation';
    }
    var age = Date.now() / 1000 - data.generated_at;
    if (age > Number(maxAge) || age < -Number(futureSkew)) {
        throw 'Observation is not fresh';
    }
    if (data.collection_success === 1) {
        data.operational = {pending: data.pending, domains: data.domains};
    }
    return JSON.stringify(data);
} catch (error) {
    throw 'CGP monitoring observation is not fresh or valid';
}
