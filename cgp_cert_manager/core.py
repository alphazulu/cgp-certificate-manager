import base64, csv, hashlib, ipaddress, json, logging, os, re, subprocess, tempfile, urllib.request, urllib.parse, time
from pathlib import Path
from datetime import datetime, timezone

CONFIG = Path('/etc/cgp-letsencrypt/config.json')
STATE = Path('/var/lib/cgp-letsencrypt')
LIVE = Path('/etc/letsencrypt/live')
LOG = logging.getLogger('cgp')
FIELDS = ('PrivateSecureKey', 'SecureCertificate', 'CAChain', 'CertificateType')

class Error(Exception): pass
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): return None

def opener(): return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
def atomic(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f, indent=2, ensure_ascii=False); f.write('\n'); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def load(path, default=None):
    if not path.exists() and default is not None: return default
    return json.loads(path.read_text())

def dns_name(value):
    s = value.strip().rstrip('.').lower(); wild = s.startswith('*.'); s = s[2:] if wild else s
    try: ipaddress.ip_address(s.strip('[]'))
    except ValueError: pass
    else: return None, 'ip_address'
    try: s = s.encode('idna').decode('ascii')
    except UnicodeError: return None, 'invalid_dns_name'
    if len(s)>253 or '.' not in s or s.split('.')[-1].isdigit() or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in s.split('.')): return None, 'invalid_dns_name'
    return ('*.' if wild else '')+s, None

def identifier(s):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*', s) or '..' in s or s.endswith('.'): raise Error('Invalid identifier')
    return s

def cli(cfg, command):
    c=cfg['communigate']; url=c['url']
    if not re.fullmatch(r'http://127\.0\.0\.1:\d+/CLI/',url,re.I): raise Error('CGP URL must be loopback')
    auth=base64.b64encode((c['username']+':'+c['password']).encode()).decode()
    req=urllib.request.Request(url, data=urllib.parse.urlencode({'command':command}).encode(), headers={'Authorization':'Basic '+auth,'Content-Type':'application/x-www-form-urlencoded'})
    with opener().open(req, timeout=60) as r: return r.read().decode('utf-8')

def array(s):
    s=s.strip()
    if not s.startswith('(') or not s.endswith(')'): raise Error('Unexpected CGP array')
    return [v.strip() for v in next(csv.reader([s[1:-1].replace('\n',' ')],skipinitialspace=True)) if v.strip()]

def token(path):
    for line in Path(path).read_text().splitlines():
        k,_,v=line.partition('=')
        if k.strip()=='dns_cloudflare_api_token' and v.strip(): return v.strip()
    raise Error('Cloudflare token missing')

def cf(path, endpoint, method='GET', params=None, data=None):
    url='https://api.cloudflare.com/client/v4/'+endpoint
    if params: url+='?'+urllib.parse.urlencode(params)
    req=urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None, method=method, headers={'Authorization':'Bearer '+token(path),'Content-Type':'application/json'})
    with opener().open(req,timeout=40) as r: p=json.load(r)
    if not p.get('success'): raise Error('Cloudflare API rejected request')
    return p

def zones(cfg):
    out={}
    accounts=cfg.get('cloudflare_accounts') or [{'credentials':cfg['cloudflare_credentials']}]
    for a in accounts:
        path=a['credentials']; page=1
        while True:
            p=cf(path,'zones',params={'status':'active','page':page,'per_page':50})
            for z in p['result']:
                n,e=dns_name(z['name'])
                if n: out.setdefault(n,{'id':z['id'],'credentials':path,'ns':z.get('name_servers',[])})
            if page>=p.get('result_info',{}).get('total_pages',1): break
            page+=1
    return out

def zone_for(name,z):
    n=name.removeprefix('*.'); return max((x for x in z if n==x or n.endswith('.'+x)),key=len,default=None)

def covered(n,w): return w.startswith('*.') and not n.startswith('*.') and n.endswith(w[1:]) and n.count('.')==w.count('.')

def discover(cfg,z):
    overrides={d['cgp_domain']:d for d in cfg.get('domains',[])}
    out=[]
    for name in sorted(set(array(cli(cfg,'LISTDOMAINS')))):
        identifier(name); d=overrides.get(name,{})
        aliases=array(cli(cfg,'GETDOMAINALIASES '+name)); candidates=[name]+(['*.'+name] if d.get('wildcard',True) else [])+aliases+d.get('extra_names',[])
        excluded={dns_name(x)[0] for x in d.get('exclude_names',[])}; accepted=set(); unavailable=set(); skipped={}
        for raw in candidates:
            n,e=dns_name(raw)
            if e: skipped[raw]=e
            elif n in excluded: skipped[raw]='excluded_manually'
            elif not zone_for(n,z): skipped[raw]='cloudflare_zone_unavailable'; unavailable.add(n)
            else: accepted.add(n)
        names=sorted(n for n in accepted if n==name or not any(covered(n,w) for w in accepted))
        for n in accepted-set(names): skipped[n]='covered_by_wildcard'
        if len(names)>100: raise Error('Too many SAN identifiers: '+name)
        out.append({'cgp_domain':name,'cert_name':identifier(d.get('cert_name',name)),'enabled':d.get('enabled',cfg.get('auto_enable_new_domains',True)),'aliases':aliases,'names':names,'unavailable':sorted(unavailable),'skipped_names':skipped,'cloudflare_available':name in names,'tls':d.get('tls',cfg.get('tls',[]))})
    if len({d['cert_name'] for d in out})!=len(out): raise Error('Duplicate certificate lineage')
    return out

def run(*args, data=None, timeout=60):
    p=subprocess.run(args,input=b'' if data is None else data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
    if p.returncode: raise Error(f'{args[0]} failed ({p.returncode})')
    return p.stdout


def chain_payload(pem):
    import base64
    import re

    blocks = re.findall(
        rb"-----BEGIN CERTIFICATE-----\s*(.*?)"
        rb"\s*-----END CERTIFICATE-----",
        pem,
        re.S
    )

    if not blocks:
        raise Error("Empty CA certificate chain")

    certificates = [
        base64.b64decode(
            b"".join(block.split()),
            validate=True
        )
        for block in blocks
    ]

    return base64.b64encode(
        b"".join(certificates)
    ).decode("ascii")


def certificate_settings_match(old, new):
    import base64
    import re

    def decode(value):
        value = value.strip()

        if not (
            value.startswith("[")
            and value.endswith("]")
        ):
            raise ValueError("Invalid CGP DataBlock")

        return base64.b64decode(
            re.sub(r"\s+", "", value[1:-1]),
            validate=True
        )

    try:
        if old.get(
            "CertificateType", ""
        ).strip('"').upper() != "YES":
            return False

        for field in (
            "PrivateSecureKey",
            "SecureCertificate",
            "CAChain"
        ):
            if decode(old.get(field, "")) != decode(new[field]):
                return False

        return True

    except (ValueError, TypeError, KeyError):
        return False


def payload(pem): return b''.join(x.strip() for x in pem.splitlines() if not x.startswith(b'-----')).decode('ascii')
def fp(value): return hashlib.sha256(base64.b64decode(value,validate=True)).hexdigest()
def fields(text):
    out={}
    for k in FIELDS:
        m=re.search(r'(?m)(?<![\w])'+k+r'\s*=\s*(\[[A-Za-z0-9+/=\s]*\]|[A-Za-z][A-Za-z0-9_-]*|"[A-Za-z][A-Za-z0-9_-]*")\s*;',text)
        if m: out[k]=re.sub(r'\s+','',m[1])
    return out

def current(cfg,name): return fields(cli(cfg,'GETDOMAINEFFECTIVESETTINGS '+identifier(name)))
def current_fp(f): return fp(f['SecureCertificate'][1:-1]) if f.get('SecureCertificate','').startswith('[') and len(f['SecureCertificate'])>2 else None

def cert_info(pem):
    der=run('openssl','x509','-outform','DER',data=pem)
    san=run('openssl','x509','-noout','-ext','subjectAltName',data=pem).decode()
    expiry=run('openssl','x509','-noout','-enddate',data=pem).decode().strip().split('=',1)[1]
    dt=datetime.strptime(expiry,'%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
    return {'fingerprint':hashlib.sha256(der).hexdigest(),'names':sorted(set(re.findall(r'DNS:([^,\s]+)',san.lower().replace('dns:','DNS:')))),'days':(dt-datetime.now(timezone.utc)).days,'expiry':dt.isoformat()}

def installed_info(f):
    if not current_fp(f): return None
    b=base64.b64decode(f['SecureCertificate'][1:-1]); return cert_info(run('openssl','x509','-inform','DER',data=b))

def local_info(d):
    p=LIVE/d['cert_name']/'cert.pem'; return cert_info(p.read_bytes()) if p.is_file() else None

def shrink_block(d,old,allow=False):
    if allow or not old: return []
    # Never remove an existing identifier merely because its zone disappeared.
    missing=set(old['names'])-set(d['names']); unavailable=set(d['unavailable'])
    return sorted(n for n in missing if n in unavailable or any(covered(x,n) for x in unavailable) or any(covered(n,x) for x in unavailable))

def dns_preflight(d,z):
    # Compare public delegation against the Cloudflare zone metadata.
    checked=set()
    for n in d['names']:
        zone=zone_for(n,z)
        if zone not in checked:
            expected={x.rstrip('.').lower() for x in z[zone]['ns']}
            actual={x.rstrip('.').lower() for x in run('dig','+short','+time=4','+tries=2','NS',zone).decode().splitlines()}
            if expected and actual!=expected: raise Error('DNS delegation mismatch: '+zone)
            checked.add(zone)
        challenge='_acme-challenge.'+n.removeprefix('*.')
        if run('dig','+short','+time=4','+tries=2','CNAME',challenge).strip(): raise Error('ACME CNAME requires manual configuration: '+challenge)

def issue(cfg,d,z,args):
    local=local_info(d); changed=local is not None and set(local['names'])!=set(d['names'])
    if cfg.get('dns_preflight',True): dns_preflight(d,z)
    paths={z[zone_for(n,z)]['credentials'] for n in d['names']}
    cmd=['certbot','certonly','--non-interactive','--agree-tos','--email',cfg['email'],'--cert-name',d['cert_name'],'--key-type','rsa','--rsa-key-size','2048']
    if len(paths)==1:
        cmd+=['--dns-cloudflare','--dns-cloudflare-credentials',next(iter(paths)),'--dns-cloudflare-propagation-seconds',str(cfg.get('propagation_seconds',60))]
    else:
        cmd+=['--manual','--preferred-challenges','dns','--manual-auth-hook','/usr/local/sbin/cgp-letsencrypt --hook-auth','--manual-cleanup-hook','/usr/local/sbin/cgp-letsencrypt --hook-cleanup']
    cmd+=['--force-renewal' if changed or args.force_renew else '--keep-until-expiring']
    for n in d['names']: cmd+=['-d',n]
    if args.dry_run: cmd+=['--dry-run']
    subprocess.run(cmd,check=True,timeout=3600)

def backup(name,f):
    p=STATE/'backups'/identifier(name)/(datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')+'.json'); atomic(p,f); return p

def update(cfg,name,f):
    if set(f)!=set(FIELDS): raise Error('Incomplete CGP settings; refusing write')
    for k,v in f.items():
        if not re.fullmatch(r'\[[A-Za-z0-9+/=]*\]|[A-Za-z][A-Za-z0-9_-]*|"[A-Za-z][A-Za-z0-9_-]*"',v): raise Error('Unsafe CGP value')
    cli(cfg,'UPDATEDOMAINSETTINGS '+identifier(name)+' {'+''.join(k+'='+v+';' for k,v in f.items())+'}')

def same(a,b): return set(FIELDS)<=a.keys() and set(FIELDS)<=b.keys() and all(a[k].strip('"')==b[k].strip('"') for k in FIELDS)

def pem_fingerprints(data):
    return [hashlib.sha256(base64.b64decode(b''.join(x.split()),validate=True)).hexdigest()
            for x in re.findall(rb'-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----',data,re.S)]

def expected_chain(d):
    p=LIVE/d['cert_name']
    return pem_fingerprints((p/'cert.pem').read_bytes()+(p/'chain.pem').read_bytes())

def tls_endpoints(d):
    # HTTPS/SNI is the default; other listeners are opt-in.
    if d.get('tls') and all(e.get('sni') for e in d['tls']): return d['tls']
    names=set(n for n in d['names'] if not n.startswith('*.'))
    for alias in d.get('aliases',[]):
        n,e=dns_name(alias)
        if n and not n.startswith('*.') and any(n==x or covered(n,x) for x in d['names']): names.add(n)
    templates=d.get('tls') or [{'host':'127.0.0.1','port':443}]
    return [dict(ep,sni=n) for ep in templates for n in ([ep['sni']] if ep.get('sni') else sorted(names))]

def probe_tls(endpoint,expected):
    host=endpoint.get('host','127.0.0.1'); port=int(endpoint['port']); sni=endpoint['sni']; mode=endpoint.get('starttls')
    cmd=['openssl','s_client','-connect',f'{host}:{port}','-servername',sni,'-verify_hostname',sni,'-verify_return_error','-CAfile','/etc/ssl/certs/ca-certificates.crt','-showcerts']
    if mode: cmd+=['-starttls',mode]
    output=run(*cmd,data=b'',timeout=20)
    actual=pem_fingerprints(output)
    if not actual or actual!=expected or b'Verify return code: 0 (ok)' not in output:
        raise Error(f'TLS certificate/chain mismatch: {sni}:{port}')

def verify_tls(d,expected):
    chain=expected_chain(d)
    if not chain or chain[0]!=expected: raise Error('Local certificate changed during verification')
    endpoints=tls_endpoints(d)
    if not endpoints: raise Error('No TLS verification endpoints')
    for endpoint in endpoints: probe_tls(endpoint,chain)

LISTENER_MODES={25:'smtp',110:'pop3',143:'imap',389:'ldap',587:'smtp',5222:'xmpp',5269:'xmpp-server',443:None,465:None,636:None,993:None,995:None,5223:None,5061:None,5349:None,9010:None,9100:None}

def discover_listeners():
    ports=set()
    for line in run('ss','-H','-lntp').decode().splitlines():
        if '"CGServer"' not in line: continue
        parts=line.split()
        if len(parts)>3:
            port=parts[3].rsplit(':',1)[-1]
            if port.isdigit(): ports.add(int(port))
    return [{'port':p,'starttls':LISTENER_MODES[p]} for p in sorted(ports) if p in LISTENER_MODES]

def deploy(cfg,d):
    name=d['cgp_domain']; p=LIVE/d['cert_name']; cert=p/'cert.pem'; key=p/'privkey.pem'; chain=p/'chain.pem'
    info=local_info(d)
    if not info or set(info['names'])!=set(d['names']) or info['days']<1: raise Error('Local certificate SAN/expiry mismatch')
    run('openssl','verify','-purpose','sslserver','-CAfile','/etc/ssl/certs/ca-certificates.crt','-untrusted',str(chain),str(cert))
    if run('openssl','x509','-in',str(cert),'-pubkey','-noout')!=run('openssl','pkey','-in',str(key),'-pubout'): raise Error('Key mismatch')
    # CGP accepts concatenated DER in a single Base64 DataBlock.
    new={'PrivateSecureKey':'['+payload(run('openssl','rsa','-in',str(key),'-traditional'))+']','SecureCertificate':'['+payload(cert.read_bytes())+']','CAChain':'['+chain_payload(chain.read_bytes())+']','CertificateType':'YES'}
    old=current(cfg,name)
    if certificate_settings_match(old,new): verify_tls(d,info['fingerprint']); return 'unchanged'
    # A first installation with no readable old settings is not safely reversible.
    if set(old)!=set(FIELDS): raise Error('Cannot back up all CGP certificate fields; refusing automatic update')
    b=backup(name,old)
    try:
        try: update(cfg,name,new)
        except Exception: LOG.warning('%s: update returned error; checking readback',name)
        if not certificate_settings_match(current(cfg,name),new): raise Error('CGP readback mismatch')
        verify_tls(d,info['fingerprint'])
    except (Exception, KeyboardInterrupt):
        try:
            update(cfg,name,old)
            if not same(current(cfg,name),old): raise Error('Rollback readback mismatch')
        except Exception: raise Error('CRITICAL: rollback unverified; backup '+str(b)) from None
        raise Error('Deployment failed; previous settings restored') from None
    for stale in sorted(b.parent.glob('*.json'),reverse=True)[5:]: stale.unlink()
    return 'installed'

def validate_backup(settings):
    """Reject incomplete or cryptographically invalid backup before any write."""
    if set(settings)!=set(FIELDS) or settings['CertificateType'].strip('"').upper()!='YES':
        raise Error('Backup PKI is disabled or incomplete')
    def decode(field):
        value=settings[field]
        if not value.startswith('[') or not value.endswith(']'):
            raise Error('Invalid backup DataBlock')
        return base64.b64decode(value[1:-1],validate=True)
    key=decode('PrivateSecureKey')
    leaf=decode('SecureCertificate')
    chain=decode('CAChain')
    if run('openssl','pkey','-inform','DER','-pubout',data=key)!=run('openssl','x509','-inform','DER','-pubkey','-noout',data=leaf):
        raise Error('Backup key mismatch')
    # CGP chain is a sequence of complete DER certificates.
    parts=[]
    while chain:
        if len(chain)<2 or chain[0]!=0x30: raise Error('Invalid backup CA DER')
        n=chain[1]
        if n<128: size=2+n
        else:
            width=n&127
            if not 1<=width<=4 or len(chain)<2+width: raise Error('Invalid backup CA DER length')
            size=2+width+int.from_bytes(chain[2:2+width],'big')
        if size>len(chain): raise Error('Truncated backup CA DER')
        parts.append(run('openssl','x509','-inform','DER',data=chain[:size]))
        chain=chain[size:]
    if not parts: raise Error('Empty backup CA chain')
    with tempfile.TemporaryDirectory() as tmp:
        path=Path(tmp)
        (path/'leaf.pem').write_bytes(run('openssl','x509','-inform','DER',data=leaf))
        (path/'chain.pem').write_bytes(b''.join(parts))
        run('openssl','verify','-purpose','sslserver','-CAfile','/etc/ssl/certs/ca-certificates.crt','-untrusted',str(path/'chain.pem'),str(path/'leaf.pem'))
