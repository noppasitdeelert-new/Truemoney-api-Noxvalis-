"""IP-intelligence services and blockchain explorers for OSINT families."""

from __future__ import annotations

from typing import List, Tuple


def _rows(blob: str, fields: int = 3) -> List[Tuple[str, ...]]:
    rows: List[Tuple[str, ...]] = []
    for line in blob.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        rows.append(tuple(part.strip() for part in line.split("|", fields - 1)))
    return rows


# slug|name|url with {q} = IP, CIDR, ASN or domain
IP_SERVICES = _rows(
    """
shodan|Shodan|https://www.shodan.io/search?query={q}
shodan-host|Shodan host|https://www.shodan.io/host/{q}
censys|Censys|https://search.censys.io/search?resource=hosts&q={q}
fofa|FOFA|https://en.fofa.info/result?qbase64={q}
zoomeye|ZoomEye|https://www.zoomeye.org/searchResult?q={q}
netlas|Netlas|https://app.netlas.io/host/{q}
binaryedge|BinaryEdge|https://app.binaryedge.io/services/query?query={q}
fullhunt|FullHunt|https://fullhunt.io/search?q={q}
leakix|LeakIX|https://leakix.net/search?scope=leak&q={q}
criminalip|Criminal IP|https://www.criminalip.io/asset/search?query={q}
onyphe|Onyphe|https://www.onyphe.io/search/?query={q}
greyNoise|GreyNoise|https://viz.greynoise.io/query/{q}
greynoise-lookup|GreyNoise lookup|https://api.greynoise.io/v3/community/{q}
ipinfo|IPinfo|https://ipinfo.io/{q}
ipapi|ipapi.co|https://ipapi.co/{q}/json/
ipapi-com|ip-api.com|http://ip-api.com/json/{q}
ipwhois|IPWhois|https://ipwhois.app/json/{q}
ipgeolocation|IPGeolocation.io|https://ipgeolocation.io/ip-location/{q}
ipstack|ipstack|https://ipstack.com/
abstractapi|Abstract IP Geolocation|https://app.abstractapi.com/api/ip-geolocation/
ipdata|IPData|https://ipdata.co/
ipregistry|IPregistry|https://ipregistry.co/{q}
maxmind|MaxMind GeoIP|https://www.maxmind.com/en/geoip-demo
dbip|DB-IP|https://db-ip.com/{q}
ip2location|IP2Location|https://www.ip2location.com/demo/{q}
ipaddress|IPAddress.com|https://www.ipaddress.com/ipv4/{q}
iplocation|IPLocation.net|https://www.iplocation.net/{q}
keycdn|KeyCDN IP lookup|https://tools.keycdn.com/geo?host={q}
whatismyipaddress|WhatIsMyIPAddress|https://whatismyipaddress.com/ip/{q}
myip|MyIP|https://myip.ms/info/whois/{q}
ipchicken|IP Chicken|https://ipchicken.com/
ipfingerprints|IPFingerprints|https://ipfingerprints.com/ip-lookup/{q}
bgpview|BGPView|https://bgpview.io/ip/{q}
bgp-he|BGP.he.net|https://bgp.he.net/ip/{q}
bgpstream|BGPStream|https://bgpstream.com/
routeviews|RouteViews|https://routeviews.org/
peeringdb|PeeringDB|https://www.peeringdb.com/search?q={q}
asrank|CAIDA AS Rank|https://asrank.caida.org/asns?asn={q}
team-cymru|Team Cymru|https://team-cymru.com/community-services/ip-asn-mapping/
spamhaus|Spamhaus|https://check.spamhaus.org/results?q={q}
barracuda|Barracuda Reputation|https://www.barracudacentral.org/lookups/lookup-reputation?ip={q}
mxtoolbox|MxToolbox blacklist|https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a{q}
ultratools|UltraTools|https://www.ultratools.com/tools/ipWhoisLookupResult?ipAddress={q}
abuseipdb|AbuseIPDB|https://www.abuseipdb.com/check/{q}
talos|Cisco Talos|https://talosintelligence.com/reputation_center/lookup?search={q}
otx|AlienVault OTX|https://otx.alienvault.com/indicator/ip/{q}
otx-domain|AlienVault OTX domain|https://otx.alienvault.com/indicator/domain/{q}
threatminer|ThreatMiner|https://www.threatminer.org/host.php?q={q}
threatcrowd|ThreatCrowd|https://www.threatcrowd.org/searchApi/v2/ip/report/?ip={q}
virustotal|VirusTotal|https://www.virustotal.com/gui/ip-address/{q}
virustotal-domain|VirusTotal domain|https://www.virustotal.com/gui/domain/{q}
urlscan|urlscan.io|https://urlscan.io/ip/{q}
scamalytics|Scamalytics|https://scamalytics.com/ip/{q}
stopforumspam|StopForumSpam|https://www.stopforumspam.com/ipcheck/{q}
ipqualityscore|IPQualityScore|https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{q}
fraudguard|FraudGuard|https://fraudguard.io/
intelx|Intelligence X|https://intelx.io/?s={q}
domaintools|DomainTools|https://whois.domaintools.com/{q}
whoisxml|WhoisXML API|https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName={q}
viewdns|ViewDNS|https://viewdns.info/iphistory/?domain={q}
dnslytics|DNSlytics|https://dnslytics.com/ip/{q}
securitytrails|SecurityTrails|https://securitytrails.com/domain/{q}/dns
spyse|Spyse|https://spyse.com/target/ip/{q}
robtex|Robtex|https://www.robtex.com/ip-lookup/{q}
hackertarget|HackerTarget|https://api.hackertarget.com/whois/?q={q}
dnsdumpster|DNSdumpster|https://dnsdumpster.com/
hurricaneelectric|Hurricane Electric BGP|https://bgp.he.net/
radb|RADb|https://www.radb.net/query?keywords={q}
rir-ripe|RIPE NCC|https://apps.db.ripe.net/db-web-ui/query?searchtext={q}
rir-arin|ARIN|https://search.arin.net/rdap/?query={q}
rir-apnic|APNIC|https://wq.apnic.net/static/search.html?query={q}
rir-lacnic|LACNIC|https://rdap.lacnic.net/rdap/ip/{q}
rir-afrinic|AFRINIC|https://rdap.afrinic.net/rdap/ip/{q}
rdap-org|RDAP.org|https://rdap.org/ip/{q}
caida|CAIDA|https://www.caida.org/
ipv6-test|IPv6 test|https://ipv6-test.com/
test-ipv6|Test-IPv6|https://test-ipv6.com/
dnsleaktest|DNS Leak Test|https://www.dnsleaktest.com/
browserleaks|BrowserLeaks|https://browserleaks.com/ip
ipleak|IPLeak|https://ipleak.net/
whatleaks|WhatLeaks|https://whatleaks.com/
doileak|DoILeak|https://www.doileak.com/
whoer|Whoer|https://whoer.net/
check-host|check-host.net|https://check-host.net/check-ping?host={q}
ping-eu|ping.eu|https://ping.eu/ping/
portchecker|PortChecker|https://portchecker.co/check?host={q}
canyouseeme|CanYouSeeMe|https://canyouseeme.org/
dnschecker|DNSChecker|https://dnschecker.org/#A/{q}
intodns|IntoDNS|https://intodns.com/{q}
dnsviz|DNSViz|https://dnsviz.net/d/{q}/dnssec/
zonemaster|Zonemaster|https://zonemaster.net/
mxtoolbox-dns|MxToolbox DNS|https://mxtoolbox.com/SuperTool.aspx?action=dns%3a{q}
cloudflare-radar|Cloudflare Radar|https://radar.cloudflare.com/domains/domain/{q}
urlhaus|URLhaus|https://urlhaus.abuse.ch/browse.php?search={q}
feodotracker|Feodo Tracker|https://feodotracker.abuse.ch/browse.php?search={q}
sslbl|SSLBL|https://sslbl.abuse.ch/blacklist/
threatfox|ThreatFox|https://threatfox.abuse.ch/browse.php?search={q}
malwarebazaar|MalwareBazaar|https://bazaar.abuse.ch/browse/
pulsedive|Pulsedive|https://pulsedive.com/indicator/?ioc={q}
hunt|Hunt.io|https://hunt.io/
shodan-cve|Shodan CVE|https://www.shodan.io/search?query=vuln%3A{q}
censys-cve|Censys CVE|https://search.censys.io/search?resource=hosts&q=services.vuln%3A{q}
nvd|NVD|https://nvd.nist.gov/vuln/search/results?query={q}
cve|CVE.org|https://www.cve.org/CVERecord?id={q}
exploitdb|Exploit-DB|https://www.exploit-db.com/search?q={q}
github-advisories|GitHub Advisories|https://github.com/advisories?query={q}
osv|OSV|https://osv.dev/list?q={q}
snyk-vuln|Snyk|https://security.snyk.io/vuln?search={q}
vulners|Vulners|https://vulners.com/search?query={q}
cvedetails|CVE Details|https://www.cvedetails.com/google-search-results.php?q={q}
mitre-attack|MITRE ATT&CK|https://attack.mitre.org/
sigma|Sigma rules|https://github.com/SigmaHQ/sigma
yara|YARA rules|https://github.com/Yara-Rules/rules
"""
)

# slug|name|explorer template ({a} = address)|address regex (may contain |)
CRYPTO_CHAINS = _rows(
    fields=4,
    blob=
    """
btc|Bitcoin|https://blockstream.info/address/{a}|^(bc1[a-z0-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$
eth|Ethereum|https://etherscan.io/address/{a}|^0x[0-9a-fA-F]{40}$
bsc|BNB Smart Chain|https://bscscan.com/address/{a}|^0x[0-9a-fA-F]{40}$
polygon|Polygon|https://polygonscan.com/address/{a}|^0x[0-9a-fA-F]{40}$
arbitrum|Arbitrum|https://arbiscan.io/address/{a}|^0x[0-9a-fA-F]{40}$
optimism|Optimism|https://optimistic.etherscan.io/address/{a}|^0x[0-9a-fA-F]{40}$
base|Base|https://basescan.org/address/{a}|^0x[0-9a-fA-F]{40}$
linea|Linea|https://lineascan.build/address/{a}|^0x[0-9a-fA-F]{40}$
scroll|Scroll|https://scrollscan.com/address/{a}|^0x[0-9a-fA-F]{40}$
zksync|zkSync Era|https://explorer.zksync.io/address/{a}|^0x[0-9a-fA-F]{40}$
mantle|Mantle|https://explorer.mantle.xyz/address/{a}|^0x[0-9a-fA-F]{40}$
avalanche|Avalanche|https://snowtrace.io/address/{a}|^0x[0-9a-fA-F]{40}$
fantom|Fantom|https://ftmscan.com/address/{a}|^0x[0-9a-fA-F]{40}$
cronos|Cronos|https://cronoscan.com/address/{a}|^0x[0-9a-fA-F]{40}$
gnosis|Gnosis|https://gnosisscan.io/address/{a}|^0x[0-9a-fA-F]{40}$
celo|Celo|https://celoscan.io/address/{a}|^0x[0-9a-fA-F]{40}$
moonbeam|Moonbeam|https://moonscan.io/address/{a}|^0x[0-9a-fA-F]{40}$
moonriver|Moonriver|https://moonriver.moonscan.io/address/{a}|^0x[0-9a-fA-F]{40}$
aurora|Aurora|https://explorer.aurora.dev/address/{a}|^0x[0-9a-fA-F]{40}$
harmony|Harmony|https://explorer.harmony.one/address/{a}|^0x[0-9a-fA-F]{40}$
klaytn|Kaia (Klaytn)|https://klaytnscope.com/account/{a}|^0x[0-9a-fA-F]{40}$
tron|Tron|https://tronscan.org/#/address/{a}|^T[1-9A-HJ-NP-Za-km-z]{33}$
solana|Solana|https://solscan.io/account/{a}|^[1-9A-HJ-NP-Za-km-z]{32,44}$
near|NEAR|https://nearblocks.io/address/{a}|^[a-z0-9._-]{2,64}$
aptos|Aptos|https://explorer.aptoslabs.com/account/{a}|^0x[0-9a-fA-F]{1,64}$
sui|Sui|https://suiexplorer.com/address/{a}|^0x[0-9a-fA-F]{64}$
cosmos|Cosmos Hub|https://www.mintscan.io/cosmos/account/{a}|^cosmos1[a-z0-9]{38}$
osmosis|Osmosis|https://www.mintscan.io/osmosis/account/{a}|^osmo1[a-z0-9]{38}$
juno|Juno|https://www.mintscan.io/juno/account/{a}|^juno1[a-z0-9]{38}$
secret|Secret Network|https://www.mintscan.io/secret/account/{a}|^secret1[a-z0-9]{38}$
akash|Akash|https://www.mintscan.io/akash/account/{a}|^akash1[a-z0-9]{38}$
celestia|Celestia|https://www.mintscan.io/celestia/account/{a}|^celestia1[a-z0-9]{38}$
polkadot|Polkadot|https://polkadot.subscan.io/account/{a}|^1[1-9A-HJ-NP-Za-km-z]{46,48}$
kusama|Kusama|https://kusama.subscan.io/account/{a}|^[A-HJ-NP-Za-km-z1-9]{47,48}$
cardano|Cardano|https://cardanoscan.io/address/{a}|^addr1[a-z0-9]{20,110}$
tezos|Tezos|https://tzkt.io/{a}|^(tz[1-4]|KT1)[1-9A-HJ-NP-Za-km-z]{33}$
algorand|Algorand|https://allo.info/account/{a}|^[A-Z2-7]{58}$
stellar|Stellar|https://stellar.expert/explorer/public/account/{a}|^G[A-Z2-7]{55}$
xrp|XRP Ledger|https://xrpscan.com/account/{a}|^r[1-9A-HJ-NP-Za-km-z]{24,34}$
litecoin|Litecoin|https://blockchair.com/litecoin/address/{a}|^(ltc1[a-z0-9]{20,60}|[LM3][a-km-zA-HJ-NP-Z1-9]{26,33})$
dogecoin|Dogecoin|https://blockchair.com/dogecoin/address/{a}|^D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}$
bitcoin-cash|Bitcoin Cash|https://blockchair.com/bitcoin-cash/address/{a}|^(bitcoincash:)?[qp][a-z0-9]{41}$
bitcoin-sv|Bitcoin SV|https://blockchair.com/bitcoin-sv/address/{a}|^1[1-9A-HJ-NP-Za-km-z]{32}$
dash|Dash|https://blockchair.com/dash/address/{a}|^X[1-9A-HJ-NP-Za-km-z]{33}$
zcash|Zcash|https://blockchair.com/zcash/address/{a}|^(t1|t3|zs)[1-9A-HJ-NP-Za-km-z]{30,90}$
monero|Monero|https://xmrchain.net/search?value={a}|^[48][1-9A-HJ-NP-Za-km-z]{94}$
eos|EOS|https://bloks.io/account/{a}|^[a-z1-5.]{1,12}$
wax|WAX|https://wax.bloks.io/account/{a}|^[a-z1-5.]{1,12}$
flow|Flow|https://flowscan.org/account/{a}|^0x[0-9a-f]{16}$
hedera|Hedera|https://hashscan.io/mainnet/account/{a}|^0\\.0\\.[0-9]{1,10}$
iota|IOTA|https://explorer.iota.org/address/{a}|^(iota1|atoi1)[a-z0-9]{50,70}$
neo|NEO|https://explorer.onegate.space/address/{a}|^N[A-Za-z0-9]{33}$
ontology|Ontology|https://explorer.ont.io/address/{a}|^A[A-Za-z0-9]{33}$
vechain|VeChain|https://explore.vechain.org/accounts/{a}|^0x[0-9a-fA-F]{40}$
theta|Theta|https://explorer.thetatoken.org/account/{a}|^0x[0-9a-fA-F]{40}$
chiliz|Chiliz|https://scan.chiliz.com/address/{a}|^0x[0-9a-fA-F]{40}$
okc|OKC|https://www.oklink.com/okc/address/{a}|^0x[0-9a-fA-F]{40}$
heco|HECO|https://www.hecoinfo.com/en-us/address/{a}|^0x[0-9a-fA-F]{40}$
kcc|KCC|https://scan.kcc.io/address/{a}|^0x[0-9a-fA-F]{40}$
evmos|Evmos|https://www.mintscan.io/evmos/account/{a}|^evmos1[a-z0-9]{38}$
injective|Injective|https://www.mintscan.io/injective/account/{a}|^inj1[a-z0-9]{38}$
kava|Kava|https://www.mintscan.io/kava/account/{a}|^kava1[a-z0-9]{38}$
polygon-zkevm|Polygon zkEVM|https://zkevm.polygonscan.com/address/{a}|^0x[0-9a-fA-F]{40}$
blast|Blast|https://blastscan.io/address/{a}|^0x[0-9a-fA-F]{40}$
manta|Manta Pacific|https://pacific-explorer.manta.network/address/{a}|^0x[0-9a-fA-F]{40}$
opbnb|opBNB|https://opbnbscan.com/address/{a}|^0x[0-9a-fA-F]{40}$
zetachain|ZetaChain|https://explorer.zetachain.com/address/{a}|^0x[0-9a-fA-F]{40}$
sonic|Sonic|https://explorer.soniclabs.com/address/{a}|^0x[0-9a-fA-F]{40}$
berachain|Berachain|https://berascan.com/address/{a}|^0x[0-9a-fA-F]{40}$
unichain|Unichain|https://uniscan.xyz/address/{a}|^0x[0-9a-fA-F]{40}$
ink|Ink|https://explorer.inkonchain.com/address/{a}|^0x[0-9a-fA-F]{40}$
worldchain|World Chain|https://worldscan.org/address/{a}|^0x[0-9a-fA-F]{40}$
gravity|Gravity|https://explorer.gravity.xyz/address/{a}|^0x[0-9a-fA-F]{40}$
taiko|Taiko|https://taikoscan.io/address/{a}|^0x[0-9a-fA-F]{40}$
morph|Morph|https://explorer.morphl2.io/address/{a}|^0x[0-9a-fA-F]{40}$
mode|Mode|https://explorer.mode.network/address/{a}|^0x[0-9a-fA-F]{40}$
"""
)
