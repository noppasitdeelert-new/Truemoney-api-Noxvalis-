"""OSINT tool directory, public data sources and EXIF tag reference."""

from __future__ import annotations

from typing import List, Tuple


def _rows(blob: str) -> List[Tuple[str, ...]]:
    rows: List[Tuple[str, ...]] = []
    for line in blob.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        rows.append(tuple(part.strip() for part in line.split("|")))
    return rows


# slug|name|homepage|category
OSINT_TOOLS = _rows(
    """
sherlock|Sherlock|https://github.com/sherlock-project/sherlock|username
maigret|Maigret|https://github.com/soxoj/maigret|username
social-analyzer|Social Analyzer|https://github.com/qeeqbox/social-analyzer|username
whatsmyname|WhatsMyName|https://whatsmyname.app/|username
namechk|Namechk|https://namechk.com/|username
holehe|holehe|https://github.com/megadose/holehe|email
h8mail|h8mail|https://github.com/khast3x/h8mail|email
theharvester|theHarvester|https://github.com/laramies/theHarvester|email
emailharvester|EmailHarvester|https://github.com/maldevel/EmailHarvester|email
ghunt|GHunt|https://github.com/mxrch/GHunt|email
epieos|Epieos|https://epieos.com/|email
hunter|Hunter.io|https://hunter.io/|email
phoneinfoga|PhoneInfoga|https://github.com/sundowndev/phoneinfoga|phone
phonenumbers|python-phonenumbers|https://github.com/daviddrysdale/python-phonenumbers|phone
truecaller|Truecaller|https://www.truecaller.com/|phone
numlookup|NumLookup|https://www.numlookup.com/|phone
subfinder|subfinder|https://github.com/projectdiscovery/subfinder|subdomain
amass|OWASP Amass|https://github.com/owasp-amass/amass|subdomain
assetfinder|assetfinder|https://github.com/tomnomnom/assetfinder|subdomain
findomain|Findomain|https://github.com/Findomain/Findomain|subdomain
dnsx|dnsx|https://github.com/projectdiscovery/dnsx|dns
dnsrecon|dnsrecon|https://github.com/darkoperator/dnsrecon|dns
dnsenum|dnsenum|https://github.com/fwaeytens/dnsenum|dns
fierce|fierce|https://github.com/mschwager/fierce|dns
massdns|massdns|https://github.com/blechschmidt/massdns|dns
dnsgen|dnsgen|https://github.com/ProjectAnte/dnsgen|dns
shuffledns|shuffledns|https://github.com/projectdiscovery/shuffledns|dns
puredns|puredns|https://github.com/d3mondev/puredns|dns
httpx|httpx|https://github.com/projectdiscovery/httpx|http
httprobe|httprobe|https://github.com/tomnomnom/httprobe|http
naabu|naabu|https://github.com/projectdiscovery/naabu|port
masscan|masscan|https://github.com/robertdavidgraham/masscan|port
nmap|Nmap|https://nmap.org/|port
rustscan|RustScan|https://github.com/RustScan/RustScan|port
zmap|ZMap|https://zmap.io/|port
nuclei|Nuclei|https://github.com/projectdiscovery/nuclei|vuln
nikto|Nikto|https://github.com/sullo/nikto|vuln
wpscan|WPScan|https://github.com/wpscanteam/wpscan|vuln
joomscan|JoomScan|https://github.com/OWASP/joomscan|vuln
droopescan|Droopescan|https://github.com/SamJoan/droopescan|vuln
whatweb|WhatWeb|https://github.com/urbanadventurer/WhatWeb|fingerprint
wafw00f|WAFW00F|https://github.com/EnableSecurity/wafw00f|fingerprint
nmap-nse|Nmap NSE|https://nmap.org/nsedoc/|fingerprint
cmseek|CMSeeK|https://github.com/Tuhinshubhra/CMSeeK|fingerprint
builtwith|BuiltWith|https://builtwith.com/|fingerprint
wappalyzer|Wappalyzer|https://www.wappalyzer.com/|fingerprint
gobuster|Gobuster|https://github.com/OJ/gobuster|discovery
feroxbuster|feroxbuster|https://github.com/epi052/feroxbuster|discovery
ffuf|ffuf|https://github.com/ffuf/ffuf|discovery
dirsearch|dirsearch|https://github.com/maurosoria/dirsearch|discovery
dirb|DIRB|https://github.com/v0re/dirb|discovery
wfuzz|Wfuzz|https://github.com/xmendez/wfuzz|discovery
arjun|Arjun|https://github.com/s0md3v/Arjun|discovery
paramspider|ParamSpider|https://github.com/devanshbatham/ParamSpider|discovery
gau|gau|https://github.com/lc/gau|discovery
waybackurls|waybackurls|https://github.com/tomnomnom/waybackurls|discovery
katana|Katana|https://github.com/projectdiscovery/katana|crawl
hakrawler|Hakrawler|https://github.com/hakluke/hakrawler|crawl
gospider|GoSpider|https://github.com/jaeles-project/gospider|crawl
photon|Photon|https://github.com/s0md3v/Photon|crawl
scrapy|Scrapy|https://scrapy.org/|crawl
gowitness|gowitness|https://github.com/sensepost/gowitness|screenshot
aquatone|Aquatone|https://github.com/michenriksen/aquatone|screenshot
eyewitness|EyeWitness|https://github.com/FortyNorthSecurity/EyeWitness|screenshot
urlscan|urlscan.io|https://urlscan.io/|screenshot
shodan|Shodan|https://www.shodan.io/|search-engine
censys|Censys|https://censys.io/|search-engine
fofa|FOFA|https://en.fofa.info/|search-engine
zoomeye|ZoomEye|https://www.zoomeye.org/|search-engine
netlas|Netlas|https://netlas.io/|search-engine
binaryedge|BinaryEdge|https://www.binaryedge.io/|search-engine
criminalip|Criminal IP|https://www.criminalip.io/|search-engine
onyphe|Onyphe|https://www.onyphe.io/|search-engine
hunterhow|Hunter.how|https://hunter.how/|search-engine
quake|Quake|https://quake.360.net/|search-engine
greynoise|GreyNoise|https://www.greynoise.io/|threat-intel
virustotal|VirusTotal|https://www.virustotal.com/|threat-intel
otx|AlienVault OTX|https://otx.alienvault.com/|threat-intel
threatfox|ThreatFox|https://threatfox.abuse.ch/|threat-intel
urlhaus|URLhaus|https://urlhaus.abuse.ch/|threat-intel
malwarebazaar|MalwareBazaar|https://bazaar.abuse.ch/|threat-intel
abuseipdb|AbuseIPDB|https://www.abuseipdb.com/|threat-intel
pulsedive|Pulsedive|https://pulsedive.com/|threat-intel
intelx|Intelligence X|https://intelx.io/|threat-intel
misp|MISP|https://www.misp-project.org/|threat-intel
opencti|OpenCTI|https://www.opencti.io/|threat-intel
thehive|TheHive|https://thehive-project.org/|threat-intel
yeti|YETI|https://yeti-platform.github.io/|threat-intel
exiftool|ExifTool|https://exiftool.org/|metadata
exiv2|Exiv2|https://exiv2.org/|metadata
mat2|mat2|https://0xacab.org/jvoisin/mat2|metadata
mediainfo|MediaInfo|https://mediaarea.net/en/MediaInfo|metadata
pdfinfo|pdfinfo (poppler)|https://poppler.freedesktop.org/|metadata
strings|strings (binutils)|https://www.gnu.org/software/binutils/|metadata
binwalk|Binwalk|https://github.com/ReFirmLabs/binwalk|metadata
foremost|Foremost|https://foremost.sourceforge.net/|forensics
scalpel|Scalpel|https://github.com/sleuthkit/scalpel|forensics
sleuthkit|The Sleuth Kit|https://www.sleuthkit.org/|forensics
autopsy|Autopsy|https://www.autopsy.com/|forensics
volatility|Volatility|https://www.volatilityfoundation.org/|forensics
radare2|radare2|https://rada.re/n/|reverse
rizin|Rizin|https://rizin.re/|reverse
ghidra|Ghidra|https://ghidra-sre.org/|reverse
cutter|Cutter|https://cutter.re/|reverse
binja|Binary Ninja|https://binary.ninja/|reverse
ida|IDA|https://hex-rays.com/ida-pro/|reverse
objdump|objdump|https://www.gnu.org/software/binutils/|reverse
dnspy|dnSpy|https://github.com/dnSpy/dnSpy|reverse
jadx|JADX|https://github.com/skylot/jadx|reverse
apktool|Apktool|https://apktool.org/|reverse
frida|Frida|https://frida.re/|reverse
mitmproxy|mitmproxy|https://mitmproxy.org/|network
burp|Burp Suite|https://portswigger.net/burp|network
zap|OWASP ZAP|https://www.zaproxy.org/|network
wireshark|Wireshark|https://www.wireshark.org/|network
tcpdump|tcpdump|https://www.tcpdump.org/|network
tshark|tshark|https://www.wireshark.org/|network
ngrep|ngrep|https://github.com/jpr5/ngrep|network
netcat|netcat|https://nc110.sourceforge.io/|network
socat|socat|http://www.dest-unreach.org/socat/|network
curl|curl|https://curl.se/|http
httpie|HTTPie|https://httpie.io/|http
postman|Postman|https://www.postman.com/|http
insomnia|Insomnia|https://insomnia.rest/|http
selenium|Selenium|https://www.selenium.dev/|automation
playwright|Playwright|https://playwright.dev/|automation
puppeteer|Puppeteer|https://pptr.dev/|automation
hashcat|Hashcat|https://hashcat.net/hashcat/|password
john|John the Ripper|https://www.openwall.com/john/|password
hydra|Hydra|https://github.com/vanhauser-thc/thc-hydra|password
medusa|Medusa|https://github.com/jmk-foofus/medusa|password
patator|Patator|https://github.com/lanjelot/patator|password
crackstation|CrackStation|https://crackstation.net/|password
hashes|Hashes.com|https://hashes.com/en/decrypt/hash|password
searchsploit|SearchSploit|https://www.exploit-db.com/searchsploit|vuln
msf|Metasploit|https://www.metasploit.com/|vuln
cve-search|CVE-Search|https://github.com/cve-search/cve-search|vuln
osv|OSV|https://osv.dev/|vuln
deps|OWASP Dependency-Check|https://owasp.org/www-project-dependency-check/|vuln
trivy|Trivy|https://trivy.dev/|vuln
grype|Grype|https://github.com/anchore/grype|vuln
semgrep|Semgrep|https://semgrep.dev/|code
trufflehog|TruffleHog|https://github.com/trufflesecurity/trufflehog|code
gitleaks|Gitleaks|https://github.com/gitleaks/gitleaks|code
detect-secrets|detect-secrets|https://github.com/Yelp/detect-secrets|code
gitrob|Gitrob|https://github.com/michenriksen/gitrob|code
gitxray|GitXray|https://github.com/kulkansecurity/gitxray|code
maltego|Maltego|https://www.maltego.com/|graph
spiderfoot|SpiderFoot|https://www.spiderfoot.net/|graph
recon-ng|Recon-ng|https://github.com/lanmaster53/recon-ng|framework
osint-framework|OSINT Framework|https://osintframework.com/|framework
intelligencex|Intelligence X|https://intelx.io/|framework
torbot|TorBot|https://github.com/DedSecInside/TorBot|tor
onionsearch|OnionSearch|https://github.com/megadose/OnionSearch|tor
ahmia|Ahmia|https://ahmia.fi/|tor
tor2web|Tor2Web|https://www.tor2web.org/|tor
archivebox|ArchiveBox|https://archivebox.io/|archive
wayback|Wayback Machine|https://web.archive.org/|archive
archive-today|archive.today|https://archive.ph/|archive
commoncrawl|Common Crawl|https://commoncrawl.org/|archive
"""
)

# slug|name|url with {q}/{d}|kind
DATA_SOURCES = _rows(
    """
opencorporates|OpenCorporates|https://opencorporates.com/companies?q={q}|company
companieshouse|UK Companies House|https://find-and-update.company-information.service.gov.uk/search?q={q}|company
sec-edgar|SEC EDGAR|https://www.sec.gov/cgi-bin/browse-edgar?company={q}&action=getcompany|company
gleif|GLEIF|https://search.gleif.org/#/search/{q}|company
registrar-cz|Czech registry|https://or.justice.cz/ias/ui/rejstrik-$firma?nazev={q}|company
handelsregister|German Handelsregister|https://www.handelsregister.de/rp_web/search.do?unternehmen={q}|company
infogreffe|France Infogreffe|https://www.infogreffe.fr/recherche-societe|company
registroimprese|Italy Registro Imprese|https://www.registroimprese.it/|company
cnpj|Brazil CNPJ|https://cnpj.biz/{q}|company
abn|Australia ABN|https://abr.business.gov.au/Search/ResultsActive?SearchText={q}|company
nzbn|New Zealand NZBN|https://app.companiesoffice.govt.nz/companies/app/ui/pages/companies/search?q={q}|company
cra|Canada CRA business|https://www.canada.ca/en/revenue-agency/services/tax/businesses/topics/business-number.html|company
duns|Dun & Bradstreet|https://www.dnb.com/business-directory.html|company
lei|LEI search|https://www.lei-lookup.com/record/{q}|company
aleph|OCCRP Aleph|https://aleph.occrp.org/search?q={q}|investigation
opensanctions|OpenSanctions|https://www.opensanctions.org/search/?q={q}|sanctions
ofac|US OFAC sanctions|https://sanctionssearch.ofac.treas.gov/|sanctions
eu-sanctions|EU sanctions map|https://www.sanctionsmap.eu/|sanctions
un-sanctions|UN Security Council list|https://www.un.org/securitycouncil/content/un-sc-consolidated-list|sanctions
uk-sanctions|UK sanctions list|https://www.gov.uk/government/publications/the-uk-sanctions-list|sanctions
worldbank-debarred|World Bank debarred|https://www.worldbank.org/en/projects-operations/procurement/debarred-firms|sanctions
icij-offshore|ICIJ Offshore Leaks|https://offshoreleaks.icij.org/search?q={q}|leak
icij-datasets|ICIJ datasets|https://offshoreleaks.icij.org/pages/database|leak
openownership|OpenOwnership|https://register.openownership.org/search?q={q}|company
landregistry|UK Land Registry|https://search-property-information.service.gov.uk/search/search-by-address|property
zillow|Zillow|https://www.zillow.com/homes/{q}_rb/|property
realtor|Realtor.com|https://www.realtor.com/realestateandhomes-search/{q}|property
rightmove|Rightmove|https://www.rightmove.co.uk/property-for-sale/find.html?searchLocation={q}|property
idealista|Idealista|https://www.idealista.com/venta-viviendas/{q}/|property
fincaraiz|Fincaraiz|https://www.fincaraiz.com.co/|property
county-assessor|US county assessor (search)|https://www.google.com/search?q=county+assessor+{q}|property
us-courts|US courts PACER|https://pacer.uscourts.gov/|legal
courtlistener|CourtListener|https://www.courtlistener.com/?q={q}|legal
canlii|CanLII|https://www.canlii.org/en/#search/text={q}|legal
bailii|BAILII|https://www.bailii.org/cgi-bin/lucy_search_1.cgi?query={q}|legal
eur-lex|EUR-Lex|https://eur-lex.europa.eu/search.html?text={q}|legal
caselaw|Caselaw Access|https://case.law/search/#/cases?q={q}|legal
uspto|USPTO|https://ppubs.uspto.gov/pubwebapp/|ip
uspto-tsdr|USPTO TSDR|https://tsdr.uspto.gov/|ip
epo|European Patent Office|https://worldwide.espacenet.com/patent/search?q={q}|ip
wipo|WIPO|https://patentscope.wipo.int/search/en/search.jsf|ip
google-patents|Google Patents|https://patents.google.com/?q={q}|ip
lens|Lens.org|https://www.lens.org/|ip
tmdn|TMview|https://www.tmdn.org/tmview/|ip
copyright|US Copyright Office|https://cocatalog.loc.gov/cgi-bin/Pwebrecon.cgi?DB=local&CMD=all%20words%20search&SA={q}|ip
loc|Library of Congress|https://www.loc.gov/search/?q={q}|library
worldcat|WorldCat|https://search.worldcat.org/search?q={q}|library
openlibrary|Open Library|https://openlibrary.org/search?q={q}|library
archive-org|Internet Archive|https://archive.org/search?query={q}|library
hathitrust|HathiTrust|https://babel.hathitrust.org/cgi/ls?q1={q}|library
google-books|Google Books|https://www.google.com/search?tbm=bks&q={q}|library
pubmed|PubMed|https://pubmed.ncbi.nlm.nih.gov/?term={q}|science
europepmc|Europe PMC|https://europepmc.org/search?query={q}|science
arxiv|arXiv|https://arxiv.org/abs/{q}|science
ssrn|SSRN|https://papers.ssrn.com/sol3/results.cfm?txtKey_Words={q}|science
researchgate|ResearchGate|https://www.researchgate.net/search?q={q}|science
semanticscholar|Semantic Scholar|https://www.semanticscholar.org/search?q={q}|science
crossref|Crossref|https://search.crossref.org/?q={q}|science
openalex|OpenAlex|https://openalex.org/works?search={q}|science
clinicaltrials|ClinicalTrials.gov|https://clinicaltrials.gov/search?term={q}|science
who-ictrp|WHO ICTRP|https://trialsearch.who.int/|science
ncbi|NCBI|https://www.ncbi.nlm.nih.gov/search/all/?term={q}|science
ebi|EBI|https://www.ebi.ac.uk/ebisearch/search.ebi?db=allebi&query={q}|science
dblp|dblp|https://dblp.org/search?q={q}|science
scholar|Google Scholar|https://scholar.google.com/scholar?q={q}|science
github|GitHub|https://github.com/search?q={q}&type=repositories|code
gitlab|GitLab|https://gitlab.com/search?search={q}|code
grep-app|grep.app|https://grep.app/search?q={q}|code
sourcegraph|Sourcegraph|https://sourcegraph.com/search?q={q}|code
searchcode|Searchcode|https://searchcode.com/?q={q}|code
publicwww|PublicWWW|https://publicwww.com/websites/{q}/|code
libraries-io|Libraries.io|https://libraries.io/search?q={q}|code
deps-dev|deps.dev|https://deps.dev/search?q={q}|code
npm|npm|https://www.npmjs.com/search?q={q}|code
pypi|PyPI|https://pypi.org/search/?q={q}|code
crates|Crates.io|https://crates.io/search?q={q}|code
maven|Maven Central|https://search.maven.org/search?q={q}|code
nuget|NuGet|https://www.nuget.org/packages?q={q}|code
packagist|Packagist|https://packagist.org/search/?q={q}|code
rubygems|RubyGems|https://rubygems.org/search?query={q}|code
dockerhub|Docker Hub|https://hub.docker.com/search?q={q}|code
ghcr|GitHub Container Registry|https://github.com/orgs/community/packages|code
quay|Quay|https://quay.io/search?q={q}|code
gitee|Gitee|https://search.gitee.com/?q={q}|code
bitbucket|Bitbucket|https://bitbucket.org/repo/all?name={q}|code
codeberg|Codeberg|https://codeberg.org/explore/repos?q={q}|code
huggingface|Hugging Face|https://huggingface.co/models?search={q}|ai
kaggle|Kaggle datasets|https://www.kaggle.com/search?q={q}|ai
openml|OpenML|https://www.openml.org/search?q={q}&type=data|ai
paperswithcode|Papers with Code|https://paperswithcode.com/search?q={q}|ai
arxiv-ai|arXiv AI|https://arxiv.org/list/cs.AI/recent|ai
wikidata|Wikidata|https://www.wikidata.org/w/index.php?search={q}|wiki
wikipedia|Wikipedia|https://en.wikipedia.org/w/index.php?search={q}|wiki
dbpedia|DBpedia|https://www.dbpedia.org/|wiki
commons|Wikimedia Commons|https://commons.wikimedia.org/w/index.php?search={q}|wiki
mediawiki|MediaWiki API|https://www.mediawiki.org/wiki/API:Main_page|wiki
osm|OpenStreetMap|https://www.openstreetmap.org/search?query={q}|geo
nominatim|Nominatim|https://nominatim.openstreetmap.org/search?q={q}|geo
overpass|Overpass Turbo|https://overpass-turbo.eu/|geo
geonames|GeoNames|https://www.geonames.org/search.html?q={q}|geo
usgs|USGS|https://www.usgs.gov/search?keywords={q}|geo
nasa|NASA|https://images.nasa.gov/search?q={q}|geo
sentinel|Copernicus Browser|https://browser.dataspace.copernicus.eu/|geo
landsat|Landsat|https://earthexplorer.usgs.gov/|geo
google-earth|Google Earth|https://earth.google.com/web/|geo
wikimapia|Wikimapia|http://wikimapia.org/search/?q={q}|geo
what3words|what3words|https://what3words.com/|geo
suncalc|SunCalc|https://www.suncalc.org/|geo
timeanddate|timeanddate|https://www.timeanddate.com/worldclock/|geo
flightradar|Flightradar24|https://www.flightradar24.com/|transport
marinetraffic|MarineTraffic|https://www.marinetraffic.com/|transport
vesselfinder|VesselFinder|https://www.vesselfinder.com/|transport
opensky|OpenSky Network|https://opensky-network.org/|transport
adsbexchange|ADS-B Exchange|https://globe.adsbexchange.com/|transport
flightaware|FlightAware|https://www.flightaware.com/|transport
railway|OpenRailwayMap|https://www.openrailwaymap.org/|transport
transitland|Transitland|https://www.transit.land/|transport
gtfs|TransitFeeds|https://transitfeeds.com/|transport
wikidata-transport|Wikidata transport|https://query.wikidata.org/|transport
who|WHO|https://www.who.int/|health
cdc|CDC|https://www.cdc.gov/search/?query={q}|health
ecdc|ECDC|https://www.ecdc.europa.eu/en|health
nih|NIH|https://search.nih.gov/search?affiliate=nih&query={q}|health
fda|FDA|https://www.accessdata.fda.gov/scripts/cder/daf/|health
ema|EMA|https://www.ema.europa.eu/en/medicines|health
pubchem|PubChem|https://pubchem.ncbi.nlm.nih.gov/#query={q}|health
chemspider|ChemSpider|https://www.chemspider.com/Search.aspx?q={q}|health
drugbank|DrugBank|https://go.drugbank.com/unearth/q?searcher=drugs&query={q}|health
rxnorm|RxNorm|https://mor.nlm.nih.gov/RxNav/search?searchBy=String&searchTerm={q}|health
snomed|SNOMED|https://browser.ihtsdotools.org/|health
icd|ICD|https://icd.who.int/browse11/l-m/en|health
gaia|Gaia DR3|https://gea.esac.esa.int/archive/|space
simbad|SIMBAD|https://simbad.u-strasbg.fr/simbad/|space
horizons|JPL Horizons|https://ssd.jpl.nasa.gov/horizons/|space
space-track|Space-Track|https://www.space-track.org/|space
celestrak|CelesTrak|https://celestrak.org/|space
heavens-above|Heavens-Above|https://heavens-above.com/|space
"""
)

# slug|tag|description
EXIF_TAGS = _rows(
    """
make|Make|ยี่ห้อกล้อง
model|Model|รุ่นกล้อง
serial|SerialNumber|หมายเลขเครื่อง
lens|LensModel|รุ่นเลนส์
lensserial|LensSerialNumber|หมายเลขเลนส์
software|Software|ซอฟต์แวร์ที่แก้ไฟล์
firmware|FirmwareVersion|เฟิร์มแวร์
artist|Artist|ผู้สร้างไฟล์
copyright|Copyright|ลิขสิทธิ์
owner|OwnerName|เจ้าของกล้อง
datetime|DateTimeOriginal|เวลาที่ถ่าย
createdate|CreateDate|เวลาสร้างไฟล์
modifydate|ModifyDate|เวลาแก้ไข
offset|OffsetTime|เขตเวลา
gpslat|GPSLatitude|ละติจูด
gpslon|GPSLongitude|ลองจิจูด
gpsalt|GPSAltitude|ความสูง
gpsspeed|GPSSpeed|ความเร็ว
gpsimgdir|GPSImgDirection|ทิศทางกล้อง
gpstime|GPSTimeStamp|เวลา GPS
gpsdate|GPSDateStamp|วันที่ GPS
gpsprocessing|GPSProcessingMethod|วิธีหาตำแหน่ง
exposure|ExposureTime|ความเร็วชัตเตอร์
fnumber|FNumber|ค่า f
iso|ISO|ความไวแสง
focal|FocalLength|ทางยาวโฟกัส
focal35|FocalLengthIn35mmFormat|เทียบฟูลเฟรม
flash|Flash|แฟลช
metering|MeteringMode|โหมดวัดแสง
whitebalance|WhiteBalance|ไวท์บาลานซ์
orientation|Orientation|การหมุนภาพ
resolution|XResolution/YResolution|ความละเอียด
unit|ResolutionUnit|หน่วยความละเอียด
colorSpace|ColorSpace|color space
profile|ProfileDescription|ICC profile
interop|InteropIndex|interop
thumbnail|ThumbnailImage|ภาพย่อ
maker|MakerNote|ข้อมูลเฉพาะผู้ผลิต
usercomment|UserComment|คอมเมนต์ผู้ใช้
imageDescription|ImageDescription|คำอธิบายภาพ
xptitle|XPTitle|ชื่อภาพ (Windows)
xpcomment|XPComment|คอมเมนต์ (Windows)
xpauthor|XPAuthor|ผู้แต่ง (Windows)
xpkeywords|XPKeywords|คีย์เวิร์ด (Windows)
xpSubject|XPSubject|หัวเรื่อง (Windows)
hostcomputer|HostComputer|เครื่องที่ประมวลผล
docname|DocumentName|ชื่อเอกสาร
pagecount|PageCount|จำนวนหน้า
pdfauthor|Author|ผู้เขียน PDF
pdftitle|Title|ชื่อเรื่อง PDF
pdfproducer|Producer|โปรแกรมสร้าง PDF
pdfcreator|Creator|โปรแกรมต้นทาง
pdfkeywords|Keywords|คีย์เวิร์ด PDF
pdfcreate|CreationDate|วันสร้าง PDF
pdfmod|ModDate|วันแก้ไข PDF
pdfxmp|XMP|XMP metadata
pdfjs|JavaScript|สคริปต์ใน PDF
pdfattach|EmbeddedFiles|ไฟล์แนบใน PDF
docauthor|Author (doc)|ผู้เขียน Word
doccompany|Company|บริษัท
doclastby|LastModifiedBy|แก้ไขล่าสุดโดย
docrevision|RevisionNumber|เลข revision
doctemplate|Template|เทมเพลตต้นทาง
xlsworksheets|Worksheets|ชื่อชีต
msiproduct|ProductCode|รหัสผลิตภัณฑ์ MSI
msimanufacturer|Manufacturer|ผู้ผลิต MSI
peimports|Imports|DLL ที่อ้างถึง
peexports|Exports|ฟังก์ชันที่ส่งออก
peversion|FileVersion|เวอร์ชันไฟล์
pedebug|PDBPath|พาธ PDB (ที่อยู่ build)
pesigner|Signer|ผู้ลงนาม
apkpackage|Package|ชื่อแพ็กเกจ Android
apkversion|VersionName|เวอร์ชันแอป
apkpermissions|Permissions|สิทธิ์ที่ขอ
apksigner|Signer|ผู้ลงนาม APK
zipcomment|Comment|คอมเมนต์ใน zip
zipentries|Entries|จำนวนไฟล์ใน zip
ziptimes|FileModifyDate|เวลาไฟล์ใน zip
mp4create|CreationTime|เวลาสร้างวิดีโอ
mp4encoder|Encoder|โปรแกรมเข้ารหัส
mp4handler|HandlerDescription|แบรนด์อุปกรณ์
mp3artist|Artist|ศิลปิน
mp3album|Album|อัลบั้ม
mp3title|Title|ชื่อเพลง
mp3encoder|Encoder|ตัวเข้ารหัส
pcapiface|Interface|interface ที่ดัก
pcaphosts|Hosts|โฮสต์ในแพ็กเก็ต
"""
)
