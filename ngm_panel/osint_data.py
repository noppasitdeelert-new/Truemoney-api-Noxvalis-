"""Compact OSINT reference tables (offline, no network, no dependencies)."""

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


# --------------------------------------------------------------- dork engines
DORK_ENGINES = _rows(
    """
google|Google|https://www.google.com/search?q={q}
bing|Bing|https://www.bing.com/search?q={q}
duckduckgo|DuckDuckGo|https://duckduckgo.com/?q={q}
brave|Brave Search|https://search.brave.com/search?q={q}
yandex|Yandex|https://yandex.com/search/?text={q}
startpage|Startpage|https://www.startpage.com/sp/search?query={q}
mojeek|Mojeek|https://www.mojeek.com/search?q={q}
searx|SearXNG (searx.be)|https://searx.be/search?q={q}
ecosia|Ecosia|https://www.ecosia.org/search?q={q}
qwant|Qwant|https://www.qwant.com/?q={q}
yahoo|Yahoo|https://search.yahoo.com/search?p={q}
baidu|Baidu|https://www.baidu.com/s?wd={q}
github|GitHub code search|https://github.com/search?q={q}&type=code
scholar|Google Scholar|https://scholar.google.com/scholar?q={q}
"""
)

# ---------------------------------------------------------------- dork topics
DORK_TOPICS = _rows(
    """
pdf|ไฟล์ PDF|filetype:pdf
doc|ไฟล์ Word|filetype:doc OR filetype:docx
xls|ไฟล์ Excel|filetype:xls OR filetype:xlsx
ppt|ไฟล์ PowerPoint|filetype:ppt OR filetype:pptx
csv|ไฟล์ CSV|filetype:csv
sql|ไฟล์ SQL dump|filetype:sql
db|ไฟล์ฐานข้อมูล|filetype:db OR filetype:sqlite
log|ไฟล์ log|filetype:log
bak|ไฟล์สำรอง|filetype:bak OR filetype:backup
old|ไฟล์เก่า|filetype:old
env|ไฟล์ .env ที่หลุด|filetype:env
json-config|config JSON|filetype:json "password" OR "api_key"
yaml-config|config YAML|filetype:yaml "password" OR "token"
xml-config|config XML|filetype:xml "connectionString"
git-config|Git config ที่เปิดเผย|inurl:.git/config
git-dir|โฟลเดอร์ .git|intitle:"index of" ".git"
svn-dir|โฟลเดอร์ .svn|intitle:"index of" ".svn"
ds-store|macOS .DS_Store|inurl:.DS_Store
directory-listing|รายการไดเรกทอรี|intitle:"index of /"
parent-directory|parent directory|"parent directory" "index of"
backup-zip|ไฟล์ zip สำรอง|filetype:zip "backup"
backup-rar|ไฟล์ rar สำรอง|filetype:rar "backup"
admin-panel|หน้า admin|inurl:admin OR intitle:"admin panel"
login-page|หน้า login|inurl:login OR intitle:"login"
dashboard|dashboard|intitle:"dashboard" inurl:admin
phpinfo|phpinfo|intitle:"phpinfo()" "PHP Version"
server-status|Apache server-status|inurl:server-status
actuator|Spring Actuator|inurl:actuator/env
swagger|Swagger UI|intitle:"Swagger UI"
graphql|GraphQL endpoint|inurl:graphql
api-docs|API docs|inurl:"/api-docs" OR inurl:"/swagger"
jenkins|Jenkins|intitle:"Dashboard [Jenkins]"
grafana|Grafana|intitle:"Grafana"
kibana|Kibana|intitle:"Kibana"
prometheus|Prometheus|intitle:"Prometheus Time Series"
elasticsearch|Elasticsearch|intitle:"Elasticsearch" port:9200
minio|MinIO console|intitle:"MinIO Browser"
kubernetes-dashboard|K8s dashboard|intitle:"Kubernetes Dashboard"
docker-api|Docker API|"Docker-Distribution-Api-Version"
jupyter|Jupyter notebook|intitle:"Jupyter Notebook"
camera|กล้องวงจรปิด|inurl:"view.shtml" OR intitle:"Live View / - AXIS"
webcam|เว็บแคม|inurl:"axis-cgi/mjpg"
printer|เครื่องพิมพ์|intitle:"Printer Status" OR inurl:printer
router|เราเตอร์|intitle:"Router" inurl:login
nas|NAS|intitle:"Synology" OR intitle:"QNAP"
iot|อุปกรณ์ IoT|intitle:"ESP8266" OR intitle:"ESP32"
ftp-anon|FTP anonymous|"ftp://" "anonymous"
rdp|Remote Desktop|"RDP" "port 3389"
vnc|VNC|intitle:"VNC Viewer"
pastebin|Pastebin|site:pastebin.com
paste-other|pastes อื่น|site:paste.ee OR site:rentry.co OR site:ghostbin.com
github-secrets|API key บน GitHub|site:github.com "api_key" OR "secret_key"
gitlab-secrets|API key บน GitLab|site:gitlab.com "api_key"
s3-bucket|S3 bucket|site:s3.amazonaws.com
azure-blob|Azure Blob|site:blob.core.windows.net
gcs-bucket|Google Cloud Storage|site:storage.googleapis.com
firebase|Firebase|site:firebaseio.com
heroku|Heroku app|site:herokuapp.com
vercel|Vercel app|site:vercel.app
netlify|Netlify app|site:netlify.app
email-list|รายการอีเมล|filetype:xls OR filetype:csv "@gmail.com"
password-list|รายการรหัสผ่าน|filetype:txt "password"
id-card|สำเนาบัตรประชาชน|filetype:pdf "บัตรประชาชน"
passport|หนังสือเดินทาง|filetype:pdf "passport"
invoice|ใบแจ้งหนี้|filetype:pdf "invoice"
receipt|ใบเสร็จ|filetype:pdf "receipt"
contract|สัญญา|filetype:pdf "contract"
salary|ข้อมูลเงินเดือน|filetype:xls "salary"
student|ข้อมูลนักเรียน|filetype:xls "student"
phone-list|รายการเบอร์โทร|filetype:csv "phone"
resume|เรซูเม่|filetype:pdf "curriculum vitae"
whois|ข้อมูล whois|intext:"Registrant Organization"
dns-zone|zone transfer|inurl:"dns-zone"
subdomain|subdomain|site:*.example.com -www
sitemap|sitemap|inurl:sitemap.xml
robots|robots.txt|inurl:robots.txt
security-txt|security.txt|inurl:security.txt
wayback|Wayback Machine|site:web.archive.org
shodan|Shodan|site:shodan.io
censys|Censys|site:censys.io
github-user|บัญชี GitHub|site:github.com "{u}"
linkedin|LinkedIn|site:linkedin.com/in "{u}"
facebook|Facebook|site:facebook.com "{u}"
instagram|Instagram|site:instagram.com "{u}"
x-twitter|X/Twitter|site:x.com "{u}"
tiktok|TikTok|site:tiktok.com "@{u}"
youtube|YouTube|site:youtube.com "{u}"
telegram|Telegram|site:t.me "{u}"
discord|Discord|site:discord.com "{u}"
reddit|Reddit|site:reddit.com "{u}"
forum|ฟอรัม|inurl:forum "{u}"
leak|ข้อมูลรั่วไหล|"{u}" "password" filetype:txt
breach|breach mention|"{u}" "breach" OR "leak"
news|ข่าว|"{u}" site:news
"""
)

# ------------------------------------------------------------- generic TLDs
GTLD_TEXT = """
com net org info biz name pro mobi asia tel travel jobs cat coop aero museum post xxx arpa
edu gov mil int io ai app dev page new xyz online site tech store shop blog cloud digital agency
solutions services systems network email news media live life world today space website fun icu
top club vip academy accountant actor airforce apartments army art associates attorney auction
audio band bar bargains beer best bet bid bike bingo bio black blue boutique broker build
builders business cab cafe camera camp capital cards care careers casa cash casino catering center
chat cheap church city claims cleaning click clinic clothing coach codes coffee college community
company computer condos construction consulting contact contractors cooking cool country coupons
courses credit creditcard cricket cruises dance date dating deals degree delivery democrat dental
dentist design diamonds diet direct directory discount doctor dog domains download earth education
energy engineer engineering enterprises equipment estate events exchange expert exposed express
fail faith family fans farm fashion finance financial fish fishing fit fitness flights florist
flowers fm football forsale foundation fund furniture futbol fyi gallery games garden gifts gives
glass global gmbh gold golf graphics gratis green grip group guide guru haus health healthcare
hockey holdings holiday homes horse hospital host hosting house how immo industries ink institute
insure international investments irish jetzt jewelry kaufen kitchen land lawyer lease legal lgbt
limited limo link loan loans lol ltd luxury maison management market marketing mba med medical
memorial men menu moda money monster mortgage movie navy ninja now observer ooo organic partners
parts party pet photo photography photos pics pictures pink pizza place plumbing plus press
productions promo properties property protection pub racing recipes red rehab reisen rent rentals
repair report republican rest restaurant review reviews rip rocks rodeo run sale salon sarl school
schule science shoes shopping show singles ski soccer social software solar space stream studio
style supplies supply support surf surgery tax taxi team technology tennis theater tienda tips
tires tools tours town toys trade training tube university uno vacations ventures vet video villas
vin vision vodka vote voyage watch webcam wedding wiki win wine work works wtf yoga zone
"""

# ------------------------------------------------------------ email providers
EMAIL_TEXT = """
gmail.com googlemail.com yahoo.com yahoo.co.uk ymail.com rocketmail.com outlook.com hotmail.com
live.com msn.com icloud.com me.com mac.com aol.com protonmail.com proton.me pm.me tutanota.com
tuta.io zoho.com zohomail.com gmx.com gmx.net gmx.de mail.com email.com yandex.com yandex.ru
rambler.ru mail.ru inbox.ru list.ru bk.ru internet.ru ukr.net meta.ua seznam.cz centrum.cz
atlas.cz wp.pl o2.pl onet.pl interia.pl op.pl tlen.pl gazeta.pl libero.it virgilio.it tiscali.it
alice.it tin.it fastwebnet.it email.it poste.it aruba.it register.it kpnmail.nl ziggo.nl xs4all.nl
hetnet.nl planet.nl online.nl wanadoo.nl orange.fr wanadoo.fr free.fr laposte.net sfr.fr neuf.fr
bbox.fr numericable.fr web.de t-online.de freenet.de arcor.de posteo.de mailbox.org mail.de
1und1.de hotmail.de live.de outlook.de bluewin.ch sunrise.ch hispeed.ch gmx.at aon.at chello.at
telia.com comhem.se bredband.net spray.se swipnet.se fastmail.com fastmail.fm hushmail.com
runbox.com posteo.net startmail.com countermail.com mailfence.com disroot.org riseup.net
autistici.org inventati.org lavabit.com vfemail.net safe-mail.net elude.in cock.li hey.com
pobox.com migadu.com skiff.com shaw.ca telus.net rogers.com bell.net sympatico.ca videotron.ca
cogeco.ca eastlink.ca bigpond.com optusnet.com.au iinet.net.au internode.on.net tpg.com.au
westnet.com.au aapt.net.au xtra.co.nz orcon.net.nz vodafone.co.nz clear.net.nz globe.com.ph
pldtdsl.net smart.com.ph bayan.net.ph naver.com daum.net hanmail.net nate.com hotmail.co.kr
yahoo.co.kr empas.com korea.com 163.com 126.com yeah.net qq.com foxmail.com sina.com sohu.com
139.com 189.cn aliyun.com tom.com 21cn.com wo.cn 263.net rediffmail.com indiatimes.com sify.com
in.com yahoo.co.in hotmail.co.in bsnl.in airtel.in mailinator.com guerrillamail.com
10minutemail.com temp-mail.org throwawaymail.com yopmail.com sharklasers.com trashmail.com
dispostable.com maildrop.cc getnada.com emailondeck.com mohmal.com tempmail.net fakeinbox.com
mintemail.com spam4.me mytemp.email mailnesia.com dropmail.me inboxkitten.com
"""

# ------------------------------------------------------------------ countries
COUNTRY_ROWS = _rows(
    """
AF|Afghanistan|93|af
AL|Albania|355|al
DZ|Algeria|213|dz
AD|Andorra|376|ad
AO|Angola|244|ao
AR|Argentina|54|ar
AM|Armenia|374|am
AW|Aruba|297|aw
AU|Australia|61|au
AT|Austria|43|at
AZ|Azerbaijan|994|az
BS|Bahamas|1242|bs
BH|Bahrain|973|bh
BD|Bangladesh|880|bd
BB|Barbados|1246|bb
BY|Belarus|375|by
BE|Belgium|32|be
BZ|Belize|501|bz
BJ|Benin|229|bj
BT|Bhutan|975|bt
BO|Bolivia|591|bo
BA|Bosnia and Herzegovina|387|ba
BW|Botswana|267|bw
BR|Brazil|55|br
BN|Brunei|673|bn
BG|Bulgaria|359|bg
BF|Burkina Faso|226|bf
BI|Burundi|257|bi
KH|Cambodia|855|kh
CM|Cameroon|237|cm
CA|Canada|1|ca
CV|Cape Verde|238|cv
KY|Cayman Islands|1345|ky
CF|Central African Republic|236|cf
TD|Chad|235|td
CL|Chile|56|cl
CN|China|86|cn
CO|Colombia|57|co
KM|Comoros|269|km
CG|Congo|242|cg
CD|DR Congo|243|cd
CR|Costa Rica|506|cr
CI|Cote d'Ivoire|225|ci
HR|Croatia|385|hr
CU|Cuba|53|cu
CY|Cyprus|357|cy
CZ|Czechia|420|cz
DK|Denmark|45|dk
DJ|Djibouti|253|dj
DM|Dominica|1767|dm
DO|Dominican Republic|1809|do
EC|Ecuador|593|ec
EG|Egypt|20|eg
SV|El Salvador|503|sv
GQ|Equatorial Guinea|240|gq
ER|Eritrea|291|er
EE|Estonia|372|ee
SZ|Eswatini|268|sz
ET|Ethiopia|251|et
FJ|Fiji|679|fj
FI|Finland|358|fi
FR|France|33|fr
GA|Gabon|241|ga
GM|Gambia|220|gm
GE|Georgia|995|ge
DE|Germany|49|de
GH|Ghana|233|gh
GR|Greece|30|gr
GD|Grenada|1473|gd
GT|Guatemala|502|gt
GN|Guinea|224|gn
GW|Guinea-Bissau|245|gw
GY|Guyana|592|gy
HT|Haiti|509|ht
HN|Honduras|504|hn
HK|Hong Kong|852|hk
HU|Hungary|36|hu
IS|Iceland|354|is
IN|India|91|in
ID|Indonesia|62|id
IR|Iran|98|ir
IQ|Iraq|964|iq
IE|Ireland|353|ie
IL|Israel|972|il
IT|Italy|39|it
JM|Jamaica|1876|jm
JP|Japan|81|jp
JO|Jordan|962|jo
KZ|Kazakhstan|7|kz
KE|Kenya|254|ke
KI|Kiribati|686|ki
KP|North Korea|850|kp
KR|South Korea|82|kr
KW|Kuwait|965|kw
KG|Kyrgyzstan|996|kg
LA|Laos|856|la
LV|Latvia|371|lv
LB|Lebanon|961|lb
LS|Lesotho|266|ls
LR|Liberia|231|lr
LY|Libya|218|ly
LI|Liechtenstein|423|li
LT|Lithuania|370|lt
LU|Luxembourg|352|lu
MO|Macau|853|mo
MG|Madagascar|261|mg
MW|Malawi|265|mw
MY|Malaysia|60|my
MV|Maldives|960|mv
ML|Mali|223|ml
MT|Malta|356|mt
MH|Marshall Islands|692|mh
MR|Mauritania|222|mr
MU|Mauritius|230|mu
MX|Mexico|52|mx
FM|Micronesia|691|fm
MD|Moldova|373|md
MC|Monaco|377|mc
MN|Mongolia|976|mn
ME|Montenegro|382|me
MA|Morocco|212|ma
MZ|Mozambique|258|mz
MM|Myanmar|95|mm
NA|Namibia|264|na
NR|Nauru|674|nr
NP|Nepal|977|np
NL|Netherlands|31|nl
NZ|New Zealand|64|nz
NI|Nicaragua|505|ni
NE|Niger|227|ne
NG|Nigeria|234|ng
MK|North Macedonia|389|mk
NO|Norway|47|no
OM|Oman|968|om
PK|Pakistan|92|pk
PW|Palau|680|pw
PS|Palestine|970|ps
PA|Panama|507|pa
PG|Papua New Guinea|675|pg
PY|Paraguay|595|py
PE|Peru|51|pe
PH|Philippines|63|ph
PL|Poland|48|pl
PT|Portugal|351|pt
PR|Puerto Rico|1787|pr
QA|Qatar|974|qa
RO|Romania|40|ro
RU|Russia|7|ru
RW|Rwanda|250|rw
KN|Saint Kitts and Nevis|1869|kn
LC|Saint Lucia|1758|lc
VC|Saint Vincent and the Grenadines|1784|vc
WS|Samoa|685|ws
SM|San Marino|378|sm
ST|Sao Tome and Principe|239|st
SA|Saudi Arabia|966|sa
SN|Senegal|221|sn
RS|Serbia|381|rs
SC|Seychelles|248|sc
SL|Sierra Leone|232|sl
SG|Singapore|65|sg
SK|Slovakia|421|sk
SI|Slovenia|386|si
SB|Solomon Islands|677|sb
SO|Somalia|252|so
ZA|South Africa|27|za
SS|South Sudan|211|ss
ES|Spain|34|es
LK|Sri Lanka|94|lk
SD|Sudan|249|sd
SR|Suriname|597|sr
SE|Sweden|46|se
CH|Switzerland|41|ch
SY|Syria|963|sy
TW|Taiwan|886|tw
TJ|Tajikistan|992|tj
TZ|Tanzania|255|tz
TH|Thailand|66|th
TL|Timor-Leste|670|tl
TG|Togo|228|tg
TO|Tonga|676|to
TT|Trinidad and Tobago|1868|tt
TN|Tunisia|216|tn
TR|Turkey|90|tr
TM|Turkmenistan|993|tm
TV|Tuvalu|688|tv
UG|Uganda|256|ug
UA|Ukraine|380|ua
AE|United Arab Emirates|971|ae
GB|United Kingdom|44|uk
US|United States|1|us
UY|Uruguay|598|uy
UZ|Uzbekistan|998|uz
VU|Vanuatu|678|vu
VE|Venezuela|58|ve
VN|Vietnam|84|vn
YE|Yemen|967|ye
ZM|Zambia|260|zm
ZW|Zimbabwe|263|zw
"""
)

# ------------------------------------------------------------- metadata fields
META_FORMATS = _rows(
    """
jpg|JPEG image|EXIF, GPS, MakerNotes, ICC profile, XMP, thumbnail
jpeg|JPEG image|EXIF, GPS, MakerNotes, ICC profile, XMP, thumbnail
tif|TIFF image|EXIF, GPS, ICC profile, page count
tiff|TIFF image|EXIF, GPS, ICC profile, page count
png|PNG image|tEXt, zTXt, iTXt, pHYs, tIME, ICC profile
gif|GIF image|comment, frame count, palette
webp|WebP image|EXIF, XMP, ICC profile, animation
heic|HEIC image|EXIF, GPS, XMP, depth map
bmp|Bitmap image|header, palette, DPI
svg|SVG vector|title, desc, metadata, editor
ico|Icon|dimensions, color depth
psd|Photoshop|layers, ICC profile, XMP, history
ai|Illustrator|XMP, creator, document info
eps|EPS|BoundingBox, creator, TIFF preview
pdf|PDF document|Author, Producer, Creator, CreationDate, XMP, JavaScript
doc|Word document|Author, Last saved by, Company, Revision, template
docx|Word (OOXML)|core.xml author, app.xml company, custom.xml
xls|Excel|Author, Company, last saved, worksheets
xlsx|Excel (OOXML)|core.xml author, app.xml, shared strings
ppt|PowerPoint|Author, Company, slides
pptx|PowerPoint (OOXML)|core.xml author, app.xml, notes
odt|OpenDocument text|meta.xml author, generator, date
ods|OpenDocument sheet|meta.xml author, generator
odp|OpenDocument slides|meta.xml author, generator
rtf|Rich Text|author, company, revision
txt|Plain text|encoding, BOM, line endings
csv|CSV|delimiter, encoding, columns
json|JSON|keys, timestamps, identifiers
xml|XML|namespaces, schema, comments
html|HTML|title, meta tags, generator, scripts
htm|HTML|title, meta tags, generator
md|Markdown|front matter, author, title
yaml|YAML|anchors, comments, keys
yml|YAML|anchors, comments, keys
ini|INI|sections, keys
toml|TOML|tables, keys
conf|Config|keys, secrets
cfg|Config|keys, secrets
log|Log file|timestamps, hostnames, IPs, usernames
sql|SQL dump|schema, INSERT rows, credentials
sqlite|SQLite database|tables, schema, freelist, WAL
db|Database|header, tables, records
mdb|Access database|tables, queries
zip|ZIP archive|file list, timestamps, comment, encryption
rar|RAR archive|file list, timestamps, comment
7z|7-Zip archive|file list, timestamps, encryption
tar|TAR archive|file list, owner, timestamps
gz|Gzip|original name, timestamp
bz2|Bzip2|original size
xz|XZ|original size
iso|ISO image|volume label, publisher, creation date
dmg|DMG image|volume name, filesystem
mp3|MP3 audio|ID3 artist/album/title, encoder, duration
flac|FLAC audio|Vorbis comments, duration, sample rate
wav|WAV audio|RIFF info, duration, sample rate
m4a|M4A audio|iTunes metadata, artwork
ogg|Ogg audio|Vorbis comments
opus|Opus audio|tags, duration
mp4|MP4 video|creation time, GPS, encoder, handler
m4v|M4V video|creation time, encoder
mov|QuickTime video|creation time, GPS, encoder
mkv|Matroska video|title, muxing app, tags, chapters
avi|AVI video|RIFF info, codec, duration
webm|WebM video|muxing app, tags
wmv|WMV video|ASF metadata, author
flv|Flash video|encoder, duration
ts|MPEG transport|programs, PIDs
srt|Subtitle|timestamps, encoding
exe|Windows executable|PE header, compiler, imports, PDB path, version info
dll|Windows library|PE header, imports, version info
sys|Windows driver|PE header, signature
msi|Windows installer|properties, author, product code
apk|Android package|manifest package, version, permissions, signer
jar|Java archive|manifest, main class, signer
class|Java class|compiler version, source file
py|Python source|encoding, shebang, docstring
pyc|Python bytecode|magic, source path, timestamp
sh|Shell script|shebang, author comment
ps1|PowerShell script|comment block, author
bat|Batch file|title, author
pem|PEM certificate|subject, issuer, validity, SAN
crt|Certificate|subject, issuer, validity, SAN
cer|Certificate|subject, issuer, validity
key|Private key|algorithm, size (ไม่พิมพ์เนื้อกุญแจ)
p12|PKCS#12|alias, issuer, validity
pfx|PKCS#12|alias, issuer, validity
jks|Java keystore|aliases, certificates
pcap|Packet capture|interfaces, hosts, protocols, timestamps
pcapng|Packet capture NG|interfaces, comments, hosts
har|HTTP archive|URLs, timestamps, headers, cookies
eml|Email message|From, To, Subject, Message-ID, Received, attachments
msg|Outlook message|sender, recipients, headers
mbox|Mailbox|messages, senders
ics|Calendar|organizer, attendees, UID
vcf|vCard|name, phone, email, organization
torrent|BitTorrent|announce, comment, created by, file list
ttf|TrueType font|name table, designer, license
otf|OpenType font|name table, designer, license
woff|Web font|name table, license
woff2|Web font|name table, license
epub|EPUB book|title, author, publisher, identifier
mobi|Mobi book|title, author, publisher
djvu|DjVu document|title, author, pages
"""
)

# -------------------------------------------------------------- user agents
UA_BROWSERS = _rows(
    """
chrome|Chrome desktop|Mozilla/5.0 ({platform}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
firefox|Firefox desktop|Mozilla/5.0 ({platform}; rv:133.0) Gecko/20100101 Firefox/133.0
edge|Edge desktop|Mozilla/5.0 ({platform}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0
safari|Safari desktop|Mozilla/5.0 ({mac}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15
opera|Opera desktop|Mozilla/5.0 ({platform}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 OPR/115.0.0.0
samsung|Samsung Internet|Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36
chrome-mobile|Chrome mobile|Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36
safari-ios|Safari iOS|Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1
firefox-mobile|Firefox mobile|Mozilla/5.0 (Android 14; Mobile; rv:133.0) Gecko/133.0 Firefox/133.0
curl|curl|curl/8.11.0
python-requests|python-requests|python-requests/2.32.3
bot-google|Googlebot|Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)
"""
)

UA_PLATFORMS = _rows(
    """
win10|Windows 10|Windows NT 10.0; Win64; x64
win11|Windows 11|Windows NT 10.0; Win64; x64; rv:120.0
win7|Windows 7|Windows NT 6.1; Win64; x64
macos|macOS|Macintosh; Intel Mac OS X 10_15_7
macos-arm|macOS Apple Silicon|Macintosh; ARM Mac OS X 14_0
linux|Linux|X11; Linux x86_64
ubuntu|Ubuntu|X11; Ubuntu; Linux x86_64
android|Android|Linux; Android 14; Pixel 8
ios|iOS|iPhone; CPU iPhone OS 18_1 like Mac OS X
ipad|iPadOS|iPad; CPU OS 18_1 like Mac OS X
chromeos|ChromeOS|X11; CrOS x86_64 15633.0.0
"""
)

# ------------------------------------------------------- passive subdomain src
SUBDOMAIN_SOURCES = _rows(
    """
crtsh|crt.sh certificate transparency|https://crt.sh/?q=%25.{d}
otx|AlienVault OTX|https://otx.alienvault.com/api/v1/indicators/domain/{d}/passive_dns
urlscan|urlscan.io|https://urlscan.io/domain/{d}
hackertarget|HackerTarget hostsearch|https://api.hackertarget.com/hostsearch/?q={d}
rapiddns|RapidDNS|https://rapiddns.io/subdomain/{d}
dnsdumpster|DNSdumpster|https://dnsdumpster.com/static/map/{d}.png
threatcrowd|ThreatCrowd|https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={d}
virustotal|VirusTotal|https://www.virustotal.com/gui/domain/{d}/relations
securitytrails|SecurityTrails|https://securitytrails.com/domain/{d}/dns
shodan|Shodan|https://www.shodan.io/search?query=hostname%3A{d}
censys|Censys|https://search.censys.io/search?resource=hosts&q={d}
netlas|Netlas|https://app.netlas.io/host/{d}
fofa|FOFA|https://en.fofa.info/result?qbase64={d}
zoomeye|ZoomEye|https://www.zoomeye.org/searchResult?q={d}
binaryedge|BinaryEdge|https://app.binaryedge.io/services/query?query={d}
fullhunt|FullHunt|https://fullhunt.io/domain/{d}
leakix|LeakIX|https://leakix.net/search?scope=leak&q={d}
intelx|Intelligence X|https://intelx.io/?s={d}
hunterhow|Hunter.how|https://hunter.how/list?searchValue={d}
subdomainfinder|SubdomainFinder|https://subdomainfinder.c99.nl/scans/{d}
dnslytics|DNSlytics|https://dnslytics.com/domain/{d}
robtex|Robtex|https://www.robtex.com/dns-lookup/{d}
viewdns|ViewDNS|https://viewdns.info/iphistory/?domain={d}
whoisxml|WhoisXML API|https://reverse-whois.whoisxmlapi.com/
nmmapper|Nmmapper|https://www.nmmapper.com/sys/tools/subdomainfinder/{d}
dnsrecon|dnsrecon (local)|https://github.com/darkoperator/dnsrecon
amass|OWASP Amass (local)|https://github.com/owasp-amass/amass
subfinder|subfinder (local)|https://github.com/projectdiscovery/subfinder
assetfinder|assetfinder (local)|https://github.com/tomnomnom/assetfinder
findomain|findomain (local)|https://github.com/Findomain/Findomain
chaos|Chaos dataset|https://chaos.projectdiscovery.io/
github-search|GitHub code search|https://github.com/search?q=%22{d}%22&type=code
google|Google|https://www.google.com/search?q=site%3A*.{d}
bing|Bing|https://www.bing.com/search?q=site%3A*.{d}
wayback|Wayback CDX|http://web.archive.org/cdx/search/cdx?url=*.{d}&output=json
commoncrawl|Common Crawl index|https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.{d}&output=json
bufferover|BufferOver|https://tls.bufferover.run/dns?q=.{d}
sonar|Project Sonar|https://opendata.rapid7.com/
certspotter|Cert Spotter|https://api.certspotter.com/v1/issuances?domain={d}&include_subdomains=true
sslsan|SSL SAN search|https://crt.sh/?q={d}&match=any
"""
)

# ------------------------------------------------------------ breach/intel
BREACH_SOURCES = _rows(
    """
hibp|Have I Been Pwned|https://haveibeenpwned.com/account/{q}
hibp-passwords|Pwned Passwords|https://api.pwnedpasswords.com/range/{prefix}
dehashed|DeHashed|https://dehashed.com/search?query={q}
leakcheck|LeakCheck|https://leakcheck.io/
intelx|Intelligence X|https://intelx.io/?s={q}
snusbase|Snusbase|https://snusbase.com/
leakpeek|LeakPeek|https://leakpeek.com/
weleakinfo|WeLeakInfo|https://weleakinfo.io/
breachdirectory|BreachDirectory|https://breachdirectory.org/
leakradar|LeakRadar|https://leakradar.io/
hudsonrock|Hudson Rock|https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={q}
scamsearch|ScamSearch|https://scamsearch.io/search_report?searchoption=all&search={q}
epieos|Epieos|https://epieos.com/?q={q}
ghunt|GHunt (local)|https://github.com/mxrch/GHunt
holehe|holehe (local)|https://github.com/megadose/holehe
h8mail|h8mail (local)|https://github.com/khast3x/h8mail
theharvester|theHarvester (local)|https://github.com/laramies/theHarvester
sherlock|Sherlock (local)|https://github.com/sherlock-project/sherlock
maigret|Maigret (local)|https://github.com/soxoj/maigret
social-analyzer|Social Analyzer (local)|https://github.com/qeeqbox/social-analyzer
whatsmyname|WhatsMyName|https://whatsmyname.app/
namechk|Namechk|https://namechk.com/
usersearch|UserSearch|https://usersearch.org/
instantusername|Instant Username|https://instantusername.com/
checkusernames|CheckUsernames|https://checkusernames.com/
knowem|Knowem|https://knowem.com/
spytox|Spytox|https://www.spytox.com/
thatsthem|ThatsThem|https://thatsthem.com/
truepeoplesearch|TruePeopleSearch|https://www.truepeoplesearch.com/
fastpeoplesearch|FastPeopleSearch|https://www.fastpeoplesearch.com/
whitepages|Whitepages|https://www.whitepages.com/
radaris|Radaris|https://radaris.com/
spokeo|Spokeo|https://www.spokeo.com/
beenverified|BeenVerified|https://www.beenverified.com/
peoplefinders|PeopleFinders|https://www.peoplefinders.com/
intelius|Intelius|https://www.intelius.com/
pipl|Pipl|https://pipl.com/
zoominfo|ZoomInfo|https://www.zoominfo.com/
rocketreach|RocketReach|https://rocketreach.co/
hunter|Hunter.io|https://hunter.io/search/{domain}
clearbit|Clearbit|https://clearbit.com/
apollo|Apollo.io|https://www.apollo.io/
snov|Snov.io|https://snov.io/email-finder
anymailfinder|Anymail Finder|https://anymailfinder.com/
voilanorbert|VoilaNorbert|https://www.voilanorbert.com/
emailrep|EmailRep|https://emailrep.io/{q}
emailhippo|Email Hippo|https://tools.emailhippo.com/
mailtester|MailTester|https://www.mailtester.com/
verifyemail|VerifyEmailAddress|https://www.verifyemailaddress.org/
trumail|TruMail|https://trumail.io/
burnermail|Burner Mail|https://burnermail.io/
"""
)

# --------------------------------------------------------------- hashing
HASH_ALGORITHMS = [
    "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
    "sha3_224", "sha3_256", "sha3_384", "sha3_512",
    "blake2b", "blake2s", "shake_128", "shake_256",
    "ripemd160",
]

# --------------------------------------------------------------- encodings
ENCODINGS = [
    ("base64", "Base64 มาตรฐาน"),
    ("base64url", "Base64 แบบ URL-safe"),
    ("base32", "Base32"),
    ("hex", "Hexadecimal"),
    ("url", "percent-encoding"),
    ("rot13", "ROT13"),
    ("html", "HTML entities"),
    ("binary", "เลขฐานสอง"),
    ("unicode-escape", "Python unicode escape"),
]
