"""Username platform directory for ``osint.username-*`` commands.

Every line is ``slug|display name|profile URL template``. ``{u}`` is replaced
with the username. These are passive link generators plus optional, scope-gated
existence checks — nothing is submitted to any central service.
"""

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


USERNAME_PLATFORMS = _rows(
    """
github|GitHub|https://github.com/{u}
gitlab|GitLab|https://gitlab.com/{u}
bitbucket|Bitbucket|https://bitbucket.org/{u}
codeberg|Codeberg|https://codeberg.org/{u}
sourceforge|SourceForge|https://sourceforge.net/u/{u}/profile
gitea|Gitea (demo)|https://try.gitea.io/{u}
huggingface|Hugging Face|https://huggingface.co/{u}
kaggle|Kaggle|https://www.kaggle.com/{u}
stackoverflow|Stack Overflow|https://stackoverflow.com/users/{u}
stackexchange|Stack Exchange|https://stackexchange.com/users/{u}
devto|DEV Community|https://dev.to/{u}
hashnode|Hashnode|https://hashnode.com/@{u}
medium|Medium|https://medium.com/@{u}
substack|Substack|https://{u}.substack.com
reddit|Reddit|https://www.reddit.com/user/{u}
hackernews|Hacker News|https://news.ycombinator.com/user?id={u}
lobsters|Lobsters|https://lobste.rs/~{u}
producthunt|Product Hunt|https://www.producthunt.com/@{u}
indiehackers|Indie Hackers|https://www.indiehackers.com/{u}
codepen|CodePen|https://codepen.io/{u}
jsfiddle|JSFiddle|https://jsfiddle.net/user/{u}
replit|Replit|https://replit.com/@{u}
glitch|Glitch|https://glitch.com/@{u}
npm|npm|https://www.npmjs.com/~{u}
pypi|PyPI|https://pypi.org/user/{u}
rubygems|RubyGems|https://rubygems.org/profiles/{u}
packagist|Packagist|https://packagist.org/users/{u}
dockerhub|Docker Hub|https://hub.docker.com/u/{u}
quay|Quay.io|https://quay.io/user/{u}
launchpad|Launchpad|https://launchpad.net/~{u}
snyk|Snyk|https://snyk.io/user/{u}
bugcrowd|Bugcrowd|https://bugcrowd.com/{u}
hackerone|HackerOne|https://hackerone.com/{u}
intigriti|Intigriti|https://app.intigriti.com/profile/{u}
openbugbounty|Open Bug Bounty|https://www.openbugbounty.org/researchers/{u}
keybase|Keybase|https://keybase.io/{u}
twitter|X / Twitter|https://x.com/{u}
threads|Threads|https://www.threads.net/@{u}
mastodon-social|Mastodon (mastodon.social)|https://mastodon.social/@{u}
mastodon-online|Mastodon (mstdn.social)|https://mstdn.social/@{u}
bluesky|Bluesky|https://bsky.app/profile/{u}.bsky.social
tumblr|Tumblr|https://{u}.tumblr.com
pleroma|Pleroma (pleroma.site)|https://pleroma.site/users/{u}
misskey|Misskey (misskey.io)|https://misskey.io/@{u}
facebook|Facebook|https://www.facebook.com/{u}
instagram|Instagram|https://www.instagram.com/{u}
linkedin|LinkedIn|https://www.linkedin.com/in/{u}
tiktok|TikTok|https://www.tiktok.com/@{u}
youtube|YouTube|https://www.youtube.com/@{u}
vimeo|Vimeo|https://vimeo.com/{u}
dailymotion|Dailymotion|https://www.dailymotion.com/{u}
twitch|Twitch|https://www.twitch.tv/{u}
kick|Kick|https://kick.com/{u}
rumble|Rumble|https://rumble.com/user/{u}
odysee|Odysee|https://odysee.com/@{u}
bitchute|BitChute|https://www.bitchute.com/channel/{u}
snapchat|Snapchat|https://www.snapchat.com/add/{u}
pinterest|Pinterest|https://www.pinterest.com/{u}
flickr|Flickr|https://www.flickr.com/people/{u}
500px|500px|https://500px.com/p/{u}
deviantart|DeviantArt|https://www.deviantart.com/{u}
behance|Behance|https://www.behance.net/{u}
dribbble|Dribbble|https://dribbble.com/{u}
artstation|ArtStation|https://www.artstation.com/{u}
ello|Ello|https://ello.co/{u}
vsco|VSCO|https://vsco.co/{u}
unsplash|Unsplash|https://unsplash.com/@{u}
soundcloud|SoundCloud|https://soundcloud.com/{u}
bandcamp|Bandcamp|https://bandcamp.com/{u}
mixcloud|Mixcloud|https://www.mixcloud.com/{u}
audius|Audius|https://audius.co/{u}
spotify|Spotify|https://open.spotify.com/user/{u}
lastfm|Last.fm|https://www.last.fm/user/{u}
discogs|Discogs|https://www.discogs.com/user/{u}
genius|Genius|https://genius.com/{u}
patreon|Patreon|https://www.patreon.com/{u}
ko-fi|Ko-fi|https://ko-fi.com/{u}
buymeacoffee|Buy Me a Coffee|https://www.buymeacoffee.com/{u}
gumroad|Gumroad|https://{u}.gumroad.com
etsy|Etsy|https://www.etsy.com/shop/{u}
ebay|eBay|https://www.ebay.com/usr/{u}
amazon|Amazon profile|https://www.amazon.com/gp/profile/{u}
mercari|Mercari|https://www.mercari.com/u/{u}
depop|Depop|https://www.depop.com/{u}
poshmark|Poshmark|https://poshmark.com/closet/{u}
vinted|Vinted|https://www.vinted.com/member/{u}
shopify|Shopify community|https://community.shopify.com/u/{u}
gravatar|Gravatar|https://gravatar.com/{u}
aboutme|About.me|https://about.me/{u}
linktree|Linktree|https://linktr.ee/{u}
beacons|Beacons|https://beacons.ai/{u}
carrd|Carrd|https://{u}.carrd.co
bio-link|Bio.link|https://bio.link/{u}
allmylinks|AllMyLinks|https://allmylinks.com/{u}
wordpress|WordPress.com|https://{u}.wordpress.com
blogger|Blogger|https://{u}.blogspot.com
wix|Wix|https://{u}.wixsite.com
weebly|Weebly|https://{u}.weebly.com
ghost|Ghost (demo)|https://{u}.ghost.io
notion|Notion|https://{u}.notion.site
readme|ReadMe|https://readme.io/
devfolio|Devfolio|https://devfolio.co/@{u}
wellfound|Wellfound|https://wellfound.com/u/{u}
angelco|AngelList|https://angel.co/u/{u}
crunchbase|Crunchbase|https://www.crunchbase.com/person/{u}
f6s|F6S|https://www.f6s.com/{u}
github-sponsors|GitHub Sponsors|https://github.com/sponsors/{u}
opencollective|Open Collective|https://opencollective.com/{u}
liberapay|Liberapay|https://liberapay.com/{u}
flattr|Flattr|https://flattr.com/@{u}
discord|Discord|https://discord.com/users/{u}
telegram|Telegram|https://t.me/{u}
signal|Signal|https://signal.me/#p/{u}
whatsapp|WhatsApp|https://wa.me/{u}
line|LINE|https://line.me/ti/p/~{u}
wechat|WeChat|https://weixin.qq.com/
kakaotalk|KakaoTalk|https://open.kakao.com/o/{u}
viber|Viber|https://viber.me/{u}
skype|Skype|https://join.skype.com/invite/{u}
zoom|Zoom|https://zoom.us/u/{u}
slack|Slack community|https://{u}.slack.com
mattermost|Mattermost|https://community.mattermost.com/core/channels/{u}
guilded|Guilded|https://www.guilded.gg/u/{u}
matrix|Matrix|https://matrix.to/#/@{u}:matrix.org
revolt|Revolt|https://revolt.chat/api/{u}
steam|Steam|https://steamcommunity.com/id/{u}
steam-custom|Steam (vanity)|https://steamcommunity.com/id/{u}/myactivity
epicgames|Epic Games|https://www.epicgames.com/account/{u}
xbox|Xbox|https://xboxgamertag.com/search/{u}
playstation|PlayStation|https://psnprofiles.com/{u}
nintendo|Nintendo|https://switchprofiles.com/{u}
roblox|Roblox|https://www.roblox.com/users/profile?username={u}
minecraft|Minecraft|https://namemc.com/profile/{u}
faceit|FACEIT|https://www.faceit.com/en/players/{u}
esl|ESL Play|https://play.eslgaming.com/player/{u}
battlenet|Battle.net|https://www.blizzard.com/
riotgames|Riot Games|https://www.op.gg/summoners/na/{u}
leagueoflegends|League of Legends|https://www.op.gg/summoners/na/{u}
dota2|Dota 2|https://www.dotabuff.com/players/{u}
pubg|PUBG|https://pubg.op.gg/user/{u}
fortnite|Fortnite|https://fortnitetracker.com/profile/all/{u}
apex|Apex Legends|https://apex.tracker.gg/apex/profile/origin/{u}
valorant|VALORANT|https://tracker.gg/valorant/profile/riot/{u}
csgo|Counter-Strike|https://csstats.gg/player/{u}
chesscom|Chess.com|https://www.chess.com/member/{u}
lichess|Lichess|https://lichess.org/@/{u}
fide|FIDE|https://ratings.fide.com/profile/{u}
duolingo|Duolingo|https://www.duolingo.com/profile/{u}
khanacademy|Khan Academy|https://www.khanacademy.org/profile/{u}
coursera|Coursera|https://www.coursera.org/user/{u}
udemy|Udemy|https://www.udemy.com/user/{u}
skillshare|Skillshare|https://www.skillshare.com/profile/{u}
pluralsight|Pluralsight|https://app.pluralsight.com/profile/{u}
edx|edX|https://courses.edx.org/u/{u}
researchgate|ResearchGate|https://www.researchgate.net/profile/{u}
orcid|ORCID|https://orcid.org/{u}
google-scholar|Google Scholar|https://scholar.google.com/citations?user={u}
semanticscholar|Semantic Scholar|https://www.semanticscholar.org/author/{u}
academia|Academia.edu|https://independent.academia.edu/{u}
dblp|dblp|https://dblp.org/pid/{u}
arxiv|arXiv|https://arxiv.org/a/{u}_1
zenodo|Zenodo|https://zenodo.org/communities/{u}
osf|OSF|https://osf.io/{u}/
figshare|Figshare|https://figshare.com/authors/{u}
ssrn|SSRN|https://papers.ssrn.com/sol3/cf_dev/AbsByAuth.cfm?per_id={u}
publons|Publons|https://publons.com/researcher/{u}
loop|Loop|https://loop.frontiersin.org/people/{u}
mendeley|Mendeley|https://www.mendeley.com/profiles/{u}
scopus|Scopus|https://www.scopus.com/authid/detail.uri?authorId={u}
webofscience|Web of Science|https://www.webofscience.com/wos/author/record/{u}
pubmed|PubMed|https://pubmed.ncbi.nlm.nih.gov/?term={u}
medscape|Medscape|https://profiles.medscape.com/{u}
doximity|Doximity|https://www.doximity.com/pub/{u}
healthgrades|Healthgrades|https://www.healthgrades.com/physician/{u}
zocdoc|Zocdoc|https://www.zocdoc.com/doctor/{u}
avvo|Avvo|https://www.avvo.com/attorneys/{u}.html
justia|Justia|https://lawyers.justia.com/lawyer/{u}
martindale|Martindale|https://www.martindale.com/attorney/{u}
findlaw|FindLaw|https://lawyers.findlaw.com/profile/view/{u}
linkedin-company|LinkedIn company|https://www.linkedin.com/company/{u}
opencorporates|OpenCorporates|https://opencorporates.com/companies/{u}
companieshouse|UK Companies House|https://find-and-update.company-information.service.gov.uk/company/{u}
sec-edgar|SEC EDGAR|https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={u}
gleif|GLEIF LEI|https://search.gleif.org/#/record/{u}
duns|Dun & Bradstreet|https://www.dnb.com/business-directory/company-profiles.{u}.html
zoominfo|ZoomInfo|https://www.zoominfo.com/c/{u}
glassdoor|Glassdoor|https://www.glassdoor.com/Overview/Working-at-{u}
indeed|Indeed|https://www.indeed.com/cmp/{u}
trustpilot|Trustpilot|https://www.trustpilot.com/review/{u}
yelp|Yelp|https://www.yelp.com/biz/{u}
googlemaps|Google Maps|https://www.google.com/maps/search/{u}
tripadvisor|Tripadvisor|https://www.tripadvisor.com/Search?q={u}
foursquare|Foursquare|https://foursquare.com/{u}
booking|Booking.com|https://www.booking.com/searchresults.html?ss={u}
airbnb|Airbnb|https://www.airbnb.com/users/show/{u}
uber|Uber|https://www.uber.com/
lyft|Lyft|https://www.lyft.com/r/{u}
doordash|DoorDash|https://www.doordash.com/store/{u}
ubereats|Uber Eats|https://www.ubereats.com/store/{u}
grubhub|Grubhub|https://www.grubhub.com/restaurant/{u}
instacart|Instacart|https://www.instacart.com/store/{u}
opentable|OpenTable|https://www.opentable.com/r/{u}
eventbrite|Eventbrite|https://www.eventbrite.com/o/{u}
meetup|Meetup|https://www.meetup.com/members/{u}
luma|Luma|https://lu.ma/{u}
ticketmaster|Ticketmaster|https://www.ticketmaster.com/artist/{u}
songkick|Songkick|https://www.songkick.com/artists/{u}
bandsintown|Bandsintown|https://www.bandsintown.com/a/{u}
strava|Strava|https://www.strava.com/athletes/{u}
garmin|Garmin Connect|https://connect.garmin.com/modern/profile/{u}
mapmyrun|MapMyRun|https://www.mapmyrun.com/profile/{u}
runkeeper|Runkeeper|https://runkeeper.com/user/{u}
fitbit|Fitbit|https://www.fitbit.com/user/{u}
myfitnesspal|MyFitnessPal|https://www.myfitnesspal.com/profile/{u}
alltrails|AllTrails|https://www.alltrails.com/members/{u}
komoot|Komoot|https://www.komoot.com/user/{u}
wikiloc|Wikiloc|https://www.wikiloc.com/wikiloc/user.do?id={u}
geocaching|Geocaching|https://www.geocaching.com/p/default.aspx?u={u}
openstreetmap|OpenStreetMap|https://www.openstreetmap.org/user/{u}
waze|Waze|https://www.waze.com/editor?env=row&user={u}
tinder|Tinder|https://tinder.com/@{u}
bumble|Bumble|https://bumble.com/
okcupid|OkCupid|https://www.okcupid.com/profile/{u}
pof|Plenty of Fish|https://www.pof.com/viewprofile.aspx?profile_id={u}
match|Match.com|https://www.match.com/profile/{u}
hinge|Hinge|https://hinge.co/
badoo|Badoo|https://badoo.com/en/{u}
grindr|Grindr|https://grindr.com/
tagged|Tagged|https://www.tagged.com/{u}
skout|Skout|https://www.skout.com/
mamba|Mamba|https://www.mamba.ru/{u}
lovoo|Lovoo|https://www.lovoo.com/profile/{u}
jaumo|Jaumo|https://www.jaumo.com/
meetic|Meetic|https://www.meetic.com/
zoosk|Zoosk|https://www.zoosk.com/
ashleymadison|Ashley Madison|https://www.ashleymadison.com/
seeking|Seeking|https://www.seeking.com/
onlyfans|OnlyFans|https://onlyfans.com/{u}
fansly|Fansly|https://fansly.com/{u}
patreon-alt|Patreon (alt)|https://www.patreon.com/{u}
manyvids|ManyVids|https://www.manyvids.com/Profile/{u}
chaturbate|Chaturbate|https://chaturbate.com/{u}
pornhub|Pornhub|https://www.pornhub.com/users/{u}
xvideos|XVideos|https://www.xvideos.com/profiles/{u}
redtube|RedTube|https://www.redtube.com/users/{u}
xnxx|XNXX|https://www.xnxx.com/profiles/{u}
cam4|CAM4|https://www.cam4.com/{u}
livejasmin|LiveJasmin|https://www.livejasmin.com/
stripchat|Stripchat|https://stripchat.com/{u}
bongacams|BongaCams|https://bongacams.com/{u}
flirt4free|Flirt4Free|https://www.flirt4free.com/models/{u}
imlive|ImLive|https://www.imlive.com/
streamate|Streamate|https://www.streamate.com/
camsoda|CamSoda|https://www.camsoda.com/{u}
"""
)
