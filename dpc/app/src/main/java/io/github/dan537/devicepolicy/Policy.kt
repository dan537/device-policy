package io.github.dan537.devicepolicy

/**
 * All policy constants in one place.
 *
 * DESIGN CONSTRAINT: this app must contain no code path that can weaken or
 * remove the policy. There is deliberately no unlock mechanism, no password,
 * no "disable" flag and no UI. `clearUserRestriction`, `clearDeviceOwnerApp`
 * and `wipeData` are never called anywhere in this codebase. The only way out
 * is a recovery-mode wipe of the device, which is intentional.
 */
object Policy {

    /**
     * NextDNS strict profile, delivered over DNS-over-TLS.
     *
     * Strict Private DNS mode fails CLOSED: if this host is unreachable, name
     * resolution fails rather than silently falling back to plaintext DNS.
     * That is the desired behaviour — losing the filter should cost internet,
     * not filtering.
     */
    const val PRIVATE_DNS_HOST = "f5b1aa.dns.nextdns.io"

    /** The one browser permitted, locked down via Chrome enterprise policy. */
    const val ALLOWED_BROWSER = "com.android.chrome"

    /**
     * Grace period before the irreversible restrictions land.
     *
     * ADB and the Settings factory-reset stay available for this long so a bad
     * build can be diagnosed and escaped without a recovery wipe. This is the
     * single safety valve in the design; do not shorten it without a reason.
     */
    const val GRACE_PERIOD_MS = 24L * 60L * 60L * 1000L

    /**
     * Apps suspended outright regardless of whether they are browsers.
     */
    val BLOCKED_PACKAGES = listOf(
        // Reddit
        "com.reddit.frontpage",
        "com.laurencedawson.reddit_sync",
        "com.laurencedawson.reddit_sync.pro",
        "com.andrewshu.android.reddit",
        "com.rubenmayayo.reddit",
        "free.reddit.news",
        "com.onelouder.baconreader",
        "com.onelouder.baconreader.premium",
        "ml.docilealligator.infinityforreddit",
        "com.phoenixforreddit",
        "o.o.joey",
        "me.ccrama.redditslide",

        // Discord
        "com.discord",
        "com.discord.ptb",
        "com.discord.canary",
        "com.aliucord",
        "com.discord.vanced",

        // Telegram
        "org.telegram.messenger",
        "org.telegram.messenger.web",
        "org.telegram.messenger.beta",
        "org.telegram.plus",
        "org.thunderdog.challegram",
        "nekox.messenger",
        "it.owlgram.android"
    )

    /**
     * Browsers suspended by name. The dynamic sweep in [PolicyEngine] catches
     * anything not on this list by inspecting intent-filter shape, so this
     * exists to act on the common cases even if that heuristic ever misses.
     *
     * Browsers with a built-in proxy or VPN (Opera, Aloha, Tor) are the reason
     * a browser allowlist is necessary at all: they tunnel around DNS-level
     * filtering completely.
     */
    val BLOCKED_BROWSERS = listOf(
        "com.sec.android.app.sbrowser",              // Samsung Internet (preinstalled on the A36)
        "com.sec.android.app.sbrowser.beta",
        "org.mozilla.firefox",
        "org.mozilla.firefox_beta",
        "org.mozilla.fenix",
        "org.mozilla.focus",
        "org.mozilla.klar",
        "com.opera.browser",
        "com.opera.browser.beta",
        "com.opera.mini.native",
        "com.opera.mini.native.beta",
        "com.opera.gx",
        "com.opera.touch",
        "alohabrowser.alohabrowser",
        "com.alohamobile.browser",
        "org.torproject.torbrowser",
        "org.torproject.android",                    // Orbot
        "com.brave.browser",
        "com.brave.browser_beta",
        "com.brave.browser_nightly",
        "com.microsoft.emmx",                        // Edge
        "com.microsoft.emmx.canary",
        "com.duckduckgo.mobile.android",
        "com.kiwibrowser.browser",
        "com.UCMobile.intl",
        "com.uc.browser.en",
        "com.yandex.browser",
        "com.yandex.browser.beta",
        "com.yandex.searchapp",
        "mark.via.gp",                               // Via
        "acr.browser.lightning",                     // Lightning
        "com.jio.web",
        "com.cloudmosa.puffinFree",
        "com.puffin.browser",
        "com.aloha.vpn",
        "org.adblockplus.browser",
        "com.ecosia.android",
        "com.qwant.liberty",
        "com.vivaldi.browser",
        "com.sec.android.app.samsungapps",           // Galaxy Store — alternate app source
        "com.phoenix.browser",
        "com.transsion.phoenix",
        "com.mi.globalbrowser",
        "com.android.browser",                       // AOSP browser
        "com.tencent.mtt",
        "com.huawei.browser"
    )

    /**
     * Packages that must NEVER be suspended, whatever the sweep decides.
     *
     * Without this guard a bug in the browser sweep could suspend Settings or
     * the dialer and leave the phone unusable with no way to intervene — the
     * policy cannot be removed. Treat this list as a safety interlock.
     */
    val NEVER_SUSPEND = setOf(
        "io.github.dan537.devicepolicy",
        ALLOWED_BROWSER,
        "android",
        "com.android.settings",
        "com.android.systemui",
        "com.android.phone",
        "com.android.server.telecom",
        "com.android.dialer",
        "com.android.contacts",
        "com.android.mms",
        "com.android.providers.settings",
        "com.android.providers.telephony",
        "com.android.providers.contacts",
        "com.android.providers.downloads",
        "com.android.packageinstaller",
        "com.google.android.packageinstaller",
        "com.android.permissioncontroller",
        "com.android.certinstaller",
        "com.android.keychain",
        "com.android.emergency",
        "com.android.vending",                       // Play Store
        "com.google.android.gms",
        "com.google.android.gsf",
        "com.google.android.gms.location.history",
        "com.google.android.dialer",
        "com.google.android.contacts",
        "com.google.android.apps.messaging",
        "com.google.android.webview",
        "com.google.android.trichromelibrary",
        "com.android.webview",
        "com.google.android.setupwizard",
        "com.google.android.apps.restore",
        // Samsung system surfaces on the A36
        "com.samsung.android.dialer",
        "com.samsung.android.messaging",
        "com.samsung.android.contacts",
        "com.samsung.android.incallui",
        "com.samsung.android.app.telephonyui",
        "com.samsung.android.emergencylauncher",
        "com.sec.android.app.launcher",
        "com.samsung.android.honeyboard",            // keyboard
        "com.sec.android.inputmethod",
        "com.samsung.android.lool",
        "com.samsung.android.setting.multisound",
        "com.wssyncmldm",                            // Samsung software update
        "com.sec.android.soagent",
        // Launchers / IME fallbacks
        "com.google.android.apps.nexuslauncher",
        "com.android.launcher3",
        "com.google.android.inputmethod.latin",
        "com.android.inputmethod.latin"
    )

    /**
     * Chrome URL blocklist.
     *
     * Chrome's filter format matches a bare host AND all of its subdomains, so
     * "reddit.com" also covers "old.reddit.com".
     *
     * This is a second, independent layer to DNS: it holds even if a DNS query
     * somehow resolves. Note the search engines — ForceGoogleSafeSearch only
     * affects Google, so leaving Bing/DuckDuckGo/Yandex reachable would leave
     * an unfiltered image search wide open.
     */
    val CHROME_URL_BLOCKLIST = listOf(
        // Reddit
        "reddit.com", "redd.it", "redditmedia.com", "redditstatic.com",
        "teddit.net", "libreddit.com", "redlib.matthew.science", "unddit.com",
        "reveddit.com", "imgur.com",

        // Discord / Telegram
        "discord.com", "discordapp.com", "discord.gg", "discordapp.net",
        "telegram.org", "t.me", "telegram.me", "telegra.ph", "web.telegram.org",

        // Search engines other than Google — SafeSearch cannot be forced on these
        "bing.com", "duckduckgo.com", "lite.duckduckgo.com", "html.duckduckgo.com",
        "search.yahoo.com", "yandex.com", "yandex.ru", "yandex.com.tr",
        "search.brave.com", "startpage.com", "searx.be", "searxng.site",
        "mojeek.com", "ecosia.org", "qwant.com", "swisscows.com", "gibiru.com",

        // Translate and cache proxies — classic filter bypasses
        "translate.google.com", "translate.googleapis.com",
        "translate.yandex.com", "webcache.googleusercontent.com",
        "12ft.io", "textance.herokuapp.com",

        // Adult
        "pornhub.com", "xvideos.com", "xnxx.com", "xhamster.com", "redtube.com",
        "youporn.com", "tube8.com", "spankbang.com", "eporner.com", "txxx.com",
        "hqporner.com", "porntrex.com", "beeg.com", "youjizz.com",
        "motherless.com", "xtube.com", "porn.com", "sex.com", "thumbzilla.com",
        "sxyprn.com", "coomer.su", "kemono.su", "scrolller.com",
        "brazzers.com", "onlyfans.com", "fansly.com", "manyvids.com",
        "chaturbate.com", "stripchat.com", "bongacams.com", "cam4.com",
        "myfreecams.com", "livejasmin.com", "camsoda.com",
        "rule34.xxx", "rule34video.com", "e-hentai.org", "exhentai.org",
        "nhentai.net", "hanime.tv", "hentaihaven.xxx", "gelbooru.com",
        "danbooru.donmai.us", "sankakucomplex.com", "luscious.net",
        "erome.com", "fapello.com", "nudevista.com",
        "mrdeepfakes.com", "adultdeepfakes.com",
        "candy.ai", "janitorai.com", "spicychat.ai", "crushon.ai",
        "promptchan.ai", "pornpen.ai", "undress.app", "clothoff.io",

        // Image boards
        "4chan.org", "4channel.org", "8kun.top",

        // Web proxies
        "croxyproxy.com", "croxyproxy.rocks", "proxysite.com", "kproxy.com",
        "4everproxy.com", "hidester.com", "blockaway.net", "proxyium.com",
        "hidemyass.com", "filterbypass.me", "proxfree.com", "zalmos.com",

        // VPN / Tor
        "torproject.org", "protonvpn.com", "mullvad.net", "nordvpn.com",
        "surfshark.com", "expressvpn.com", "windscribe.com", "ivpn.net",
        "privateinternetaccess.com", "cyberghostvpn.com", "tunnelbear.com",
        "hide.me", "psiphon.ca", "getlantern.org", "vpngate.net",
        "vpnbook.com", "freeopenvpn.org",

        // NextDNS management — so the phone cannot weaken its own filter
        "my.nextdns.io", "api.nextdns.io", "account.nextdns.io",

        // Chrome internals that could be used to inspect or defeat filtering.
        // chrome://policy is deliberately LEFT REACHABLE so the policy can be
        // audited from the device later.
        "chrome://flags",
        "chrome://net-internals",
        "chrome://net-export",
        "chrome://net-internals/#dns"
    )

    /**
     * Chrome URL allowlist — takes precedence over the blocklist.
     *
     * Health, clinical and recovery resources. NSFW blocklists routinely
     * misclassify sexual-health and addiction-recovery content as adult, and a
     * filter that blocks the user's own route out is a bad failure mode. These
     * are also allowlisted at the DNS layer; belt and braces.
     */
    val CHROME_URL_ALLOWLIST = listOf(
        // Crisis / mental health
        "samaritans.org", "giveusashout.org", "mind.org.uk", "rethink.org",
        "mentalhealth.org.uk", "hubofhope.co.uk", "findahelpline.com",
        "befrienders.org", "988lifeline.org",

        // NHS and clinical reference
        "nhs.uk", "111.nhs.uk", "england.nhs.uk", "nice.org.uk",
        "patient.info", "netdoctor.co.uk", "mayoclinic.org",
        "clevelandclinic.org", "healthline.com", "webmd.com",
        "medlineplus.gov", "nih.gov", "ncbi.nlm.nih.gov", "who.int",
        "cdc.gov", "bmj.com", "thelancet.com",
        "psychologytoday.com", "verywellmind.com", "verywellhealth.com",

        // Sexual health services
        "brook.org.uk", "sexwise.org.uk", "fpa.org.uk", "tht.org.uk",
        "shl.uk", "sh24.org.uk", "plannedparenthood.org",
        "ashasexualhealth.org",

        // Recovery — compulsive sexual behaviour
        "saa-recovery.org", "sa.org", "slaafws.org", "sexhelp.com",
        "yourbrainonporn.com", "rebootnation.org", "nofap.com",
        "fortifyprogram.org", "covenanteyes.com", "integrityrestored.com",

        // Recovery — general
        "smartrecovery.org", "smartrecovery.org.uk", "aa.org",
        "alcoholics-anonymous.org.uk", "na.org", "ukna.org",
        "talktofrank.com", "wearewithyou.org.uk", "actiononaddiction.org.uk",
        "rehab4addiction.co.uk",

        // Therapy directories
        "bacp.co.uk", "counselling-directory.org.uk", "psychotherapy.org.uk",
        "cosrt.org.uk", "atsac.co.uk"
    )
}
