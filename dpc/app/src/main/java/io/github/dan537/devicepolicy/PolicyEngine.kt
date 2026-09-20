package io.github.dan537.devicepolicy

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ResolveInfo
import android.net.Uri
import android.os.Bundle
import android.os.UserManager
import android.util.Log

/**
 * Asserts the entire device policy. Idempotent: safe to call as often as we
 * like, from provisioning, boot, package-install and the periodic worker.
 *
 * The periodic re-assertion is the real safety net. Any drift — a restriction
 * somehow cleared, Private DNS repointed, a blocked app reinstalled — is
 * repaired on the next pass rather than persisting silently.
 *
 * NOTE: nothing in this class ever clears a restriction, unsuspends a blocked
 * package, or relinquishes device ownership. That is deliberate and is the
 * mechanism by which "there is no off switch" is literally true.
 */
object PolicyEngine {

    private const val TAG = "DevicePolicy"
    private const val PREFS = "policy_state"
    private const val KEY_PROVISIONED_AT = "provisioned_at"

    /** Restrictions applied immediately and permanently. */
    private val IMMEDIATE_RESTRICTIONS = listOf(
        // The headline one. This does not merely hide the VPN settings page:
        // per AOSP it prevents VPNs from starting at all, and on Android 12+
        // clears any VPN the user had already configured.
        UserManager.DISALLOW_CONFIG_VPN,

        // Locks Private DNS globally. Device-owner-only restriction.
        UserManager.DISALLOW_CONFIG_PRIVATE_DNS,

        // Stops force-stop / clear-data being used against this app.
        UserManager.DISALLOW_APPS_CONTROL,

        // Safe mode would start the device without third-party apps.
        UserManager.DISALLOW_SAFE_BOOT,

        // "Reset network settings" can otherwise clear DNS configuration.
        UserManager.DISALLOW_NETWORK_RESET,

        // No secondary users to browse from.
        UserManager.DISALLOW_ADD_USER
    )

    /**
     * Restrictions deferred until the grace period expires.
     *
     * Applying these immediately would remove the ability to diagnose or
     * escape a broken policy, because the policy itself cannot be removed.
     * DISALLOW_DEBUGGING_FEATURES matters because `adb shell` holds
     * WRITE_SECURE_SETTINGS and could otherwise write private_dns_mode
     * directly, bypassing DISALLOW_CONFIG_PRIVATE_DNS.
     */
    private val DEFERRED_RESTRICTIONS = listOf(
        UserManager.DISALLOW_DEBUGGING_FEATURES,
        UserManager.DISALLOW_FACTORY_RESET
    )

    /**
     * Everything that does no network I/O, and is therefore safe to call from a
     * BroadcastReceiver or Activity on the main thread.
     *
     * Kept separate from [applyNetwork] so the lockdown lands instantly during
     * provisioning rather than waiting on a worker: restrictions, Chrome policy
     * and app suspension are all local operations.
     */
    fun applyLocal(context: Context) {
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val admin = ComponentName(context, AdminReceiver::class.java)

        if (!dpm.isDeviceOwnerApp(context.packageName)) {
            Log.w(TAG, "Not device owner; no policy to apply.")
            return
        }

        recordProvisioningTime(context)

        applyRestrictions(dpm, admin)
        applyChromePolicy(dpm, admin)
        suspendBlockedApps(context, dpm, admin)
        protectSelf(dpm, admin)

        Log.i(TAG, "Local policy applied.")
    }

    /**
     * The Private DNS lock. MUST NOT run on the main thread.
     *
     * setGlobalPrivateDnsModeSpecifiedHost() resolves the hostname and performs
     * a TLS handshake on port 853 synchronously on the calling thread, so
     * calling it from a receiver throws NetworkOnMainThreadException and the
     * DNS lock silently never applies. Only [PolicyWorker] calls this.
     */
    fun applyNetwork(context: Context) {
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val admin = ComponentName(context, AdminReceiver::class.java)
        if (!dpm.isDeviceOwnerApp(context.packageName)) return

        applyPrivateDns(dpm, admin)
    }

    /** Full pass. Background thread only — see [applyNetwork]. */
    fun apply(context: Context) {
        applyLocal(context)
        applyNetwork(context)
    }

    // -----------------------------------------------------------------------
    // Grace period
    // -----------------------------------------------------------------------

    private fun recordProvisioningTime(context: Context) {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (!prefs.contains(KEY_PROVISIONED_AT)) {
            prefs.edit().putLong(KEY_PROVISIONED_AT, System.currentTimeMillis()).apply()
        }
    }

    private fun gracePeriodExpired(context: Context): Boolean {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val at = prefs.getLong(KEY_PROVISIONED_AT, 0L)
        if (at == 0L) return false
        return System.currentTimeMillis() - at >= Policy.GRACE_PERIOD_MS
    }

    // -----------------------------------------------------------------------
    // User restrictions
    // -----------------------------------------------------------------------

    private fun applyRestrictions(dpm: DevicePolicyManager, admin: ComponentName) {
        for (r in IMMEDIATE_RESTRICTIONS) {
            runCatching { dpm.addUserRestriction(admin, r) }
                .onFailure { Log.w(TAG, "Could not set $r: ${it.message}") }
        }
    }

    /**
     * Called separately by the worker so the deferred set lands even if the
     * device is never rebooted after the grace period elapses.
     */
    fun applyDeferredIfDue(context: Context) {
        if (!gracePeriodExpired(context)) return

        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val admin = ComponentName(context, AdminReceiver::class.java)
        if (!dpm.isDeviceOwnerApp(context.packageName)) return

        for (r in DEFERRED_RESTRICTIONS) {
            runCatching { dpm.addUserRestriction(admin, r) }
                .onFailure { Log.w(TAG, "Could not set deferred $r: ${it.message}") }
        }
        Log.i(TAG, "Grace period over; deferred restrictions applied.")
    }

    // -----------------------------------------------------------------------
    // Private DNS
    // -----------------------------------------------------------------------

    /** True when Private DNS is already in strict mode pinned to our resolver. */
    fun isPrivateDnsLocked(context: Context): Boolean {
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val admin = ComponentName(context, AdminReceiver::class.java)
        if (!dpm.isDeviceOwnerApp(context.packageName)) return false
        return runCatching {
            dpm.getGlobalPrivateDnsMode(admin) == DevicePolicyManager.PRIVATE_DNS_MODE_PROVIDER_HOSTNAME &&
                dpm.getGlobalPrivateDnsHost(admin) == Policy.PRIVATE_DNS_HOST
        }.getOrDefault(false)
    }

    private fun applyPrivateDns(dpm: DevicePolicyManager, admin: ComponentName) {
        // Defensive: if a future caller invokes this from the main thread the
        // failure would be silent and the DNS layer simply would not exist.
        if (android.os.Looper.myLooper() == android.os.Looper.getMainLooper()) {
            Log.e(TAG, "applyPrivateDns called on main thread; refusing. Use PolicyWorker.")
            return
        }

        val alreadyCorrect =
            dpm.getGlobalPrivateDnsMode(admin) == DevicePolicyManager.PRIVATE_DNS_MODE_PROVIDER_HOSTNAME &&
                dpm.getGlobalPrivateDnsHost(admin) == Policy.PRIVATE_DNS_HOST
        if (alreadyCorrect) return

        // This call validates that the host actually serves DNS-over-TLS, so it
        // fails while the network is still coming up during provisioning. The
        // periodic worker retries, which is why no retry loop is needed here.
        val result = runCatching {
            dpm.setGlobalPrivateDnsModeSpecifiedHost(admin, Policy.PRIVATE_DNS_HOST)
        }.getOrElse {
            Log.w(TAG, "Private DNS call threw", it)
            return
        }

        when (result) {
            DevicePolicyManager.PRIVATE_DNS_SET_NO_ERROR ->
                Log.i(TAG, "Private DNS locked to ${Policy.PRIVATE_DNS_HOST}")
            DevicePolicyManager.PRIVATE_DNS_SET_ERROR_HOST_NOT_SERVING ->
                Log.w(TAG, "Resolver not reachable yet; worker will retry.")
            else ->
                Log.w(TAG, "Private DNS not set, result=$result; worker will retry.")
        }
    }

    // -----------------------------------------------------------------------
    // Chrome enterprise policy
    // -----------------------------------------------------------------------

    /**
     * Chrome on Android reads enterprise policy from app restrictions.
     *
     * List-valued policies must be passed as a SERIALISED JSON STRING, not a
     * string array — Chrome parses the JSON itself. Google's own documentation
     * shows `"URLBlocklist": "[\"www.solamora.com\"]"`. Passing a real array
     * silently produces an ignored policy, so verify via chrome://policy after
     * any change here.
     */
    private fun applyChromePolicy(dpm: DevicePolicyManager, admin: ComponentName) {
        val b = Bundle().apply {
            putString("URLBlocklist", toJsonArray(Policy.CHROME_URL_BLOCKLIST))
            putString("URLAllowlist", toJsonArray(Policy.CHROME_URL_ALLOWLIST))

            // Force SafeSearch on Google. Only affects Google, which is why the
            // other search engines are on the blocklist.
            putBoolean("ForceGoogleSafeSearch", true)

            // 2 = Strict Restricted Mode.
            putInt("ForceYouTubeRestrict", 2)

            // 1 = Incognito disabled. Without this, blocklists still apply but
            // history does not, which makes relapse frictionless.
            putInt("IncognitoModeAvailability", 1)

            // Critical: stops Chrome resolving around the locked system DNS
            // using its own DNS-over-HTTPS.
            putString("DnsOverHttpsMode", "off")

            // Pin search to Google so ForceGoogleSafeSearch actually bites.
            putBoolean("DefaultSearchProviderEnabled", true)
            putString("DefaultSearchProviderName", "Google")
            putString("DefaultSearchProviderSearchURL", "https://www.google.com/search?q={searchTerms}&safe=active")
            putString("DefaultSearchProviderKeyword", "google.com")

            // No syncing a bookmark of a blocked site in from elsewhere, and no
            // guest profile to escape policy with.
            putBoolean("BrowserGuestModeEnabled", false)
            putBoolean("EditBookmarksEnabled", false)
        }

        runCatching { dpm.setApplicationRestrictions(admin, Policy.ALLOWED_BROWSER, b) }
            .onFailure { Log.w(TAG, "Could not set Chrome policy: ${it.message}") }
    }

    private fun toJsonArray(items: List<String>): String =
        items.joinToString(prefix = "[", postfix = "]") { "\"" + it.replace("\\", "\\\\").replace("\"", "\\\"") + "\"" }

    // -----------------------------------------------------------------------
    // App suspension
    // -----------------------------------------------------------------------

    private fun suspendBlockedApps(
        context: Context,
        dpm: DevicePolicyManager,
        admin: ComponentName
    ) {
        val targets = LinkedHashSet<String>()
        targets += Policy.BLOCKED_PACKAGES
        targets += Policy.BLOCKED_BROWSERS
        targets += discoverBrowsers(context)

        // The safety interlock. A bug that suspended Settings or the dialer
        // would leave an unusable phone that cannot be un-policied.
        targets.removeAll(Policy.NEVER_SUSPEND)

        val installed = targets.filter { isInstalled(context, it) }
        if (installed.isEmpty()) return

        val failed = runCatching {
            dpm.setPackagesSuspended(admin, installed.toTypedArray(), true)
        }.getOrElse {
            Log.w(TAG, "Suspension call failed: ${it.message}")
            return
        }

        if (failed.isNotEmpty()) {
            // Usually means the package is protected by the platform. Logged
            // rather than retried, since retrying will not change the outcome.
            Log.w(TAG, "Could not suspend: ${failed.joinToString()}")
        }
        Log.i(TAG, "Suspended ${installed.size - failed.size}/${installed.size} target packages.")
    }

    /**
     * Finds every installed browser, including ones we have never heard of.
     *
     * Getting this discriminator right matters in both directions: too loose
     * and we suspend half the phone, too tight and an unknown browser walks
     * straight through the filter.
     *
     * `ResolveInfo.handleAllWebDataURI` would be the obvious test but it is
     * hidden API, absent from android.jar, so it cannot be used.
     *
     * Instead we rely on the shape of the intent filter. A real browser
     * registers for http/https with NO data authority and NO path — it will
     * take any URL. An app with deep links always pins a specific host, and
     * usually a path prefix too. So:
     *
     *   - probe with a host that cannot exist, so host-specific filters miss
     *   - require countDataAuthorities() == 0 and countDataPaths() == 0
     *
     * GET_RESOLVED_FILTER is required or `ResolveInfo.filter` comes back null
     * and nothing matches.
     */
    private fun discoverBrowsers(context: Context): List<String> {
        val pm = context.packageManager
        val flags = PackageManager.MATCH_ALL or PackageManager.GET_RESOLVED_FILTER

        val found = LinkedHashSet<String>()
        for (scheme in listOf("http", "https")) {
            val probe = Intent(Intent.ACTION_VIEW, Uri.parse("$scheme://policy-probe.invalid/"))
                .addCategory(Intent.CATEGORY_BROWSABLE)

            val resolved: List<ResolveInfo> = runCatching {
                pm.queryIntentActivities(probe, flags)
            }.getOrElse { emptyList() }

            for (ri in resolved) {
                val f = ri.filter ?: continue
                if (f.countDataAuthorities() != 0) continue
                if (f.countDataPaths() != 0) continue
                found += ri.activityInfo.packageName
            }
        }

        return found.filterNot { it in Policy.NEVER_SUSPEND }
    }

    private fun isInstalled(context: Context, pkg: String): Boolean =
        runCatching { context.packageManager.getApplicationInfo(pkg, 0); true }.getOrDefault(false)

    // -----------------------------------------------------------------------
    // Self-protection
    // -----------------------------------------------------------------------

    private fun protectSelf(dpm: DevicePolicyManager, admin: ComponentName) {
        // A device owner cannot be uninstalled anyway, but this closes the
        // Settings path that would otherwise show an (always failing) option.
        runCatching { dpm.setUninstallBlocked(admin, admin.packageName, true) }
            .onFailure { Log.w(TAG, "Could not block own uninstall: ${it.message}") }
    }
}
