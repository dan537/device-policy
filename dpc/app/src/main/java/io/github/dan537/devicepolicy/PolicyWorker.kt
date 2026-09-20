package io.github.dan537.devicepolicy

import android.content.Context
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.Worker
import androidx.work.WorkerParameters
import androidx.work.WorkManager
import java.util.concurrent.TimeUnit

/**
 * The safety net.
 *
 * Everything else in this app is a one-shot application of policy at some
 * event. This runs on a timer forever and re-asserts the whole policy, which
 * means any drift gets repaired: a restriction cleared through some path we
 * did not anticipate, Private DNS repointed, or a blocked app reinstalled.
 *
 * It is also what retries Private DNS. setGlobalPrivateDnsModeSpecifiedHost
 * validates that the host really serves DNS-over-TLS, so it fails during
 * provisioning before the network is up. Rather than a retry loop at
 * provisioning time, we simply let the next pass fix it.
 *
 * 15 minutes is the platform minimum for periodic work; asking for less is
 * silently clamped.
 */
class PolicyWorker(context: Context, params: WorkerParameters) : Worker(context, params) {

    override fun doWork(): Result {
        PolicyEngine.apply(applicationContext)
        PolicyEngine.applyDeferredIfDue(applicationContext)

        // Private DNS validates the resolver over the network, so it routinely
        // fails while connectivity is still coming up after provisioning or a
        // reboot. Waiting for the next periodic pass leaves the DNS layer
        // unset for up to 15 minutes; retry on a short backoff instead.
        // After MAX_DNS_ATTEMPTS we stop and let the periodic pass own it —
        // at that point the network is genuinely down, not merely late.
        if (!PolicyEngine.isPrivateDnsLocked(applicationContext) &&
            runAttemptCount < MAX_DNS_ATTEMPTS
        ) {
            return Result.retry()
        }
        return Result.success()
    }

    companion object {
        private const val PERIODIC_NAME = "policy-reassert"
        private const val ONE_OFF_NAME = "policy-reassert-now"
        private const val MAX_DNS_ATTEMPTS = 8

        fun schedule(context: Context) {
            val request = PeriodicWorkRequestBuilder<PolicyWorker>(15, TimeUnit.MINUTES).build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                PERIODIC_NAME,
                // UPDATE rather than KEEP so a policy update shipped in a new
                // APK takes effect without waiting for the old schedule to die.
                ExistingPeriodicWorkPolicy.UPDATE,
                request
            )
        }

        fun runOnce(context: Context) {
            val request = OneTimeWorkRequestBuilder<PolicyWorker>().build()
            WorkManager.getInstance(context).enqueueUniqueWork(
                ONE_OFF_NAME,
                androidx.work.ExistingWorkPolicy.REPLACE,
                request
            )
        }
    }
}
