package io.github.dan537.devicepolicy

import android.app.Activity
import android.os.Bundle

/**
 * Handles ACTION_ADMIN_POLICY_COMPLIANCE, the last step of QR enrollment.
 *
 * Also mandatory on Android 11+. This is where a normal EMM would show a
 * setup screen; we have deliberately no UI, so it applies policy and exits
 * immediately.
 *
 * There is no Activity in this app that a user can launch, and no launcher
 * icon. Nothing to open means nothing to turn off.
 */
class PolicyComplianceActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // applyLocal() only — this is the main thread and Private DNS blocks on
        // network I/O. The worker applies the DNS lock moments later.
        PolicyEngine.applyLocal(this)
        PolicyWorker.schedule(this)
        PolicyWorker.runOnce(this)

        setResult(RESULT_OK)
        finish()
    }
}
