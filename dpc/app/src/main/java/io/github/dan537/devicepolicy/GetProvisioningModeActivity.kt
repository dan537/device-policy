package io.github.dan537.devicepolicy

import android.app.Activity
import android.app.admin.DevicePolicyManager
import android.content.Intent
import android.os.Bundle

/**
 * Handles ACTION_GET_PROVISIONING_MODE during QR enrollment.
 *
 * MANDATORY on Android 11 and above. If a DPC does not implement handlers for
 * both ACTION_GET_PROVISIONING_MODE and ACTION_ADMIN_POLICY_COMPLIANCE,
 * provisioning fails outright — with an unhelpful error, on a device you have
 * just factory reset. Do not remove this.
 *
 * We only ever want a fully managed device. A work profile would leave the
 * personal side of the phone completely unfiltered, which would defeat the
 * entire purpose.
 */
class GetProvisioningModeActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val result = Intent().putExtra(
            DevicePolicyManager.EXTRA_PROVISIONING_MODE,
            DevicePolicyManager.PROVISIONING_MODE_FULLY_MANAGED_DEVICE
        )
        setResult(RESULT_OK, result)
        finish()
    }
}
