package com.carriez.flutter_hbb

import android.app.Activity
import android.app.ActivityManager
import android.app.Application
import android.app.KeyguardManager
import android.app.PendingIntent
import android.app.admin.DevicePolicyManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentSender
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Log
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import java.util.concurrent.TimeUnit
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

/**
 * Managed builds (RDC): the Android facts the debug-log upload reports (the counterpart of the
 * Windows security inventory) and the self-update install. Called from Rust (managed_android.rs)
 * via JNI as call(context, op, arg).
 */
object RdcPlatform {
    private const val TAG = "rdc"
    private const val SECRET_ALIAS = "rdc-device-secrets"

    @JvmStatic
    fun call(context: Context, op: String, arg: String): String = try {
        when (op) {
            "device_report" -> deviceReport(context).toString()
            "stage_update" -> stageUpdate(context, arg)
            "install_update" -> installUpdate(context, arg)
            else -> "error:unknown op"
        }
    } catch (e: Throwable) {
        Log.w(TAG, "RdcPlatform.$op failed", e)
        "error:" + (e.message ?: e.javaClass.simpleName)
    }

    private fun <T> safe(block: () -> T): T? = try {
        block()
    } catch (e: Throwable) {
        null
    }

    private fun deviceReport(context: Context): JSONObject {
        val cr = context.contentResolver
        val pm = context.packageManager
        val report = JSONObject()
        report.put("manufacturer", Build.MANUFACTURER)
        report.put("model", Build.MODEL)
        report.put("release", Build.VERSION.RELEASE)
        report.put("sdk", Build.VERSION.SDK_INT)
        report.put("security_patch", Build.VERSION.SECURITY_PATCH)
        safe { context.getSystemService(KeyguardManager::class.java).isDeviceSecure }
            ?.let { report.put("screen_lock", it) }
        safe {
            when (context.getSystemService(DevicePolicyManager::class.java).storageEncryptionStatus) {
                DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER -> "file-based"
                DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE -> "active"
                DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY -> "default key"
                DevicePolicyManager.ENCRYPTION_STATUS_INACTIVE -> "off"
                DevicePolicyManager.ENCRYPTION_STATUS_UNSUPPORTED -> "unsupported"
                else -> "unknown"
            }
        }?.let { report.put("encryption", it) }
        safe { Settings.Global.getInt(cr, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) != 0 }
            ?.let { report.put("developer_options", it) }
        safe { Settings.Global.getInt(cr, Settings.Global.ADB_ENABLED, 0) != 0 }
            ?.let { report.put("usb_debugging", it) }
        safe { Settings.Global.getInt(cr, "adb_wifi_enabled", 0) != 0 }
            ?.let { report.put("wireless_debugging", it) }
        safe { Settings.Global.getInt(cr, Settings.Global.AUTO_TIME, 0) != 0 }
            ?.let { report.put("auto_time", it) }
        systemProperty("ro.boot.verifiedbootstate")?.let { report.put("verified_boot", it) }
        systemProperty("ro.boot.flash.locked")?.let { report.put("bootloader_locked", it == "1") }
        safe { pm.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE) }
            ?.let { report.put("strongbox", it) }
        safe { secretKeyLevel() }?.let { report.put("secret_key_storage", it) }
        safe { pm.canRequestPackageInstalls() }?.let { report.put("install_unknown_apps", it) }
        safe { installerOf(context) }?.let { report.put("installer", it) }
        safe {
            val info = pm.getPackageInfo(context.packageName, 0)
            if (Build.VERSION.SDK_INT >= 28) info.longVersionCode else info.versionCode.toLong()
        }?.let { report.put("version_code", it) }
        safe { network(context) }?.let { report.put("network", it) }
        return report
    }

    private fun systemProperty(name: String): String? = safe {
        val process = ProcessBuilder("getprop", name).redirectErrorStream(true).start()
        if (!process.waitFor(2, TimeUnit.SECONDS)) {
            process.destroy()
            return@safe null
        }
        process.inputStream.bufferedReader().readText().trim().ifEmpty { null }
    }

    // Where the Keystore key that wraps the app's secrets (SecretWrap) lives; never creates it.
    private fun secretKeyLevel(): String? {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val key = store.getKey(SECRET_ALIAS, null) as? SecretKey ?: return "none"
        val info = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
            .getKeySpec(key, KeyInfo::class.java) as KeyInfo
        if (Build.VERSION.SDK_INT >= 31) {
            return when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> "strongbox"
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "tee"
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> "software"
                KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> "secure hardware"
                else -> "unknown"
            }
        }
        @Suppress("DEPRECATION")
        return if (info.isInsideSecureHardware) "secure hardware" else "software"
    }

    private fun installerOf(context: Context): String? {
        val pm = context.packageManager
        return if (Build.VERSION.SDK_INT >= 30) {
            pm.getInstallSourceInfo(context.packageName).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            pm.getInstallerPackageName(context.packageName)
        }
    }

    private fun network(context: Context): JSONObject {
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val result = JSONObject()
        val active = cm.activeNetwork ?: return result.put("type", "none")
        val caps = cm.getNetworkCapabilities(active)
        if (caps != null) {
            result.put(
                "type", when {
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
                    else -> "other"
                }
            )
            result.put("vpn", caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN))
            result.put("validated", caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED))
        }
        cm.getLinkProperties(active)?.let { link ->
            if (Build.VERSION.SDK_INT >= 28) {
                result.put("private_dns", link.isPrivateDnsActive)
                link.privateDnsServerName?.let { result.put("private_dns_server", it) }
            }
        }
        return result
    }

    private fun isForeground(): Boolean {
        val info = ActivityManager.RunningAppProcessInfo()
        ActivityManager.getMyMemoryState(info)
        return info.importance <= ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND
    }

    private class Staged(val path: String, val sessionId: Int, var armed: Boolean)

    @Volatile
    private var staged: Staged? = null

    @Volatile
    private var lifecycleHooked = false

    /** Android asked for confirmation on an install meant to be silent; ask in the open app instead. */
    @Volatile
    @JvmStatic
    var silentRefused = false

    private fun silentCapable(context: Context): Boolean =
        Build.VERSION.SDK_INT >= 31 && !silentRefused && installerOf(context) == context.packageName

    /**
     * Once RDC installed its own previous update (it is then the installer of record), Android 12+
     * updates it without asking. The verified APK is written into an install session here and
     * committed when RDC leaves the screen (hookLifecycle), so it never closes under the user and
     * is committed before a vendor's background freezer stops the app. `path` empty = a remote
     * session is open: hold the update. Returns "silent", or "confirm" when Android will ask
     * (installUpdate, while the app is open).
     */
    @Synchronized
    private fun stageUpdate(context: Context, path: String): String {
        hookLifecycle(context)
        val current = staged
        if (path.isEmpty()) {
            current?.armed = false
            return "held"
        }
        if (!silentCapable(context)) {
            current?.let { safe { context.packageManager.packageInstaller.abandonSession(it.sessionId) } }
            staged = null
            return "confirm"
        }
        if (current != null && current.path == path) {
            current.armed = true
            return "silent"
        }
        current?.let { safe { context.packageManager.packageInstaller.abandonSession(it.sessionId) } }
        staged = Staged(path, writeSession(context, File(path)), true)
        return "silent"
    }

    @Synchronized
    private fun commitStaged(context: Context) {
        val current = staged ?: return
        if (!current.armed) return
        staged = null
        try {
            context.packageManager.packageInstaller.openSession(current.sessionId).use {
                it.commit(resultIntent(context, current.sessionId, true))
            }
            Log.i(TAG, "update install committed (silent)")
        } catch (e: Throwable) {
            Log.w(TAG, "update commit failed", e)
        }
    }

    private fun hookLifecycle(context: Context) {
        if (lifecycleHooked) return
        lifecycleHooked = true
        // Sessions left uncommitted by an earlier run of the app (it was closed or killed).
        val installer = context.packageManager.packageInstaller
        for (info in installer.mySessions) {
            if (Build.VERSION.SDK_INT < 29 || !info.isCommitted) safe { installer.abandonSession(info.sessionId) }
        }
        val app = context.applicationContext as Application
        app.registerActivityLifecycleCallbacks(object : Application.ActivityLifecycleCallbacks {
            override fun onActivityStopped(activity: Activity) {
                if (activity.isChangingConfigurations || staged?.armed != true) return
                val appContext = activity.applicationContext
                Thread { commitStaged(appContext) }.start()
            }

            override fun onActivityCreated(activity: Activity, state: Bundle?) {}
            override fun onActivityStarted(activity: Activity) {}
            override fun onActivityResumed(activity: Activity) {}
            override fun onActivityPaused(activity: Activity) {}
            override fun onActivitySaveInstanceState(activity: Activity, state: Bundle) {}
            override fun onActivityDestroyed(activity: Activity) {}
        })
    }

    private fun writeSession(context: Context, file: File): Int {
        val installer = context.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
        params.setAppPackageName(context.packageName)
        params.setSize(file.length())
        if (Build.VERSION.SDK_INT >= 31) {
            params.setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
        }
        val sessionId = installer.createSession(params)
        try {
            installer.openSession(sessionId).use { session ->
                session.openWrite("rdc.apk", 0, file.length()).use { out ->
                    file.inputStream().use { it.copyTo(out) }
                    session.fsync(out)
                }
            }
        } catch (e: Throwable) {
            safe { installer.abandonSession(sessionId) }
            throw e
        }
        return sessionId
    }

    private fun resultIntent(context: Context, sessionId: Int, silent: Boolean): IntentSender {
        val intent = Intent(context, UpdateResultReceiver::class.java).putExtra("rdc_silent", silent)
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or
            (if (Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0)
        return PendingIntent.getBroadcast(context, sessionId, intent, flags).intentSender
    }

    /**
     * Before RDC is its own installer of record, Android asks once ("Update this app?"), so the
     * install starts only while the app is open. Returns "started" or "deferred:<reason>".
     */
    private fun installUpdate(context: Context, path: String): String {
        val file = File(path)
        if (!file.isFile) return "error:update file missing"
        if (!isForeground()) return "deferred:needs the app open to confirm"
        val sessionId = writeSession(context, file)
        try {
            context.packageManager.packageInstaller.openSession(sessionId).use {
                it.commit(resultIntent(context, sessionId, false))
            }
        } catch (e: Throwable) {
            safe { context.packageManager.packageInstaller.abandonSession(sessionId) }
            throw e
        }
        Log.i(TAG, "update install committed (asks to confirm)")
        return "started"
    }
}

/** Result of an update install session; asks the user to confirm when Android requires it. */
class UpdateResultReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
        if (status == PackageInstaller.STATUS_PENDING_USER_ACTION) {
            if (intent.getBooleanExtra("rdc_silent", false)) {
                RdcPlatform.silentRefused = true
                Log.i("rdc", "silent update needs confirmation; will ask while the app is open")
                return
            }
            val confirm = if (Build.VERSION.SDK_INT >= 33) {
                intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
            } else {
                @Suppress("DEPRECATION")
                intent.getParcelableExtra(Intent.EXTRA_INTENT)
            }
            confirm?.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)?.let { context.startActivity(it) }
            return
        }
        val message = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE)
        Log.i("rdc", "update install status=$status ${message ?: ""}")
    }
}
