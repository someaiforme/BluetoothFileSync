package com.bluetoothfilesync

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothSocket
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.DocumentsContract
import android.webkit.MimeTypeMap
import android.os.Build
import android.os.Bundle
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.ListView
import android.widget.TextView
import android.widget.EditText
import android.widget.ScrollView
import android.view.View
import android.view.ViewGroup
import android.text.InputType
import androidx.appcompat.app.AlertDialog
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.documentfile.provider.DocumentFile
import java.io.BufferedOutputStream
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.Executors
import java.util.concurrent.Callable
import java.util.concurrent.Future
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.crypto.SecretKey
import javax.crypto.KeyGenerator
import java.security.KeyStore
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.json.JSONObject

class MainActivity : AppCompatActivity() {

    companion object {
        private const val AUTH_KEY_PREF = "bluetoothfilesync_auth_key_v2"
        private const val AUTH_WRAP_ALIAS = "bluetoothfilesync_auth_wrap_v1"
        private const val AUTH_NONCE_BYTES = 32
        private const val MAX_FRAME_BYTES = 1 * 1024 * 1024
        private const val SECURE_NONCE_BYTES = 12
        private const val SECURE_TAG_BYTES = 16
        private const val SECURE_PLAINTEXT_MAX_BYTES =
            MAX_FRAME_BYTES - SECURE_NONCE_BYTES - SECURE_TAG_BYTES
        // Maximum secure payload per transfer frame.
        private const val TRANSFER_CHUNK_BYTES = SECURE_PLAINTEXT_MAX_BYTES
        private const val BLUETOOTHFILESYNC_TEMP_PREFIX = ".bluetoothfilesync-"
        private const val BLUETOOTHFILESYNC_TEMP_SUFFIX = ".part"

        // Persistent diagnostic log. Logging is event-only, never per transfer
        // chunk, and is written from a background executor.
        private const val LOG_FILE_NAME = "bluetoothfilesync.log"
        private const val LOG_BACKUP_FILE_NAME = "bluetoothfilesync.log.1"
        private const val MAX_LOG_BYTES = 256L * 1024L
        private const val MAX_HISTORY_DISPLAY_LINES = 40
    }

    private data class ProtocolIdentity(
        val serviceName: String,
        val serviceUuid: String,
        val protocolVersion: String,
        val rfcommChannel: Int
    )

    private lateinit var protocolIdentity: ProtocolIdentity

    private fun loadProtocolIdentity(): ProtocolIdentity {
        return try {
            val json = resources.openRawResource(R.raw.bluetoothfilesync_protocol)
                .bufferedReader(Charsets.UTF_8)
                .use { it.readText() }
            val obj = JSONObject(json)

            val serviceName = obj.getString("service_name").trim()
            val serviceUuid = obj.getString("service_uuid").trim().lowercase()
            val protocolVersion = obj.getString("protocol_version").trim()
            val rfcommChannel = obj.getInt("rfcomm_channel")

            require(serviceName == "bluetoothfilesync") { "Invalid bluetoothfilesync service name." }
            java.util.UUID.fromString(serviceUuid)
            require(protocolVersion.matches(Regex("[0-9]+"))) {
                "Invalid bluetoothfilesync protocol version."
            }
            require(rfcommChannel in 1..30) {
                "Invalid bluetoothfilesync RFCOMM channel."
            }

            ProtocolIdentity(
                serviceName,
                serviceUuid,
                protocolVersion,
                rfcommChannel
            )
        } catch (e: Exception) {
            throw IllegalStateException(
                "bluetoothfilesync protocol identity is missing or invalid.",
                e
            )
        }
    }

    private val bluetoothEnableLauncher =
        registerForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) {
            if (bluetoothAdapter.isEnabled) {
                if (bluetoothWasInitiallyOff) {
                    bluetoothStartedByBluetoothfilesync = true
                }
                autoConnectToSavedDevice()
            } else {
                setStatus(
                    "● Bluetooth is required for file sync"
                )
            }
        }

    private val syncFolderLauncher =
        registerForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) { result ->

            if (result.resultCode != RESULT_OK) {
                return@registerForActivityResult
            }

            val uri =
                result.data?.data
                    ?: return@registerForActivityResult

            val takeFlags =
                (result.data?.flags ?: 0) and
                (Intent.FLAG_GRANT_READ_URI_PERMISSION or
                 Intent.FLAG_GRANT_WRITE_URI_PERMISSION)

            // A selected sync folder must survive an app restart. Require the
            // provider to grant both read/write persistable access before we
            // save the URI. Otherwise a folder could appear selected during
            // this run but become inaccessible on the next launch.
            if (takeFlags !=
                (Intent.FLAG_GRANT_READ_URI_PERMISSION or
                 Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
            ) {
                setStatus(
                    "● Cannot use that folder\n" +
                    "The storage provider did not grant persistent read/write access."
                )
                return@registerForActivityResult
            }

            try {
                contentResolver.takePersistableUriPermission(
                    uri,
                    takeFlags
                )
            } catch (_: SecurityException) {
                setStatus(
                    "● Cannot use that folder\n" +
                    "Android could not save persistent access to it."
                )
                return@registerForActivityResult
            }

            val persisted =
                contentResolver.persistedUriPermissions.any { permission ->
                    permission.uri == uri &&
                    permission.isReadPermission &&
                    permission.isWritePermission
                }

            if (!persisted) {
                setStatus(
                    "● Cannot use that folder\n" +
                    "Persistent read/write access was not granted."
                )
                return@registerForActivityResult
            }

            val root =
                DocumentFile.fromTreeUri(
                    this,
                    uri
                )

            if (root == null || !root.canRead() || !root.canWrite()) {
                setStatus(
                    "● Cannot use that folder"
                )
                return@registerForActivityResult
            }

            syncFolderUri = uri
            syncRootDocument = root

            getSharedPreferences(
                "bluetoothfilesync",
                Context.MODE_PRIVATE
            ).edit()
                .putString(
                    "sync_folder_uri",
                    uri.toString()
                )
                .apply()

            setStatus(
                "● Sync folder selected:\n" +
                (root.name ?: uri.toString())
            )

            updateSyncFolderView()

            // Folder enumeration and hashing can perform substantial SAF I/O.
            // Do it off the UI thread, then start Auto Sync only after the scan
            // has produced a current local file snapshot.
            refreshLocalFilesAsync(
                reason = "folder_selected"
            ) {
                tryAutoSync()
            }
        }

    private lateinit var bluetoothAdapter: BluetoothAdapter

    private lateinit var deviceAdapter:
        ArrayAdapter<String>

    private lateinit var statusView:
        TextView

    private lateinit var syncFolderView:
        TextView

    private lateinit var syncButton:
        Button

    private lateinit var savedDeviceView:
        TextView

    private lateinit var deviceList:
        ListView

    private lateinit var autoSyncSwitch:
        android.widget.Switch

    private lateinit var historyButton:
        Button

    private lateinit var conflictView:
        TextView

    private lateinit var exitButton:
        Button

    private lateinit var activityScrollView:
        ScrollView

    private val activityLog =
        StringBuilder()

    private val logExecutor =
        Executors.newSingleThreadExecutor()

    // Folder scans/hashes are always serialized on a background executor.
    // UI-triggered scans never perform SAF I/O or SHA-256 work on the main thread.
    private val localScanExecutor =
        Executors.newSingleThreadExecutor()

    @Volatile
    private var localScanInProgress = false

    @Volatile
    private var localFilesReady = false

    @Volatile
    private var localScanGeneration = 0L

    @Volatile
    private var localSnapshotGeneration = 0L

    private var statusScrollPending = false

    // Protects the hand-off between the UI-triggered scan and a sync that
    // starts while that scan is still running.
    private val localScanStateLock = Any()

    @Volatile
    private var localScanFuture: Future<*>? = null

    @Volatile
    private var currentSessionId = "------------"

    private var sessionEndedLogged = false

    private val devices =
        mutableListOf<String>()

    private var receiverRegistered = false

    private val localFiles =
        mutableListOf<SyncFile>()

    private val windowsFiles =
        mutableListOf<SyncFile>()

    private var syncFolderUri:
        Uri? = null

    private var syncRootDocument:
        DocumentFile? = null

    private var bluetoothSocket:
        BluetoothSocket? = null

    private var bluetoothInput:
        InputStream? = null

    private var bluetoothOutput:
        OutputStream? = null

    private var secureChannel:
        SecureChannel? = null

    private val bluetoothLock =
        Any()

    @Volatile
    private var syncInProgress = false

    private var autoSyncStartedThisSession = false
    private var autoConnectInProgress = false

    // Remember whether Bluetooth was OFF when bluetoothfilesync started.
    // If bluetoothfilesync successfully turned it on, we will restore that state
    // after sync where Android permits an application to do so.
    private var bluetoothWasInitiallyOff = false
    private var bluetoothStartedByBluetoothfilesync = false

    private val preferences by lazy {
        getSharedPreferences(
            "bluetoothfilesync",
            Context.MODE_PRIVATE
        )
    }


    private val syncState:
        android.content.SharedPreferences
        by lazy {
            getSharedPreferences(
                "bluetoothfilesync_sync_state",
                Context.MODE_PRIVATE
            )
        }

    private val localHashCache:
        android.content.SharedPreferences
        by lazy {
            getSharedPreferences(
                "bluetoothfilesync_hash_cache",
                Context.MODE_PRIVATE
            )
        }


    // ========================================================
    // FILE MODEL
    // ========================================================

    data class SyncFile(
        val path: String,
        val size: Long,
        val modified: Long,
        val hash: String
    )

    enum class SyncAction {
        SAME,
        UPLOAD,
        DOWNLOAD,
        CONFLICT
    }

    data class SyncResult(
        val path: String,
        val action: SyncAction,
        val details: String
    )

    private data class SyncFileError(
        val path: String,
        val action: String,
        val message: String
    )

    // A Bluetooth/protocol I/O failure means the command stream may no longer
    // be at a safe command boundary. These failures must still abort the
    // session; ordinary per-file failures are isolated and recorded below.
    private class SyncTransportException(
        message: String,
        cause: Throwable? = null
    ) : Exception(message, cause)


    // ========================================================
    // BLUETOOTH DISCOVERY
    // ========================================================

    private val receiver =
        object : BroadcastReceiver() {

            @SuppressLint("MissingPermission")
            override fun onReceive(
                context: Context,
                intent: Intent
            ) {

                when (intent.action) {

                    BluetoothDevice.ACTION_FOUND -> {

                        val device =
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                                intent.getParcelableExtra(
                                    BluetoothDevice.EXTRA_DEVICE,
                                    BluetoothDevice::class.java
                                )
                            } else {
                                @Suppress("DEPRECATION")
                                intent.getParcelableExtra<BluetoothDevice>(
                                    BluetoothDevice.EXTRA_DEVICE
                                )
                            }

                        device?.let {

                            val name =
                                it.name
                                    ?: "Unknown device"

                            val address =
                                it.address

                            val entry =
                                "$name\n$address"

                            if (
                                !devices.contains(entry)
                            ) {

                                devices.add(entry)

                                deviceAdapter
                                    .notifyDataSetChanged()
                            }

                            val savedAddress =
                                preferences.getString(
                                    "last_device_address",
                                    null
                                )

                            if (
                                bluetoothSocket == null &&
                                savedAddress != null &&
                                savedAddress.equals(
                                    address,
                                    ignoreCase = true
                                )
                            ) {
                                connectBluetoothDevice(
                                    it,
                                    true
                                )
                            }
                        }
                    }

                    BluetoothAdapter.ACTION_DISCOVERY_FINISHED -> {

                        if (
                            devices.isEmpty()
                        ) {

                            setStatus(
                                "● Scan complete — no devices found"
                            )

                        } else {

                            setStatus(
                                "● Scan complete — " +
                                "${devices.size} device(s) found"
                            )
                        }
                    }
                }
            }
        }


    // ========================================================
    // ON CREATE
    // ========================================================

    override fun onCreate(
        savedInstanceState: Bundle?
    ) {

        super.onCreate(
            savedInstanceState
        )

        protocolIdentity = loadProtocolIdentity()
        logEvent("APP_STARTED", "service=${protocolIdentity.serviceName} uuid=${protocolIdentity.serviceUuid} version=${protocolIdentity.protocolVersion} rfcomm=${protocolIdentity.rfcommChannel}")

        setContentView(
            R.layout.activity_main
        )

        statusView =
            findViewById(
                R.id.statusView
            )

        activityScrollView =
            findViewById(
                R.id.activityScrollView
            )

        statusView.text = ""
        setStatus("● Starting Bluetooth...")

        // The Activity log is intentionally independently scrollable. Prevent the
        // outer page NestedScrollView from stealing vertical gestures from it.
        activityScrollView.setOnTouchListener { view, event ->
            when (event.actionMasked) {
                android.view.MotionEvent.ACTION_DOWN,
                android.view.MotionEvent.ACTION_MOVE -> {
                    view.parent?.requestDisallowInterceptTouchEvent(true)
                }
                android.view.MotionEvent.ACTION_UP,
                android.view.MotionEvent.ACTION_CANCEL -> {
                    view.parent?.requestDisallowInterceptTouchEvent(false)
                }
            }
            false
        }

        val scanButton =
            findViewById<Button>(
                R.id.scanButton
            )

        syncFolderView =
            findViewById(
                R.id.syncFolderView
            )

        savedDeviceView =
            findViewById(
                R.id.savedDeviceView
            )

        autoSyncSwitch =
            findViewById(
                R.id.autoSyncSwitch
            )

        historyButton =
            findViewById(
                R.id.historyButton
            )

        conflictView =
            findViewById(
                R.id.conflictView
            )

        exitButton =
            findViewById(
                R.id.exitButton
            )

        conflictView.text = ""
        // Keep the conflict card hidden until there is an actual conflict.
        conflictView.visibility = View.GONE

        // EXIT is always available, including when a transfer is stuck or failed.
        exitButton.visibility = android.view.View.VISIBLE
        exitButton.setOnClickListener {
            syncInProgress = false
            closeBluetoothConnection()
            finishAndRemoveTask()
        }

        val forgetDeviceButton =
            findViewById<Button>(
                R.id.forgetDeviceButton
            )

        forgetDeviceButton.setOnClickListener {
            if (!hasSavedDevice()) {
                setStatus("● No saved device to forget")
                return@setOnClickListener
            }

            AlertDialog.Builder(this)
                .setTitle("Forget device?")
                .setMessage(
                    "This removes the saved bluetoothfilesync device and clears its authentication " +
                    "key. The Android Bluetooth pairing itself can be removed from Android " +
                    "Bluetooth settings if needed. To pair with this Windows computer again, " +
                    "the Windows server may need --authorize-new-device."
                )
                .setNegativeButton("CANCEL", null)
                .setPositiveButton("FORGET") { _, _ ->
                    closeBluetoothConnection()

                    preferences.edit()
                        .remove("last_device_address")
                        .remove("last_device_name")
                        .remove(AUTH_KEY_PREF)
                        .apply()

                    autoSyncStartedThisSession = false
                    updateSavedDeviceView()
                    updateDeviceSelectionUi()
                    devices.clear()
                    deviceAdapter.notifyDataSetChanged()
                    setStatus(
                        "● Device forgotten from bluetoothfilesync"
                    )
                }
                .show()
        }

        val chooseFolderButton =
            findViewById<Button>(
                R.id.chooseFolderButton
            )


        syncButton =
            findViewById(
                R.id.syncButton
            )


        deviceList =
            findViewById(
                R.id.deviceList
            )
        val bluetoothManager =
            getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager

        bluetoothAdapter =
            bluetoothManager.adapter
                ?: run {
                    setStatus(
                        "● This device does not support Bluetooth"
                    )
                    return
                }

        // Capture the Bluetooth state before bluetoothfilesync does anything to it.
        bluetoothWasInitiallyOff = !bluetoothAdapter.isEnabled
        bluetoothStartedByBluetoothfilesync = false

        initializeSyncFolder()
        updateSyncFolderView()
        updateSavedDeviceView()
        updateDeviceSelectionUi()


        // ====================================================
        // DEVICE LIST
        // ====================================================

        deviceAdapter =
            object : ArrayAdapter<String>(
                this,
                R.layout.device_list_item,
                devices
            ) {
                override fun getView(
                    position: Int,
                    convertView: View?,
                    parent: ViewGroup
                ): View {
                    val row =
                        convertView
                            ?: layoutInflater.inflate(
                                R.layout.device_list_item,
                                parent,
                                false
                            )

                    val value =
                        getItem(position).orEmpty()

                    val parts =
                        value.split("\n", limit = 2)

                    row.findViewById<TextView>(R.id.deviceName).text =
                        parts.firstOrNull().orEmpty()

                    row.findViewById<TextView>(R.id.deviceAddress).text =
                        parts.getOrNull(1).orEmpty()

                    return row
                }
            }

        deviceList.adapter =
            deviceAdapter

        // Show the selector only while no bluetoothfilesync device is saved.
        // Once a device is successfully selected/trusted, the list collapses
        // and the compact saved-device row remains.
        updateDeviceSelectionUi()

        // The device list lives inside the main ScrollView. Keep touch
        // gestures on the list itself so the list can scroll independently
        // when many Bluetooth devices are discovered.
        deviceList.setOnTouchListener { view, event ->
            when (event.actionMasked) {
                android.view.MotionEvent.ACTION_DOWN,
                android.view.MotionEvent.ACTION_MOVE -> {
                    // Keep the outer page from stealing a vertical swipe meant
                    // for the device list.  The ListView must retain the gesture
                    // so it can scroll through multiple discovered devices.
                    view.parent?.requestDisallowInterceptTouchEvent(true)
                }

                android.view.MotionEvent.ACTION_UP,
                android.view.MotionEvent.ACTION_CANCEL -> {
                    view.parent?.requestDisallowInterceptTouchEvent(false)
                }
            }
            false
        }

        // ====================================================
        // RECEIVER
        // ====================================================

        registerReceiver(
            receiver,
            IntentFilter().apply {

                addAction(
                    BluetoothDevice.ACTION_FOUND
                )

                addAction(
                    BluetoothAdapter.ACTION_DISCOVERY_FINISHED
                )
            },
            Context.RECEIVER_EXPORTED
        )
        receiverRegistered = true


        // ====================================================
        // BUTTONS
        // ====================================================

        scanButton.text = "CHANGE DEVICE"
        scanButton.setOnClickListener {

            preferences.edit()
                .remove("last_device_address")
                .remove("last_device_name")
                .remove(AUTH_KEY_PREF)
                .apply()

            updateSavedDeviceView()
            updateDeviceSelectionUi()
            autoSyncStartedThisSession = false
            startBluetoothScan()
        }

        chooseFolderButton.setOnClickListener {
            autoSyncStartedThisSession = false
            chooseSyncFolder()
        }

        autoSyncSwitch.isChecked = isAutoSyncEnabled()
        autoSyncSwitch.setOnCheckedChangeListener { _, enabled ->
            preferences.edit()
                .putBoolean("auto_sync_enabled", enabled)
                .apply()

            if (enabled) {
                autoSyncStartedThisSession = false
                logEvent("AUTO_SYNC_ENABLED")
                setStatus("● Auto Sync enabled")
                tryAutoSync()
            } else {
                logEvent("AUTO_SYNC_DISABLED")
                setStatus("● Auto Sync disabled")
            }
        }

        historyButton.setOnClickListener {
            showSyncHistory()
        }


        syncButton.setOnClickListener {

            if (syncInProgress) {
                return@setOnClickListener
            }

            if (localScanInProgress || !localFilesReady) {
                setStatus(
                    "● Sync folder is still being scanned — please try again in a moment"
                )
                return@setOnClickListener
            }

            if (bluetoothSocket?.isConnected == true) {
                performSync()
            } else {
                setStatus(
                    "● Bluetooth connection is not active"
                )
                ensureBluetoothReady()
            }
        }


        // ====================================================
        // DEVICE SELECTION
        // ====================================================

        deviceList.setOnItemClickListener {
                _, _, position, _ ->

            connectToDevice(
                devices[position]
            )
        }


        refreshLocalFilesAsync(
            reason = "startup"
        ) {
            tryAutoSync()
        }

        ensureBluetoothReady()
    }


    // ========================================================
    // STATUS
    // ========================================================

    private fun setStatus(
        message: String
    ) {

        runOnUiThread {

            val cleaned = message.trim()

            if (cleaned.isNotEmpty()) {
                // Avoid logging the same status repeatedly when Android
                // delivers duplicate discovery/lifecycle broadcasts.
                val logText = activityLog.toString()
                val lastLine = logText.substringAfterLast("\n")
                if (lastLine != cleaned) {
                    if (activityLog.isNotEmpty()) {
                        activityLog.append("\n")
                    }
                    activityLog.append(cleaned)
                }

                // Activity is intentionally in-memory only. Persistent logging
                // is event-only and is never performed from transfer loops.
                val maxChars = 16000
                if (activityLog.length > maxChars) {
                    activityLog.delete(0, activityLog.length - maxChars)
                    val firstNewline = activityLog.indexOf("\n")
                    if (firstNewline >= 0) {
                        activityLog.delete(0, firstNewline + 1)
                    }
                }
            }

            statusView.text =
                activityLog.toString()

            // Coalesce rapid status updates into one scroll operation. This
            // avoids posting a full layout/scroll pass for every diagnostic
            // message during discovery, authentication, and sync.
            if (!statusScrollPending) {
                statusScrollPending = true
                activityScrollView.postDelayed(
                    {
                        statusScrollPending = false
                        activityScrollView.fullScroll(
                            View.FOCUS_DOWN
                        )
                    },
                    100L
                )
            }
        }
    }


    // ========================================================
    // PERSISTENT LOGGING
    // ========================================================

    private fun newSessionId(): String =
        java.util.UUID.randomUUID()
            .toString()
            .replace("-", "")
            .take(12)
            .uppercase(java.util.Locale.US)

    private fun logEvent(
        event: String,
        detail: String? = null
    ) {
        val timestamp =
            java.text.SimpleDateFormat(
                "yyyy-MM-dd'T'HH:mm:ss.SSS",
                java.util.Locale.US
            ).format(java.util.Date())

        val safeDetail = detail
            ?.replace("\r", " ")
            ?.replace("\n", " ")
            ?.trim()
            ?.take(500)

        val line = buildString {
            append(timestamp)
            append(" | session=")
            append(currentSessionId)
            append(" | ")
            append(event)
            if (!safeDetail.isNullOrEmpty()) {
                append(" | ")
                append(safeDetail)
            }
        }

        // Persistent log I/O is explicitly kept off the Bluetooth/data-transfer
        // thread. The sync path never calls this for individual chunks.
        try {
            logExecutor.execute {
                appendPersistentLogLine(line)
            }
        } catch (_: java.util.concurrent.RejectedExecutionException) {
            // App is shutting down; diagnostic logging must never delay sync.
        }
    }

    private fun appendPersistentLogLine(line: String) {
        try {
            val logFile = File(filesDir, LOG_FILE_NAME)
            val backupFile = File(filesDir, LOG_BACKUP_FILE_NAME)
            val data = (line + "\n").toByteArray(Charsets.UTF_8)

            if (logFile.exists() &&
                logFile.length() + data.size > MAX_LOG_BYTES
            ) {
                if (backupFile.exists()) {
                    backupFile.delete()
                }
                if (!logFile.renameTo(backupFile)) {
                    return
                }
            }

            java.io.FileOutputStream(logFile, true).use { output ->
                output.write(data)
                output.flush()
            }
        } catch (_: Exception) {
            // Diagnostic logging must never interfere with syncing.
        }
    }

    private fun readPersistentHistory(): List<String> {
        return try {
            val backup = File(filesDir, LOG_BACKUP_FILE_NAME)
            val current = File(filesDir, LOG_FILE_NAME)
            val combined = mutableListOf<String>()

            if (backup.isFile) {
                combined.addAll(backup.readLines(Charsets.UTF_8))
            }
            if (current.isFile) {
                combined.addAll(current.readLines(Charsets.UTF_8))
            }

            combined.filter { it.isNotBlank() }
                .takeLast(MAX_HISTORY_DISPLAY_LINES)
        } catch (_: Exception) {
            emptyList()
        }
    }


    // ========================================================
    // LOCAL FILES
    // ========================================================

    private fun hasPersistedSyncFolderPermission(
        uri: Uri
    ): Boolean {
        return contentResolver.persistedUriPermissions.any { permission ->
            permission.uri == uri &&
            permission.isReadPermission &&
            permission.isWritePermission
        }
    }


    private fun initializeSyncFolder() {

        val preferences =
            getSharedPreferences(
                "bluetoothfilesync",
                Context.MODE_PRIVATE
            )

        val savedUri =
            preferences.getString(
                "sync_folder_uri",
                null
            )

        if (savedUri != null) {
            try {
                val uri = Uri.parse(savedUri)
                val root = DocumentFile.fromTreeUri(this, uri)
                if (
                    hasPersistedSyncFolderPermission(uri) &&
                    root != null &&
                    root.canRead() &&
                    root.canWrite()
                ) {
                    syncFolderUri = uri
                    syncRootDocument = root
                    return
                }
            } catch (_: Exception) {
            }
        }

        val defaultDir =
            File(
                filesDir,
                "bluetoothfilesync"
            )

        if (!defaultDir.exists()) {
            defaultDir.mkdirs()
        }

        syncFolderUri = null
        syncRootDocument = DocumentFile.fromFile(defaultDir)
    }


    private fun updateSyncFolderView() {

        syncFolderView.text =
            "Sync folder:\n${getSyncFolderDisplayPath()}"
    }


    private fun chooseSyncFolder() {

        val intent =
            Intent(
                Intent.ACTION_OPEN_DOCUMENT_TREE
            ).apply {
                addFlags(
                    Intent.FLAG_GRANT_READ_URI_PERMISSION or
                    Intent.FLAG_GRANT_WRITE_URI_PERMISSION or
                    Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION or
                    Intent.FLAG_GRANT_PREFIX_URI_PERMISSION
                )
            }

        syncFolderLauncher.launch(intent)
    }


    private fun getSyncFolderDisplayPath(): String {
        val uri = syncFolderUri

        if (uri == null) {
            return File(
                filesDir,
                "bluetoothfilesync"
            ).absolutePath
        }

        return try {
            val documentId =
                DocumentsContract.getTreeDocumentId(uri)

            when {
                documentId.startsWith("raw:", ignoreCase = true) -> {
                    Uri.decode(
                        documentId.substringAfter(":")
                    )
                }

                documentId.startsWith("primary:", ignoreCase = true) -> {
                    val relative = Uri.decode(
                        documentId.substringAfter(":")
                    ).trimStart('/')

                    if (relative.isBlank()) {
                        "/storage/emulated/0"
                    } else {
                        "/storage/emulated/0/$relative"
                    }
                }

                ":" in documentId -> {
                    val separator = documentId.indexOf(':')
                    val volume = documentId.substring(0, separator)
                    val relative = Uri.decode(
                        documentId.substring(separator + 1)
                    ).trimStart('/')

                    if (relative.isBlank()) {
                        "/storage/$volume"
                    } else {
                        "/storage/$volume/$relative"
                    }
                }

                else -> uri.toString()
            }
        } catch (_: Exception) {
            uri.toString()
        }
    }


    private fun localDocument(
        relativePath: String
    ): DocumentFile? {

        var current = syncRootDocument
            ?: return null

        if (relativePath.isBlank()) {
            return current
        }

        for (part in relativePath.split('/')) {
            current =
                current.findFile(part)
                    ?: return null
        }

        return current
    }


    private fun ensureLocalDirectory(
        relativeDirectory: String
    ): DocumentFile {

        var current =
            syncRootDocument
                ?: throw Exception("Sync folder is not available.")

        if (relativeDirectory.isBlank()) {
            return current
        }

        for (part in relativeDirectory.split('/')) {
            current =
                current.findFile(part)?.takeIf { it.isDirectory }
                    ?: current.createDirectory(part)
                    ?: throw Exception("Could not create directory: $part")
        }

        return current
    }


    private fun scanLocalFiles(
        root: DocumentFile,
        hashStateKey: String
    ): ArrayList<SyncFile> {
        val scannedFiles =
            ArrayList<SyncFile>()

        scanDirectory(
            root,
            "",
            scannedFiles,
            hashStateKey
        )

        scannedFiles.sortBy {
            it.path.lowercase()
        }

        return scannedFiles
    }


    private fun refreshLocalFilesBlocking(
        reusePreparedSnapshot: Boolean = false
    ) {
        val root =
            syncRootDocument
                ?: throw Exception("Sync folder is not available.")

        // Auto Sync can safely reuse the scan that just completed during
        // startup/folder selection. This avoids immediately hashing the same
        // Android folder a second time after "Local file scan complete".
        val currentGeneration = synchronized(localFiles) { localScanGeneration }
        if (reusePreparedSnapshot &&
            localFilesReady &&
            !localScanInProgress &&
            localSnapshotGeneration == currentGeneration
        ) {
            val count = synchronized(localFiles) { localFiles.size }
            logEvent(
                "LOCAL_SCAN_REUSED",
                "reason=auto_sync_prepared_snapshot files=$count"
            )
            return
        }

        // Reuse an in-progress UI-triggered scan rather than queueing a second
        // SAF enumeration/hash pass behind it. This is the main optimization
        // for the "Preparing sync..." delay seen immediately after startup or
        // folder selection.
        val runningFuture = synchronized(localScanStateLock) {
            if (localScanInProgress) localScanFuture else null
        }

        if (runningFuture != null) {
            logEvent(
                "LOCAL_SCAN_WAIT",
                "reason=sync_waiting_for_existing_scan"
            )

            try {
                runningFuture.get()
            } catch (e: java.util.concurrent.ExecutionException) {
                val cause = e.cause ?: e
                if (cause is Exception) {
                    throw cause
                }
                throw Exception(
                    cause.message ?: cause.javaClass.simpleName,
                    cause
                )
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                throw Exception(
                    "Local file scan was interrupted.",
                    e
                )
            }

            if (!localFilesReady) {
                throw Exception(
                    "Local file scan did not complete successfully."
                )
            }

            val count = synchronized(localFiles) { localFiles.size }
            logEvent(
                "LOCAL_SCAN_REUSED",
                "reason=sync_used_existing_scan files=$count"
            )
            // The caller immediately reports the next sync phase; avoid an
            // extra UI status transition here.
            return
        }

        // No scan is running, so an explicit sync gets a fresh snapshot.
        localFilesReady = false

        val hashStateKey = syncStateFolderKey()
        val generation = synchronized(localFiles) { localScanGeneration }

        setStatus(
            "● Scanning local files..."
        )
        logEvent(
            "LOCAL_SCAN_STARTED",
            "reason=sync_refresh"
        )

        val future = localScanExecutor.submit(
            Callable<ArrayList<SyncFile>> {
                val startedAt = System.nanoTime()
                val scannedFiles = scanLocalFiles(root, hashStateKey)
                val durationMs =
                    (System.nanoTime() - startedAt) / 1_000_000L
                logEvent(
                    "LOCAL_SCAN_FINISHED",
                    "files=${scannedFiles.size} duration_ms=$durationMs mode=sync"
                )
                scannedFiles
            }
        )

        val scannedFiles = try {
            future.get()
        } catch (e: java.util.concurrent.ExecutionException) {
            val cause = e.cause ?: e
            if (cause is Exception) {
                throw cause
            }
            throw Exception(
                cause.message ?: cause.javaClass.simpleName,
                cause
            )
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            throw Exception(
                "Local file scan was interrupted.",
                e
            )
        }

        val stillCurrent = synchronized(localFiles) {
            generation == localScanGeneration
        }

        if (!stillCurrent) {
            throw Exception(
                "Sync folder changed while preparing sync."
            )
        }

        synchronized(localFiles) {
            localFiles.clear()
            localFiles.addAll(scannedFiles)
        }

        localFilesReady = true
        localSnapshotGeneration = generation
        setStatus(
            "● Local files ready — ${scannedFiles.size} file(s)"
        )
    }


    private fun refreshLocalFilesAsync(
        reason: String,
        afterScan: (() -> Unit)? = null
    ) {
        val generation = synchronized(localFiles) {
            localScanGeneration += 1L
            localScanGeneration
        }

        val root = syncRootDocument

        if (root == null) {
            synchronized(localScanStateLock) {
                localScanInProgress = false
                localScanFuture = null
            }
            localFilesReady = false
            setStatus("● Sync folder is not available")
            return
        }

        val hashStateKey = syncStateFolderKey()

        synchronized(localScanStateLock) {
            localScanInProgress = true
            localFilesReady = false
        }

        setStatus(
            if (reason == "startup") {
                "● Scanning sync folder..."
            } else {
                "● Scanning sync folder after selection..."
            }
        )

        logEvent(
            "LOCAL_SCAN_STARTED",
            "reason=$reason"
        )

        // submit() returns the Future immediately. Publish it under the same
        // lock used by performSync() so a sync cannot observe 'in progress'
        // without also seeing the Future it must wait for.
        val future = synchronized(localScanStateLock) {
            val submitted = localScanExecutor.submit {
                val startedAt = System.nanoTime()

                try {
                    val scannedFiles = scanLocalFiles(root, hashStateKey)

                    val shouldPublish = synchronized(localFiles) {
                        generation == localScanGeneration
                    }

                    if (shouldPublish) {
                        synchronized(localFiles) {
                            localFiles.clear()
                            localFiles.addAll(scannedFiles)
                        }
                        localFilesReady = true
                        localSnapshotGeneration = generation
                    }

                    val durationMs =
                        (System.nanoTime() - startedAt) / 1_000_000L

                    logEvent(
                        "LOCAL_SCAN_FINISHED",
                        "files=${scannedFiles.size} duration_ms=$durationMs reason=$reason"
                    )

                    if (shouldPublish) {
                        setStatus(
                            "● Local file scan complete — ${scannedFiles.size} file(s)"
                        )
                    }

                    // Run follow-up lifecycle/auto-sync work only after the
                    // scan state has been marked complete below.
                    if (shouldPublish) {
                        synchronized(localScanStateLock) {
                            localScanInProgress = false
                        }
                        afterScan?.invoke()
                    }
                } catch (e: Exception) {
                    val shouldPublish = synchronized(localFiles) {
                        generation == localScanGeneration
                    }

                    if (shouldPublish) {
                        localFilesReady = false
                        setStatus(
                            "● Could not scan sync folder:\n" +
                                (e.message ?: e.javaClass.simpleName)
                        )
                        logEvent(
                            "LOCAL_SCAN_FAILED",
                            e.message ?: e.javaClass.simpleName
                        )
                    }

                    synchronized(localScanStateLock) {
                        if (shouldPublish) {
                            localScanInProgress = false
                        }
                    }
                }
            }

            localScanFuture = submitted
            submitted
        }

        // Keep the local reference live for clarity and future diagnostics.
        // The state lock retains the same Future for performSync().
        if (future.isCancelled) {
            synchronized(localScanStateLock) {
                if (generation == localScanGeneration) {
                    localScanInProgress = false
                    localFilesReady = false
                }
            }
        }
    }


    private fun scanDirectory(
        directory: DocumentFile,
        prefix: String,
        destination: MutableList<SyncFile>,
        hashStateKey: String
    ) {

        for (child in directory.listFiles()) {

            val name =
                child.name
                    ?: continue

            val isReservedRootDirectory =
                prefix.isEmpty() &&
                    (name.equals("Backups", ignoreCase = true) ||
                     name.equals("Conflicts", ignoreCase = true) ||
                     name.equals("SyncHistory", ignoreCase = true))

            if (isReservedRootDirectory ||
                isBluetoothfilesyncTempName(name)
            ) {
                continue
            }

            val path =
                if (prefix.isEmpty()) name else "$prefix/$name"

            if (child.isDirectory) {
                scanDirectory(
                    child,
                    path,
                    destination,
                    hashStateKey
                )
            } else if (child.isFile) {
                destination.add(
                    SyncFile(
                        path,
                        child.length(),
                        child.lastModified(),
                        localHashForDocument(
                            path,
                            child,
                            hashStateKey
                        )
                    )
                )
            }
        }
    }


    private fun isBluetoothfilesyncTempName(name: String): Boolean {
        if (!name.startsWith(BLUETOOTHFILESYNC_TEMP_PREFIX) ||
            !name.endsWith(BLUETOOTHFILESYNC_TEMP_SUFFIX)
        ) {
            return false
        }
        val token = name.substring(
            BLUETOOTHFILESYNC_TEMP_PREFIX.length,
            name.length - BLUETOOTHFILESYNC_TEMP_SUFFIX.length
        )
        return token.length == 32 && token.all { it in "0123456789abcdef" }
    }


    private fun newBluetoothfilesyncTempName(): String {
        return BLUETOOTHFILESYNC_TEMP_PREFIX +
            java.util.UUID.randomUUID().toString().replace("-", "") +
            BLUETOOTHFILESYNC_TEMP_SUFFIX
    }


    private fun ensureBluetoothReady() {

        if (!bluetoothPermissionsGranted()) {
            requestBluetoothPermissions()
            return
        }

        if (!bluetoothAdapter.isEnabled) {

            setStatus(
                "● Turning Bluetooth on..."
            )

            @Suppress("DEPRECATION")
            bluetoothEnableLauncher.launch(
                Intent(
                    BluetoothAdapter.ACTION_REQUEST_ENABLE
                )
            )

            return
        }

        autoConnectToSavedDevice()
    }


    @SuppressLint("MissingPermission")
    private fun autoConnectToSavedDevice() {

        if (!bluetoothPermissionsGranted()) {
            requestBluetoothPermissions()
            return
        }

        if (!bluetoothAdapter.isEnabled) {
            ensureBluetoothReady()
            return
        }

        val preferences =
            getSharedPreferences(
                "bluetoothfilesync",
                Context.MODE_PRIVATE
            )

        val savedAddress =
            preferences.getString(
                "last_device_address",
                null
            )

        val bonded =
            bluetoothAdapter.bondedDevices

        val savedDevice =
            savedAddress?.let { address ->
                bonded.firstOrNull {
                    it.address.equals(
                        address,
                        ignoreCase = true
                    )
                }
            }

        if (savedDevice != null) {
            connectBluetoothDevice(savedDevice, true)
            return
        }

        if (bonded.size == 1) {
            connectBluetoothDevice(bonded.first(), true)
            return
        }

        setStatus(
            if (bonded.isEmpty()) {
                "● Bluetooth on — no paired device found"
            } else {
                "● Bluetooth on — choose a device below"
            }
        )
    }


    @SuppressLint("MissingPermission")
    private fun connectBluetoothDevice(
        device: BluetoothDevice,
        automatic: Boolean
    ) {

        if (automatic) {
            if (autoConnectInProgress) {
                return
            }
            autoConnectInProgress = true
        }

        closeBluetoothConnection()

        currentSessionId = newSessionId()
        sessionEndedLogged = false
        logEvent(
            "SESSION_STARTED",
            if (automatic) "mode=automatic" else "mode=manual"
        )

        setStatus(
            if (automatic) {
                "● Auto-connecting to ${device.name ?: device.address}..."
            } else {
                "● Connecting to ${device.name ?: device.address}..."
            }
        )

        Thread {
            try {
                val socket = device.createRfcommSocketToServiceRecord(
                    java.util.UUID.fromString(protocolIdentity.serviceUuid)
                )

                if (bluetoothAdapter.isDiscovering) {
                    bluetoothAdapter.cancelDiscovery()
                }

                socket.connect()

                bluetoothSocket = socket
                bluetoothInput = socket.inputStream
                bluetoothOutput = BufferedOutputStream(
                    socket.outputStream,
                    TRANSFER_CHUNK_BYTES
                )

                logEvent(
                    "SESSION_CONNECTED",
                    "device=${device.name ?: device.address}"
                )

                synchronized(bluetoothLock) {
                    secureChannel = authenticateWithWindows(device)

                    preferences.edit()
                        .putString("last_device_address", device.address)
                        .putString("last_device_name", device.name ?: device.address)
                        .apply()
                }

                runOnUiThread { syncButton.isEnabled = true }
                runOnUiThread {
                    updateSavedDeviceView()
                    updateDeviceSelectionUi()
                }

                setStatus("● Securely connected — ready to sync")
                tryAutoSync()

            } catch (e: Exception) {
                logEvent("SESSION_FAILED", e.message ?: e.javaClass.simpleName)
                closeBluetoothConnection()
                setStatus(
                    if (automatic) {
                        "● Auto-connect failed — choose a device below\\n" +
                            "${e.message}"
                    } else {
                        "● Connection failed:\\n" +
                            "${e.javaClass.simpleName}\\n" +
                            "${e.message}"
                    }
                )
            } finally {
                if (automatic) {
                    autoConnectInProgress = false
                }
            }
        }.start()
    }



    // ========================================================
    // ENCRYPTED CHANNEL (post-authentication)
    // ========================================================

    private fun concatBytes(vararg parts: ByteArray): ByteArray {
        var total = 0
        for (part in parts) total += part.size
        val result = ByteArray(total)
        var offset = 0
        for (part in parts) {
            System.arraycopy(part, 0, result, offset, part.size)
            offset += part.size
        }
        return result
    }

    private fun counterBytes(counter: Long): ByteArray {
        require(counter >= 0L) { "Invalid secure-channel counter." }
        return ByteBuffer.allocate(8)
            .order(ByteOrder.BIG_ENDIAN)
            .putLong(counter)
            .array()
    }

    private fun secureNonce(counter: Long): ByteArray {
        return concatBytes(byteArrayOf(0, 0, 0, 0), counterBytes(counter))
    }

    private fun secureAad(direction: String, counter: Long): ByteArray {
        return concatBytes(
            "bluetoothfilesync-v${protocolIdentity.protocolVersion}|$direction|".toByteArray(Charsets.UTF_8),
            counterBytes(counter)
        )
    }

    private fun hkdfSha256(
        inputKeyMaterial: ByteArray,
        salt: ByteArray,
        info: ByteArray,
        length: Int
    ): ByteArray {
        require(length > 0) { "HKDF output length must be positive." }
        val actualSalt = if (salt.isEmpty()) ByteArray(32) else salt
        val prk = hmacSha256(actualSalt, inputKeyMaterial)
        val result = ByteArray(length)
        var previous = ByteArray(0)
        var written = 0
        var blockNumber = 1

        while (written < length) {
            require(blockNumber <= 255) { "HKDF output too large." }
            previous = hmacSha256(
                prk,
                concatBytes(previous, info, byteArrayOf(blockNumber.toByte()))
            )
            val count = minOf(previous.size, length - written)
            System.arraycopy(previous, 0, result, written, count)
            written += count
            blockNumber++
        }
        return result
    }

    private inner class SecureChannel(
        authKey: ByteArray,
        sessionNonce: ByteArray,
        isServer: Boolean
    ) {
        private val encryptor: Cipher
        private val decryptor: Cipher
        private val encryptKey: SecretKeySpec
        private val decryptKey: SecretKeySpec
        private val encryptDirection: String
        private val decryptDirection: String
        private var sendCounter = 0L
        private var receiveCounter = 0L

        init {
            require(authKey.size == 32) { "Authentication key must be 32 bytes." }
            require(sessionNonce.size == AUTH_NONCE_BYTES) { "Session nonce must be 32 bytes." }

            val c2sKey = hkdfSha256(
                authKey,
                sessionNonce,
                "bluetoothfilesync c2s v${protocolIdentity.protocolVersion}".toByteArray(Charsets.UTF_8),
                32
            )
            val s2cKey = hkdfSha256(
                authKey,
                sessionNonce,
                "bluetoothfilesync s2c v${protocolIdentity.protocolVersion}".toByteArray(Charsets.UTF_8),
                32
            )

            if (isServer) {
                encryptKey = SecretKeySpec(s2cKey, "AES")
                encryptDirection = "s2c"
                decryptKey = SecretKeySpec(c2sKey, "AES")
                decryptDirection = "c2s"
            } else {
                encryptKey = SecretKeySpec(c2sKey, "AES")
                encryptDirection = "c2s"
                decryptKey = SecretKeySpec(s2cKey, "AES")
                decryptDirection = "s2c"
            }

            encryptor = Cipher.getInstance("AES/GCM/NoPadding")
            decryptor = Cipher.getInstance("AES/GCM/NoPadding")
        }

        fun encrypt(plaintext: ByteArray): ByteArray {
            return encrypt(plaintext, 0, plaintext.size)
        }

        fun encrypt(plaintext: ByteArray, offset: Int, length: Int): ByteArray {
            require(offset >= 0 && length >= 0 && offset + length <= plaintext.size)
            require(length <= SECURE_PLAINTEXT_MAX_BYTES) {
                "Secure payload too large: $length bytes."
            }
            if (sendCounter == Long.MAX_VALUE) {
                throw IllegalStateException("Secure-channel frame counter exhausted.")
            }
            val counter = sendCounter
            val nonce = secureNonce(counter)
            val aad = secureAad(encryptDirection, counter)
            encryptor.init(
                Cipher.ENCRYPT_MODE,
                encryptKey,
                GCMParameterSpec(128, nonce)
            )
            encryptor.updateAAD(aad)
            val ciphertext = encryptor.doFinal(plaintext, offset, length)
            sendCounter++
            return concatBytes(nonce, ciphertext)
        }

        fun decrypt(framed: ByteArray): ByteArray {
            if (framed.size < SECURE_NONCE_BYTES + SECURE_TAG_BYTES) {
                throw java.io.IOException("Encrypted frame too short.")
            }
            if (framed.size > MAX_FRAME_BYTES) {
                throw java.io.IOException("Encrypted frame too large.")
            }

            val nonce = framed.copyOfRange(0, SECURE_NONCE_BYTES)
            if (nonce[0].toInt() != 0 ||
                nonce[1].toInt() != 0 ||
                nonce[2].toInt() != 0 ||
                nonce[3].toInt() != 0
            ) {
                throw java.io.IOException("Invalid secure-channel nonce.")
            }

            val counter = ByteBuffer.wrap(nonce, 4, 8)
                .order(ByteOrder.BIG_ENDIAN)
                .long
            if (counter != receiveCounter) {
                throw java.io.IOException(
                    "Unexpected secure-channel frame counter: " +
                        "$counter; expected $receiveCounter."
                )
            }

            val ciphertext = framed.copyOfRange(SECURE_NONCE_BYTES, framed.size)
            val aad = secureAad(decryptDirection, counter)

            return try {
                decryptor.init(
                    Cipher.DECRYPT_MODE,
                    decryptKey,
                    GCMParameterSpec(128, nonce)
                )
                decryptor.updateAAD(aad)
                val plaintext = decryptor.doFinal(ciphertext)
                receiveCounter++
                plaintext
            } catch (e: Exception) {
                throw java.io.IOException(
                    "Encrypted frame authentication failed.",
                    e
                )
            }
        }
    }


    // ========================================================
    // APPLICATION AUTHENTICATION
    // ========================================================

    private fun hmacSha256(key: ByteArray, message: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(message)
    }

    private fun hex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }

    private fun fromHex(value: String): ByteArray {
        require(value.length % 2 == 0) { "Invalid hex data" }
        return ByteArray(value.length / 2) { i ->
            value.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    private fun getOrCreateAuthWrapKey(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val existing = ks.getKey(AUTH_WRAP_ALIAS, null)
        if (existing is SecretKey) return existing

        val generator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            "AndroidKeyStore"
        )
        generator.init(
            KeyGenParameterSpec.Builder(
                AUTH_WRAP_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build()
        )
        return generator.generateKey()
    }

    private fun storeAuthKey(rawKey: ByteArray) {
        val key = getOrCreateAuthWrapKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        // Android Keystore generates the GCM IV for us. Passing a caller-supplied
        // IV while encrypting with a Keystore AES-GCM key can be rejected with
        // InvalidAlgorithmParameterException on some devices/providers.
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(rawKey)
        val encoded = Base64.getEncoder().encodeToString(iv + ciphertext)
        preferences.edit().putString(AUTH_KEY_PREF, encoded).apply()
    }

    private fun loadAuthKey(): ByteArray? {
        val encoded = preferences.getString(AUTH_KEY_PREF, null) ?: return null
        return try {
            val combined = Base64.getDecoder().decode(encoded)
            if (combined.size < 13) return null
            val iv = combined.copyOfRange(0, 12)
            val ciphertext = combined.copyOfRange(12, combined.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                getOrCreateAuthWrapKey(),
                GCMParameterSpec(128, iv)
            )
            cipher.doFinal(ciphertext)
        } catch (_: Exception) {
            null
        }
    }

    private fun promptForPairingCodeBlocking(): String? {
        val latch = CountDownLatch(1)
        var result: String? = null

        runOnUiThread {
            val input = EditText(this).apply {
                inputType = InputType.TYPE_CLASS_NUMBER
                hint = "6-digit code"
                setSingleLine(true)
                selectAll()
            }

            AlertDialog.Builder(this)
                .setTitle("Pair bluetoothfilesync")
                .setMessage("Enter the 6-digit pairing code shown by the Windows bluetoothfilesync server.")
                .setView(input)
                .setNegativeButton("CANCEL") { _, _ ->
                    latch.countDown()
                }
                .setPositiveButton("PAIR") { _, _ ->
                    result = input.text.toString().trim()
                    latch.countDown()
                }
                .setOnCancelListener { latch.countDown() }
                .show()

            input.requestFocus()
        }

        latch.await(5, TimeUnit.MINUTES)
        return result
    }

    private fun verifyWindowsAuthOk(
        response: String,
        key: ByteArray,
        nonce: ByteArray,
        context: String
    ) {
        val parts = response.split(" ", limit = 2)
        if (parts.size != 2 || parts[0] != "AUTH_OK") {
            throw Exception("Windows $context failed: $response")
        }

        val expected = hex(
            hmacSha256(
                key,
                nonce + ":windows".toByteArray(Charsets.UTF_8)
            )
        )
        if (!MessageDigest.isEqual(expected.toByteArray(), parts[1].toByteArray())) {
            throw Exception("Windows identity verification failed.")
        }
    }

    private fun authenticateWithWindows(device: BluetoothDevice): SecureChannel {
        logEvent("AUTHENTICATING", "device=${device.name ?: device.address}")
        val output = bluetoothOutput ?: error("Bluetooth output is not available")
        val input = bluetoothInput ?: error("Bluetooth input is not available")

        val keyRecordExists = preferences.contains(AUTH_KEY_PREF)
        val existingKey = loadAuthKey()

        if (keyRecordExists && existingKey == null) {
            logEvent("AUTH_FAILED", "stored authentication key could not be recovered")
            throw Exception(
                "Saved bluetoothfilesync authentication key could not be recovered. " +
                    "Use FORGET DEVICE and pair again."
            )
        }

        val keyState = if (existingKey != null) "1" else "0"

        sendCommand(
            output,
            "HELLO ${protocolIdentity.serviceUuid} ${protocolIdentity.protocolVersion} KEY=$keyState SESSION=$currentSessionId"
        )

        val response = readFrameAsString(input)

        when {
            response.startsWith("AUTH_CHALLENGE ") -> {
                val key = existingKey ?: error("Windows requires authentication, but Android has no key")
                val nonce = fromHex(response.substringAfter("AUTH_CHALLENGE ").trim())
                require(nonce.size == AUTH_NONCE_BYTES) { "Windows supplied an invalid authentication nonce." }
                val proof = hex(hmacSha256(key, nonce))
                sendCommand(output, "AUTH_RESPONSE $proof")

                val serverProofResponse = readFrameAsString(input)
                verifyWindowsAuthOk(
                    serverProofResponse,
                    key,
                    nonce,
                    "authentication"
                )
                logEvent("AUTH_OK")
                return SecureChannel(key, nonce, isServer = false)
            }

            response.startsWith("PAIR_REQUIRED ") -> {
                logEvent("PAIRING_REQUIRED")
                if (existingKey != null) {
                    logEvent("PAIRING_REJECTED", "Windows requested pairing while a trusted key exists")
                    throw Exception(
                        "Windows requested a new pairing while this Android device already has a trusted key. " +
                            "Use FORGET DEVICE before pairing again."
                    )
                }

                val nonceHex = response.substringAfter("PAIR_REQUIRED ").trim()
                val nonce = fromHex(nonceHex)
                require(nonce.size == AUTH_NONCE_BYTES) { "Windows supplied an invalid pairing nonce." }
                val code = promptForPairingCodeBlocking()
                    ?: run {
                        logEvent("PAIR_FAILED", "cancelled")
                        throw Exception("Pairing cancelled.")
                    }

                if (!Regex("\\d{6}").matches(code)) {
                    logEvent("PAIR_FAILED", "invalid code format")
                    throw Exception("Pairing code must contain exactly 6 digits.")
                }

                sendCommand(output, "PAIR_CODE $code")

                val keyMessage = readFrameAsString(input)
                if (!keyMessage.startsWith("PAIR_KEY ")) {
                    logEvent("PAIR_FAILED", keyMessage)
                    throw Exception("Windows pairing failed: $keyMessage")
                }

                val newKey = Base64.getDecoder().decode(
                    keyMessage.substringAfter("PAIR_KEY ").trim()
                )
                if (newKey.size != 32) {
                    throw Exception("Windows supplied an invalid authentication key.")
                }

                val confirm = hex(
                    hmacSha256(
                        newKey,
                        nonce + ":pair-confirm".toByteArray(Charsets.UTF_8)
                    )
                )
                sendCommand(output, "PAIR_CONFIRM $confirm")

                val serverProofResponse = readFrameAsString(input)
                verifyWindowsAuthOk(
                    serverProofResponse,
                    newKey,
                    nonce,
                    "pairing confirmation"
                )
                storeAuthKey(newKey)
                logEvent("PAIRED")
                return SecureChannel(newKey, nonce, isServer = false)
            }

            else -> {
                logEvent("AUTH_FAILED", response)
                if (response == "ERROR: NEW_DEVICE_NOT_AUTHORIZED") {
                    throw Exception(
                        "This Windows computer already has a trusted bluetoothfilesync device. " +
                        "To authorize this Android device, restart the Windows server with " +
                        "--authorize-new-device, then connect again."
                    )
                }
                throw Exception("Authentication rejected by Windows: $response")
            }
        }
    }

    // ========================================================
    // CONNECT
    // ========================================================

    private fun connectToDevice(
        selected: String
    ) {

        if (!bluetoothPermissionsGranted()) {
            requestBluetoothPermissions()
            return
        }

        if (!bluetoothAdapter.isEnabled) {
            ensureBluetoothReady()
            return
        }

        val address =
            selected
                .substringAfter("\n")
                .trim()

        @SuppressLint("MissingPermission")
        val device =
            bluetoothAdapter.getRemoteDevice(address)

        connectBluetoothDevice(
            device,
            false
        )
    }


    // ========================================================
    // SYNC STATE / HASH / BACKUP HELPERS
    // ========================================================

    private fun localHashForDocument(
        relativePath: String,
        file: DocumentFile,
        hashStateKey: String = syncStateFolderKey()
    ): String {
        val size = file.length()
        val modified = file.lastModified()
        val key = "$hashStateKey:$relativePath"

        if (modified > 0L) {
            val cachedSize = localHashCache.getLong("size:$key", Long.MIN_VALUE)
            val cachedModified = localHashCache.getLong("modified:$key", Long.MIN_VALUE)
            val cachedHash = localHashCache.getString("hash:$key", null)
            if (cachedHash != null && cachedSize == size && cachedModified == modified) {
                return cachedHash
            }
        }

        val hash = sha256Document(file)

        if (modified > 0L) {
            localHashCache.edit()
                .putLong("size:$key", size)
                .putLong("modified:$key", modified)
                .putString("hash:$key", hash)
                .apply()
        }

        return hash
    }


    private fun sha256Document(
        file: DocumentFile
    ): String {

        val digest =
            MessageDigest.getInstance("SHA-256")

        val input =
            contentResolver.openInputStream(file.uri)
                ?: throw Exception("Could not read file: ${file.name}")

        input.use { stream ->
            val buffer = ByteArray(1024 * 1024)
            while (true) {
                val count = stream.read(buffer)
                if (count <= 0) break
                digest.update(buffer, 0, count)
            }
        }

        return digest.digest()
            .joinToString("") { byte ->
                "%02x".format(byte)
            }
    }


    private fun getLastSyncedHash(
        relativePath: String
    ): String? {

        return syncState.getString(
            "hash:${syncStateFolderKey()}:$relativePath",
            null
        )
    }


    private fun saveLastSyncedHash(
        relativePath: String,
        hash: String
    ) {

        syncState.edit()
            .putString(
                "hash:${syncStateFolderKey()}:$relativePath",
                hash
            )
            .apply()
    }


    private fun syncStateFolderKey(): String {

        val source =
            syncFolderUri?.toString()
                ?: "private:$filesDir/bluetoothfilesync"

        return MessageDigest.getInstance("SHA-256")
            .digest(source.toByteArray(Charsets.UTF_8))
            .joinToString("") { byte ->
                "%02x".format(byte)
            }
    }


    private fun mimeTypeForPath(
        path: String
    ): String {

        val extension =
            path.substringAfterLast('.', "")
                .lowercase()

        return if (extension.isNotBlank()) {
            MimeTypeMap.getSingleton()
                .getMimeTypeFromExtension(extension)
                ?: "application/octet-stream"
        } else {
            "application/octet-stream"
        }
    }


    private fun copyDocument(
        source: DocumentFile,
        targetDirectory: DocumentFile,
        targetName: String
    ): DocumentFile {

        val target =
            targetDirectory.createFile(
                mimeTypeForPath(targetName),
                targetName
            )
                ?: throw Exception("Could not create $targetName")

        val input =
            contentResolver.openInputStream(source.uri)
                ?: throw Exception("Could not read ${source.name}")

        val output =
            contentResolver.openOutputStream(target.uri, "w")
                ?: throw Exception("Could not write $targetName")

        try {
            input.use { src ->
                output.use { dst ->
                    src.copyTo(dst, 1024 * 1024)
                }
            }
        } catch (e: Exception) {
            target.delete()
            throw e
        }

        return target
    }


    private fun makeLocalBackup(
        destination: DocumentFile,
        relativePath: String
    ): DocumentFile? {

        if (!destination.exists()) return null
        if (!destination.isFile) {
            throw Exception("Destination exists but is not a file.")
        }

        val relativeParent =
            relativePath.substringBeforeLast('/', "")

        val backupDir =
            ensureLocalDirectory(
                if (relativeParent.isBlank()) {
                    "Backups"
                } else {
                    "Backups/$relativeParent"
                }
            )

        val name =
            destination.name ?: "file"

        val dot = name.lastIndexOf('.')
        val stem = if (dot > 0) name.substring(0, dot) else name
        val extension = if (dot > 0) name.substring(dot) else ""
        val timestamp =
            java.text.SimpleDateFormat(
                "yyyy-MM-dd-HH-mm-ss-SSS",
                java.util.Locale.US
            ).format(java.util.Date())

        var backupName = "$stem-$timestamp$extension"
        var counter = 1
        while (backupDir.findFile(backupName) != null) {
            backupName = "$stem-$timestamp-$counter$extension"
            counter++
        }

        val backup =
            copyDocument(
                destination,
                backupDir,
                backupName
            )

        // The backup is deliberately kept while the replacement is performed.
        // The caller removes the old destination only after this copy succeeds
        // and can restore from this backup if replacement fails.
        return backup
    }


    private fun makeConflictFile(
        relativePath: String,
        side: String
    ): DocumentFile {

        val name =
            relativePath.substringAfterLast('/')

        val parent =
            relativePath.substringBeforeLast('/', "")

        val dot = name.lastIndexOf('.')
        val stem = if (dot > 0) name.substring(0, dot) else name
        val extension = if (dot > 0) name.substring(dot) else ""

        val directory =
            ensureLocalDirectory(
                if (parent.isBlank()) {
                    "Conflicts/$stem"
                } else {
                    "Conflicts/$parent/$stem"
                }
            )

        // Conflict copies always carry the side and timestamp, matching the
        // Windows naming convention. Never create an un-timestamped conflict
        // filename such as "name-Android.txt" or "name-Windows.txt".
        val timestamp =
            java.text.SimpleDateFormat(
                "yyyy-MM-dd-HH-mm-ss-SSS",
                java.util.Locale.US
            ).format(java.util.Date())

        val baseName = "$stem-$side-$timestamp"
        var targetName = "$baseName$extension"
        var counter = 1

        // Millisecond timestamps are normally sufficient, but keep creation
        // collision-safe if two conflict copies are generated in the same ms.
        while (directory.findFile(targetName) != null) {
            targetName = "$baseName-$counter$extension"
            counter++
        }

        return directory.createFile(
            mimeTypeForPath(targetName),
            targetName
        ) ?: throw Exception("Could not create conflict copy.")
    }


    private fun saveLocalConflictCopy(
        relativePath: String
    ): DocumentFile {

        val source =
            localDocument(relativePath)
                ?: throw Exception("Local conflict source is missing.")

        repeat(3) {
            val target = makeConflictFile(relativePath, "Android")

            try {
                val sourceHashBefore = sha256Document(source)

                val input =
                    contentResolver.openInputStream(source.uri)
                        ?: throw Exception("Could not read local conflict source.")

                val output =
                    contentResolver.openOutputStream(target.uri, "w")
                        ?: throw Exception("Could not write conflict copy.")

                input.use { src ->
                    output.use { dst ->
                        src.copyTo(dst, 1024 * 1024)
                    }
                }

                val copiedHash = sha256Document(target)
                val sourceHashAfter = sha256Document(source)

                if (sourceHashBefore == copiedHash && copiedHash == sourceHashAfter) {
                    return target
                }

                target.delete()
            } catch (e: Exception) {
                target.delete()
                throw e
            }
        }

        throw Exception("Android file changed repeatedly while saving its conflict copy.")
    }


    private fun downloadRemoteCopy(
        relativePath: String,
        destination: DocumentFile?,
        expectedSize: Long,
        expectedHash: String?,
        expectedDestinationHash: String? = null,
        validateDestination: Boolean = true,
        destinationParent: DocumentFile? = null,
        destinationName: String? = null
    ): DocumentFile {

        val input = bluetoothInput
        val output = bluetoothOutput

        if (
            bluetoothSocket == null ||
            input == null ||
            output == null ||
            !bluetoothSocket!!.isConnected
        ) {
            throw Exception("Bluetooth connection is not active.")
        }

        val name =
            destinationName
                ?: destination?.name
                ?: relativePath.substringAfterLast('/')

        val parent =
            destinationParent
                ?: destination?.parentFile
                ?: ensureLocalDirectory(
                    relativePath.substringBeforeLast('/', "")
                )

        val tempName = newBluetoothfilesyncTempName()
        parent.findFile(tempName)?.delete()
        val temporary =
            parent.createFile(
                mimeTypeForPath(name),
                tempName
            ) ?: throw Exception("Could not create temporary download file.")

        sendSecureCommand(output, "GET $relativePath")

        val header = readSecureFrameAsString(input)
        if (header.startsWith("ERROR:")) throw Exception(header)
        if (!header.startsWith("FILE ")) throw Exception("Unexpected response: $header")

        val remoteSize =
            header.substringAfter("FILE ").trim().toLong()

        if (remoteSize != expectedSize) {
            temporary.delete()
            throw Exception("Windows file changed while syncing.")
        }

        var received = 0L
        val transferDigest = MessageDigest.getInstance("SHA-256")
        try {
            val outputStream =
                contentResolver.openOutputStream(temporary.uri, "w")
                    ?: throw Exception("Could not write temporary download file.")

            outputStream.use { fileOutput ->
                while (received < expectedSize) {
                    val frame = readSecureFrame(input)
                    if (received + frame.size > expectedSize) {
                        throw Exception("Received more data than expected.")
                    }
                    fileOutput.write(frame)
                    transferDigest.update(frame)
                    received += frame.size
                }
            }

            if (received != expectedSize) {
                throw Exception("Size mismatch: $received / $expectedSize bytes")
            }

            // Windows always sends a literal EOF frame after the file's
            // data. Termination above is purely byte-count driven, so a
            // legitimate chunk that happens to equal "EOF" is never
            // mistaken for the terminator; this explicit check instead
            // confirms the stream is still in sync with Windows before
            // the transfer is treated as complete.
            val eof = readSecureFrame(input)
            if (!eof.contentEquals("EOF".toByteArray())) {
                throw Exception("Expected EOF after downloaded file.")
            }

            val downloadedHash = transferDigest.digest()
                .joinToString("") { byte -> "%02x".format(byte) }
            if (
                expectedHash != null &&
                !downloadedHash.equals(expectedHash, ignoreCase = true)
            ) {
                throw Exception("Hash mismatch after download.")
            }

            val destinationPath =
                relativePath

            var backup: DocumentFile? = null
            var destinationRemoved = false

            try {
                if (validateDestination) {
                    // Re-resolve and hash the live destination immediately before
                    // replacement. The expected hash came from the sync plan.
                    val currentDestination = localDocument(destinationPath)
                    val currentDestinationHash =
                        if (currentDestination?.isFile == true) {
                            sha256Document(currentDestination)
                        } else {
                            null
                        }

                    if (expectedDestinationHash == null) {
                        if (currentDestination != null && currentDestination.exists()) {
                            throw Exception(
                                "Android destination changed after the sync plan was created."
                            )
                        }
                    } else if (currentDestinationHash == null ||
                        !currentDestinationHash.equals(expectedDestinationHash, ignoreCase = true)
                    ) {
                        throw Exception(
                            "Android destination changed after the sync plan was created."
                        )
                    }

                    if (currentDestination != null && currentDestination.exists()) {
                        // First create a durable backup. The original stays untouched
                        // until the backup is completely written.
                        backup = makeLocalBackup(
                            currentDestination,
                            destinationPath
                        )

                        // Verify the backup matches the exact version we validated
                        // before deleting that live version.
                        if (backup == null ||
                            !sha256Document(backup).equals(currentDestinationHash, ignoreCase = true)
                        ) {
                            throw Exception("Android backup verification failed.")
                        }

                        if (!currentDestination.delete()) {
                            throw Exception("Could not remove old destination file.")
                        }
                        destinationRemoved = true
                    }
                }

                if (temporary.renameTo(name)) {
                    val finalFile =
                        parent.findFile(name)
                            ?: throw Exception("Downloaded file could not be resolved after rename.")

                    return finalFile
                } else {
                    // Some providers don't support rename. Copy then delete temp.
                    val finalFile =
                        parent.createFile(
                            mimeTypeForPath(name),
                            name
                        ) ?: throw Exception("Could not create destination file.")

                    val src = contentResolver.openInputStream(temporary.uri)
                        ?: throw Exception("Could not reopen temporary file.")
                    val dst = contentResolver.openOutputStream(finalFile.uri, "w")
                        ?: throw Exception("Could not write destination file.")

                    src.use { source ->
                        dst.use { target ->
                            source.copyTo(target, 1024 * 1024)
                        }
                    }

                    if (!sha256Document(finalFile).equals(downloadedHash, ignoreCase = true)) {
                        finalFile.delete()
                        throw Exception("Final Android file failed hash verification.")
                    }

                    temporary.delete()
                    return finalFile
                }

            } catch (e: Exception) {
                temporary.delete()

                if (destinationRemoved && backup != null) {
                    try {
                        // Remove any partial replacement before restoring the backup.
                        parent.findFile(name)?.delete()
                        copyDocument(
                            backup,
                            parent,
                            name
                        )
                    } catch (restoreError: Exception) {
                        throw Exception(
                            "Replacement failed and backup restore failed: " +
                            restoreError.message,
                            e
                        )
                    }
                }

                throw e
            }

        } catch (e: Exception) {
            temporary.delete()
            throw e
        }
    }


    private fun uploadAndroidConflictCopyBlocking(
        relativePath: String,
        conflictFile: DocumentFile
    ) {
        val input = bluetoothInput
            ?: throw Exception("Bluetooth input is unavailable.")
        val output = bluetoothOutput
            ?: throw Exception("Bluetooth output is unavailable.")

        if (!conflictFile.isFile) {
            throw Exception("Android conflict path is not a file: $relativePath")
        }

        val size = conflictFile.length()
        sendSecureCommand(output, "PUT_CONFLICT $relativePath $size")

        val ready = readSecureFrameAsString(input)
        if (ready != "READY") {
            throw Exception(ready)
        }

        val transferDigest = MessageDigest.getInstance("SHA-256")
        var sent = 0L
        val fileInput =
            contentResolver.openInputStream(conflictFile.uri)
                ?: throw SyncTransportException("Could not read Android conflict file after Windows accepted it: $relativePath")

        try {
            fileInput.use { source ->
                val buffer = ByteArray(TRANSFER_CHUNK_BYTES)
                while (true) {
                    val count = try {
                        source.read(buffer)
                    } catch (e: Exception) {
                        throw SyncTransportException(
                            "Could not read Android conflict file during transfer: $relativePath",
                            e
                        )
                    }
                    if (count <= 0) break
                    transferDigest.update(buffer, 0, count)
                    sendSecureFrame(output, buffer, count)
                    sent += count
                }
            }
        } catch (e: SyncTransportException) {
            throw e
        } catch (e: Exception) {
            throw SyncTransportException(
                "Android conflict file transfer could not be completed: $relativePath",
                e
            )
        }

        flushBluetoothOutput()

        if (sent != size) {
            throw Exception("Android conflict file changed during transfer: $relativePath")
        }

        sendSecureFrame(output, "EOF".toByteArray())
        flushBluetoothOutput()

        val result = readSecureFrameAsString(input)
        if (!result.startsWith("CONFLICT_PUT_OK")) {
            throw Exception(result)
        }

        val localHash = transferDigest.digest()
            .joinToString("") { byte -> "%02x".format(byte) }
        val remoteHash = result.substringAfter("CONFLICT_PUT_OK", "").trim()
        if (remoteHash.isNotEmpty() && !localHash.equals(remoteHash, ignoreCase = true)) {
            throw Exception("Windows conflict hash verification failed for $relativePath.")
        }
    }


    private fun saveWindowsConflictCopy(
        relativePath: String,
        windows: SyncFile
    ): DocumentFile {

        // Create the final conflict filename up front so it always follows
        // the same convention as Windows: <stem>-Windows-<timestamp><ext>.
        // We retain its parent directory/name, remove only the placeholder,
        // and stream the download into a bluetoothfilesync temp file there.
        val target =
            makeConflictFile(relativePath, "Windows")

        val targetParent =
            target.parentFile
                ?: throw Exception("Could not resolve Android Conflicts directory.")

        val targetName =
            target.name
                ?: throw Exception("Could not resolve Android conflict filename.")

        if (!target.delete()) {
            throw Exception("Could not prepare Android conflict destination.")
        }

        return downloadRemoteCopy(
            relativePath,
            destination = null,
            expectedSize = windows.size,
            expectedHash = windows.hash,
            expectedDestinationHash = null,
            validateDestination = false,
            destinationParent = targetParent,
            destinationName = targetName
        )
    }


    // ========================================================
    // UPLOAD
    // ========================================================


    private fun uploadLocalFileBlocking(
        relativePath: String
    ) {

        val input = bluetoothInput ?: throw Exception("Bluetooth input is unavailable.")
        val output = bluetoothOutput ?: throw Exception("Bluetooth output is unavailable.")

        val file =
            localDocument(relativePath)
                ?: throw Exception("Local file not found: $relativePath")

        if (!file.isFile) {
            throw Exception("Local path is not a file: $relativePath")
        }

        val size = file.length()
        val modifiedBefore = file.lastModified()
        val expectedHash = localFiles.firstOrNull { it.path == relativePath }?.hash
            ?: localHashForDocument(relativePath, file)

        sendSecureCommand(output, "PUT $relativePath $size $expectedHash")

        val ready = readSecureFrameAsString(input)
        if (ready != "READY") throw Exception(ready)

        val transferDigest = MessageDigest.getInstance("SHA-256")
        var sent = 0L
        val fileInput =
            contentResolver.openInputStream(file.uri)
                ?: throw SyncTransportException("Could not read local file after Windows accepted the upload: $relativePath")

        try {
            fileInput.use { source ->
                val buffer = ByteArray(TRANSFER_CHUNK_BYTES)
                while (true) {
                    val count = try {
                        source.read(buffer)
                    } catch (e: Exception) {
                        throw SyncTransportException(
                            "Could not read local file during upload: $relativePath",
                            e
                        )
                    }
                    if (count <= 0) break
                    transferDigest.update(buffer, 0, count)
                    sendSecureFrame(output, buffer, count)
                    sent += count
                }
            }
        } catch (e: SyncTransportException) {
            throw e
        } catch (e: Exception) {
            // Windows is already waiting for the remainder/EOF of this file.
            // Do not send another command on a stream that may be mid-transfer.
            throw SyncTransportException(
                "Local file transfer could not be completed: $relativePath",
                e
            )
        }

        flushBluetoothOutput()

        val sentHash = transferDigest.digest()
            .joinToString("") { byte -> "%02x".format(byte) }

        // Windows has consumed the complete transfer and will now return to a
        // command boundary. Read that response before applying local TOCTOU
        // validation so a changed Android file can be rejected without leaving
        // the protocol stream waiting on this file's response.
        val result = readSecureFrameAsString(input)
        if (!result.startsWith("PUT_OK")) throw Exception(result)

        val remoteHash = result.substringAfter("PUT_OK", "").trim()

        if (
            remoteHash.isNotEmpty() &&
            !expectedHash.equals(remoteHash, ignoreCase = true)
        ) {
            throw Exception("Windows hash verification failed for $relativePath.")
        }

        if (sent != size || file.length() != size || file.lastModified() != modifiedBefore) {
            throw Exception("Android file changed during upload: $relativePath")
        }

        if (!expectedHash.equals(sentHash, ignoreCase = true)) {
            throw Exception("Android file changed before or during upload: $relativePath")
        }

        saveLastSyncedHash(relativePath, expectedHash)
    }




    // ========================================================
    // DOWNLOAD
    // ========================================================


    // ========================================================
    // WINDOWS LIST
    // ========================================================

    private fun parseWindowsListing(
        listing: String
    ) {

        windowsFiles.clear()

        if (listing == "NO_FILES") {
            return
        }

        for (line in listing.lines()) {

            if (line.isBlank()) {
                continue
            }

            val parts =
                line.split("|")

            if (parts.size != 4) {
                continue
            }

            try {

                val path = parts[0]
                    .trim()
                    .replace('\\', '/')

                if (path.isBlank()) {
                    continue
                }

                // Defense in depth: Windows excludes these namespaces from
                // its normal LIST, but Android must never treat them as
                // ordinary sync files if they appear in a listing anyway.
                val firstPathPart =
                    path.trimStart('/')
                        .substringBefore('/')

                if (firstPathPart.equals("Backups", ignoreCase = true) ||
                    firstPathPart.equals("Conflicts", ignoreCase = true) ||
                    firstPathPart.equals("SyncHistory", ignoreCase = true)
                ) {
                    continue
                }

                val size =
                    parts[1].toLong()

                val modified =
                    parts[2].toLong() /
                    1_000_000L

                val hash =
                    parts[3]
                        .trim()
                        .lowercase()

                if (hash.length != 64) {
                    continue
                }

                windowsFiles.add(
                    SyncFile(
                        path,
                        size,
                        modified,
                        hash
                    )
                )

            } catch (_: Exception) {
            }
        }

        windowsFiles.sortBy {
            it.path.lowercase()
        }
    }


    // ========================================================
    // AUTO SYNC
    // ========================================================

    private fun isAutoSyncEnabled(): Boolean {
        return preferences.getBoolean(
            "auto_sync_enabled",
            true
        )
    }


    private fun updateDeviceSelectionUi() {
        if (!::deviceList.isInitialized) {
            return
        }

        val hasDevice = hasSavedDevice()
        deviceList.visibility =
            if (hasDevice) {
                View.GONE
            } else {
                View.VISIBLE
            }
    }


    private fun updateSavedDeviceView() {
        val name = preferences.getString(
            "last_device_name",
            null
        )
        val address = preferences.getString(
            "last_device_address",
            null
        )

        savedDeviceView.text =
            if (name != null && address != null) {
                "Device: $name\n$address"
            } else {
                "Device: None"
            }
    }


    private fun historyKey(): String = "sync_history"


    private fun addSyncHistory(
        success: Boolean,
        uploads: Int = 0,
        downloads: Int = 0,
        conflicts: Int = 0,
        error: String? = null
    ) {
        val timestamp =
            java.text.SimpleDateFormat(
                "yyyy-MM-dd HH:mm:ss",
                java.util.Locale.US
            ).format(java.util.Date())

        val safeError =
            error?.replace("|", "/")
                ?.replace("\n", " ")
                ?.replace("\r", " ")
                ?.take(180)

        val entry =
            if (success) {
                "$timestamp|session=$currentSessionId|SUCCESS|uploaded=$uploads|downloaded=$downloads|conflicts=$conflicts"
            } else {
                "$timestamp|session=$currentSessionId|FAILED|${safeError ?: "Unknown error"}"
            }

        val existing =
            preferences.getString(historyKey(), "")
                ?.lineSequence()
                ?.filter { it.isNotBlank() }
                ?.toList()
                ?: emptyList()

        val updated =
            (listOf(entry) + existing).take(20)

        preferences.edit()
            .putString(
                historyKey(),
                updated.joinToString("\n")
            )
            .apply()
    }


    private fun showSyncHistory() {
        val history = readPersistentHistory()

        val message =
            if (history.isNotEmpty()) {
                history.joinToString("\n")
            } else {
                val legacy =
                    preferences.getString(historyKey(), "")
                        ?.lineSequence()
                        ?.filter { it.isNotBlank() }
                        ?.toList()
                        ?: emptyList()

                if (legacy.isEmpty()) {
                    "No sync history yet."
                } else {
                    legacy.take(20).joinToString("\n")
                }
            }

        AlertDialog.Builder(this)
            .setTitle("Sync History")
            .setMessage(message)
            .setPositiveButton("CLOSE", null)
            .show()
    }


    private fun displaySyncIssues(
        conflicts: List<SyncResult>,
        fileErrors: List<SyncFileError>
    ) {
        val text = buildString {
            if (conflicts.isNotEmpty()) {
                append("Conflicting file(s):\n\n")
                append(conflicts.joinToString("\n") { "• ${it.path}" })
            }

            if (fileErrors.isNotEmpty()) {
                if (isNotEmpty()) {
                    append("\n\n")
                }
                append("File(s) that could not be synced:\n\n")
                append(
                    fileErrors.joinToString("\n") {
                        "• ${it.path} (${it.action}): ${it.message}"
                    }
                )
            }
        }

        runOnUiThread {
            conflictView.text = text
            conflictView.visibility =
                if (text.isNotBlank()) {
                    View.VISIBLE
                } else {
                    View.GONE
                }
            exitButton.visibility = View.VISIBLE
        }
    }


    private fun hasSavedSyncFolder(): Boolean {
        return preferences.getString(
            "sync_folder_uri",
            null
        ) != null &&
            syncFolderUri != null &&
            syncRootDocument?.canRead() == true &&
            syncRootDocument?.canWrite() == true
    }


    private fun hasSavedDevice(): Boolean {
        return preferences.getString(
            "last_device_address",
            null
        ) != null
    }


    private fun tryAutoSync() {

        if (autoSyncStartedThisSession || syncInProgress) {
            return
        }

        // Never start a sync from a stale/incomplete local snapshot.
        // Startup and folder-selection scans run asynchronously.
        if (localScanInProgress || !localFilesReady) {
            return
        }

        if (!isAutoSyncEnabled()) {
            return
        }

        if (!hasSavedSyncFolder() || !hasSavedDevice()) {
            return
        }

        if (!bluetoothPermissionsGranted()) {
            return
        }

        if (!bluetoothAdapter.isEnabled) {
            return
        }

        if (bluetoothSocket?.isConnected != true) {
            // Startup connection is asynchronous. If this lifecycle check
            // happens before the saved device has connected, make sure the
            // automatic connection is still initiated.
            if (!autoConnectInProgress) {
                autoConnectToSavedDevice()
            }
            return
        }

        autoSyncStartedThisSession = true

        runOnUiThread {
            setStatus(
                "● Automatic sync starting..."
            )
        }

        performSync(
            reusePreparedLocalSnapshot = true
        )
    }


    // ========================================================
    // BLUETOOTH RESTORE AFTER SYNC
    // ========================================================

    private fun restoreBluetoothAfterSync(): Boolean {
        if (!bluetoothWasInitiallyOff || !bluetoothStartedByBluetoothfilesync) {
            return true
        }

        if (!bluetoothAdapter.isEnabled) {
            return true
        }

        // On Android versions where programmatic Bluetooth disable is
        // available, restore the user's original OFF state. On newer
        // Android versions the operation is silently unavailable to normal
        // apps, so do not block a successful sync or display a warning.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return true
        }

        @Suppress("DEPRECATION")
        bluetoothAdapter.disable()

        // Do not turn a Bluetooth restore limitation into a sync failure.
        return true
    }


    // ========================================================
    // SYNC
    // ========================================================

    private fun performSync(
        reusePreparedLocalSnapshot: Boolean = false
    ) {

        if (syncInProgress) {
            return
        }

        syncInProgress = true

        Thread {

            synchronized(bluetoothLock) {

                val fileErrors = mutableListOf<SyncFileError>()

                try {

                    if (
                        bluetoothSocket == null ||
                        bluetoothInput == null ||
                        bluetoothOutput == null ||
                        !bluetoothSocket!!.isConnected
                    ) {
                        throw Exception(
                            "Bluetooth connection is not active."
                        )
                    }

                    setStatus(
                        "● Preparing sync..."
                    )
                    logEvent("SYNC_STARTED")

                    refreshLocalFilesBlocking(
                        reusePreparedSnapshot = reusePreparedLocalSnapshot
                    )

                    setStatus(
                        "● Local files prepared — sending Windows file list..."
                    )

                    sendSecureCommand(
                        bluetoothOutput!!,
                        "LIST"
                    )

                    val windowsListing =
                        readSecureFrameAsString(
                            bluetoothInput!!
                        )
                    logEvent("LIST_RECEIVED", "bytes=${windowsListing.toByteArray(Charsets.UTF_8).size}")
                    setStatus("● Windows file list received — building sync plan...")

                    parseWindowsListing(
                        windowsListing
                    )
                    val results =
                        compareDirectories()

                    val conflicts =
                        results.filter {
                            it.action == SyncAction.CONFLICT
                        }

                    val uploads =
                        results.filter {
                            it.action == SyncAction.UPLOAD
                        }

                    val downloads =
                        results.filter {
                            it.action == SyncAction.DOWNLOAD
                        }

                    logEvent(
                        "SYNC_PLAN",
                        "android_to_windows=${uploads.size} windows_to_android=${downloads.size} conflicts=${conflicts.size}"
                    )
                    setStatus(
                        "● Sync plan ready\n" +
                        "${uploads.size} upload(s), " +
                        "${downloads.size} download(s), " +
                        "${conflicts.size} conflict(s)"
                    )
                    if (conflicts.isNotEmpty()) {
                        logEvent("CONFLICTS", "count=${conflicts.size}")
                    }

                    // Each conflict is isolated. Local preservation failures can
                    // safely skip that conflict because no Windows command has
                    // been sent yet. Transport failures still abort the session.
                    for (conflict in conflicts) {

                        val windows =
                            windowsFiles.firstOrNull {
                                it.path == conflict.path
                            }

                        if (
                            localFiles.none {
                                it.path == conflict.path
                            } ||
                            windows == null
                        ) {
                            fileErrors += SyncFileError(
                                conflict.path,
                                "CONFLICT",
                                "Conflict source file was no longer available."
                            )
                            continue
                        }

                        try {
                            setStatus(
                                "● Saving conflict:\n" +
                                conflict.path
                            )

                            val androidConflict =
                                saveLocalConflictCopy(
                                    conflict.path
                                )

                            sendSecureCommand(
                                bluetoothOutput!!,
                                "CONFLICT ${conflict.path}"
                            )

                            val conflictResponse =
                                readSecureFrameAsString(
                                    bluetoothInput!!
                                )

                            if (conflictResponse != "CONFLICT_OK") {
                                throw Exception(
                                    "Windows conflict preservation failed: $conflictResponse"
                                )
                            }

                            // Put the Android version into the Windows Conflicts
                            // folder as well, so Windows keeps both versions.
                            uploadAndroidConflictCopyBlocking(
                                conflict.path,
                                androidConflict
                            )

                            saveWindowsConflictCopy(
                                conflict.path,
                                windows
                            )
                        } catch (e: Exception) {
                            if (e is SyncTransportException) {
                                throw e
                            }

                            val message = e.message ?: e.javaClass.simpleName
                            fileErrors += SyncFileError(
                                conflict.path,
                                "CONFLICT",
                                message
                            )
                            logEvent(
                                "FILE_FAILED",
                                "action=CONFLICT path=${conflict.path} error=$message"
                            )
                            setStatus(
                                "⚠ Conflict preservation failed — continuing:\n" +
                                "${conflict.path}\n$message"
                            )
                        }
                    }

                    val total =
                        uploads.size +
                        downloads.size

                    var completed = 0

                    // A failed file is recorded and skipped. A transport failure
                    // is rethrown because continuing could send the next command
                    // into a broken or partially consumed protocol stream.
                    for (result in uploads) {

                        completed++

                        setStatus(
                            "● Syncing $completed / $total\n" +
                            "Uploading:\n" +
                            result.path
                        )

                        try {
                            uploadLocalFileBlocking(
                                result.path
                            )
                        } catch (e: Exception) {
                            if (e is SyncTransportException) {
                                throw e
                            }

                            val message = e.message ?: e.javaClass.simpleName
                            fileErrors += SyncFileError(
                                result.path,
                                "UPLOAD",
                                message
                            )
                            logEvent(
                                "FILE_FAILED",
                                "action=UPLOAD path=${result.path} error=$message"
                            )
                            setStatus(
                                "⚠ Upload failed — continuing:\n" +
                                "${result.path}\n$message"
                            )
                        }
                    }

                    for (result in downloads) {

                        completed++

                        try {
                            val windows =
                                windowsFiles.firstOrNull {
                                    it.path == result.path
                                }
                                    ?: throw Exception(
                                        "Windows file disappeared: ${result.path}"
                                    )

                            setStatus(
                                "● Syncing $completed / $total\n" +
                                "Downloading:\n" +
                                result.path
                            )

                            val destination =
                                localDocument(result.path)

                            downloadRemoteCopy(
                                result.path,
                                destination,
                                windows.size,
                                windows.hash,
                                expectedDestinationHash = localFiles
                                    .firstOrNull { it.path == result.path }
                                    ?.hash
                            )

                            saveLastSyncedHash(
                                result.path,
                                windows.hash
                            )
                        } catch (e: Exception) {
                            if (e is SyncTransportException) {
                                throw e
                            }

                            val message = e.message ?: e.javaClass.simpleName
                            fileErrors += SyncFileError(
                                result.path,
                                "DOWNLOAD",
                                message
                            )
                            logEvent(
                                "FILE_FAILED",
                                "action=DOWNLOAD path=${result.path} error=$message"
                            )
                            setStatus(
                                "⚠ Download failed — continuing:\n" +
                                "${result.path}\n$message"
                            )
                        }
                    }

                    val hasIssues =
                        conflicts.isNotEmpty() || fileErrors.isNotEmpty()

                    if (!hasIssues) {
                        setStatus(
                            "✓ Sync complete\n" +
                            "${uploads.size} uploaded, ${downloads.size} downloaded."
                        )
                    } else {
                        val issueSummary =
                            buildString {
                                append("⚠ Sync complete with issues.\n")
                                append("${uploads.size - fileErrors.count { it.action == "UPLOAD" }} uploaded, ")
                                append("${downloads.size - fileErrors.count { it.action == "DOWNLOAD" }} downloaded, ")
                                append("${conflicts.size} conflict(s), ")
                                append("${fileErrors.size} file error(s).\n")
                                if (conflicts.isNotEmpty()) {
                                    append("Original conflict files were not changed.\n")
                                }
                                append("Failed files were skipped; other files continued syncing.")
                            }
                        setStatus(issueSummary)
                    }

                    // Tell the Windows server the sync session is finished.
                    // The server will acknowledge, restore Bluetooth if it
                    // was initially off, and then terminate.
                    sendSecureCommand(
                        bluetoothOutput!!,
                        "SYNC_DONE"
                    )

                    val shutdownResponse =
                        readSecureFrameAsString(
                            bluetoothInput!!
                        )

                    if (shutdownResponse != "SYNC_DONE_OK") {
                        throw Exception(
                            "Unexpected Windows shutdown response: $shutdownResponse"
                        )
                    }

                    logEvent(
                        "SYNC_DONE",
                        "android_to_windows=${uploads.size} windows_to_android=${downloads.size} conflicts=${conflicts.size} file_errors=${fileErrors.size}"
                    )

                    if (fileErrors.isEmpty() && conflicts.isEmpty()) {
                        addSyncHistory(
                            success = true,
                            uploads = uploads.size,
                            downloads = downloads.size,
                            conflicts = 0
                        )
                    } else {
                        val details = buildString {
                            append("uploaded=${uploads.size - fileErrors.count { it.action == "UPLOAD" }}")
                            append(" downloaded=${downloads.size - fileErrors.count { it.action == "DOWNLOAD" }}")
                            append(" conflicts=${conflicts.size}")
                            append(" file_errors=${fileErrors.size}")
                            if (fileErrors.isNotEmpty()) {
                                append(" | ")
                                append(
                                    fileErrors.joinToString("; ") {
                                        "${it.action} ${it.path}: ${it.message}"
                                    }
                                )
                            }
                        }
                        addSyncHistory(
                            success = false,
                            uploads = uploads.size - fileErrors.count { it.action == "UPLOAD" },
                            downloads = downloads.size - fileErrors.count { it.action == "DOWNLOAD" },
                            conflicts = conflicts.size,
                            error = "COMPLETED_WITH_ISSUES|$details"
                        )
                    }

                    syncInProgress = false
                    autoSyncStartedThisSession = true

                    if (hasIssues) {
                        displaySyncIssues(
                            conflicts,
                            fileErrors
                        )
                        closeBluetoothConnection()
                        restoreBluetoothAfterSync()
                    } else {
                        closeBluetoothConnection()
                        restoreBluetoothAfterSync()

                        runOnUiThread {
                            finishAndRemoveTask()
                        }
                    }

                } catch (e: Exception) {

                    syncInProgress = false
                    autoSyncStartedThisSession = false
                    logEvent("SYNC_FAILED", e.message ?: e.javaClass.simpleName)

                    addSyncHistory(
                        success = false,
                        error = e.message ?: e.javaClass.simpleName
                    )

                    setStatus(
                        "● Sync failed:\n" +
                        "${e.message}"
                    )

                    // Mirror the cleanup on every success/conflict path
                    // below: by the time an exception reaches here,
                    // Windows has already ended its side of the session
                    // (a single Windows run exits on any error), so this
                    // socket cannot be reused. Leaving it open would make
                    // the next SYNC attempt fail against a dead
                    // connection instead of reconnecting cleanly.
                    closeBluetoothConnection()
                    restoreBluetoothAfterSync()
                }
            }

        }.start()
    }


    private fun compareDirectories():
        List<SyncResult> {

        val caseCollisions =
            (localFiles.map { it.path } + windowsFiles.map { it.path })
                .groupBy { it.lowercase() }
                .values
                .map { paths -> paths.distinct() }
                .filter { paths -> paths.size > 1 }

        if (caseCollisions.isNotEmpty()) {
            val details = caseCollisions
                .take(5)
                .joinToString("; ") { it.joinToString(" vs ") }
            throw Exception(
                "Case-insensitive filename collision; sync stopped: $details"
            )
        }

        val localMap =
            localFiles.associateBy {
                it.path
            }

        val windowsMap =
            windowsFiles.associateBy {
                it.path
            }

        val allPaths =
            (localMap.keys + windowsMap.keys)
                .distinct()
                .sortedBy { it.lowercase() }

        val results =
            mutableListOf<SyncResult>()

        for (path in allPaths) {

            val local =
                localMap[path]

            val windows =
                windowsMap[path]

            if (local != null && windows != null) {

                if (
                    local.hash.equals(
                        windows.hash,
                        ignoreCase = true
                    )
                ) {

                    saveLastSyncedHash(
                        path,
                        local.hash
                    )

                    results.add(
                        SyncResult(
                            path,
                            SyncAction.SAME,
                            "Same content"
                        )
                    )

                } else {

                    val lastHash =
                        getLastSyncedHash(path)

                    when {

                        lastHash != null &&
                        local.hash.equals(
                            lastHash,
                            ignoreCase = true
                        ) &&
                        !windows.hash.equals(
                            lastHash,
                            ignoreCase = true
                        ) -> {

                            results.add(
                                SyncResult(
                                    path,
                                    SyncAction.DOWNLOAD,
                                    "Windows changed since last successful sync"
                                )
                            )
                        }

                        lastHash != null &&
                        windows.hash.equals(
                            lastHash,
                            ignoreCase = true
                        ) &&
                        !local.hash.equals(
                            lastHash,
                            ignoreCase = true
                        ) -> {

                            results.add(
                                SyncResult(
                                    path,
                                    SyncAction.UPLOAD,
                                    "Android changed since last successful sync"
                                )
                            )
                        }

                        else -> {

                            results.add(
                                SyncResult(
                                    path,
                                    SyncAction.CONFLICT,
                                    "Both sides changed since last successful sync"
                                )
                            )
                        }
                    }
                }

                continue
            }

            if (local != null && windows == null) {

                results.add(
                    SyncResult(
                        path,
                        SyncAction.UPLOAD,
                        "Only on Android"
                    )
                )

                continue
            }

            if (local == null && windows != null) {

                results.add(
                    SyncResult(
                        path,
                        SyncAction.DOWNLOAD,
                        "Only on Windows"
                    )
                )
            }
        }

        return results
    }


    // ========================================================
    // FRAMED PROTOCOL
    // ========================================================

    private fun sendFrame(
        output: OutputStream,
        data: ByteArray,
        length: Int
    ) {
        require(length in 0..data.size)
        require(length <= MAX_FRAME_BYTES)

        val header =
            ByteBuffer
                .allocate(4)
                .order(ByteOrder.BIG_ENDIAN)
                .putInt(length)
                .array()

        try {
            output.write(header)
            output.write(data, 0, length)
        } catch (e: Exception) {
            throw SyncTransportException(
                e.message ?: "Bluetooth send failed.",
                e
            )
        }
    }


    private fun sendFrame(
        output: OutputStream,
        data: ByteArray
    ) {
        require(data.size <= MAX_FRAME_BYTES)
        sendFrame(
            output,
            data,
            data.size
        )
    }


    private fun sendCommand(
        output: OutputStream,
        command: String
    ) {

        sendFrame(
            output,
            command.toByteArray(
                Charsets.UTF_8
            )
        )
        output.flush()
    }


    private fun flushBluetoothOutput() {
        try {
            bluetoothOutput?.flush()
        } catch (_: Exception) {
        }
    }


    private fun readExact(
        input: InputStream,
        size: Int
    ): ByteArray {

        val data =
            ByteArray(size)

        var offset =
            0

        while (
            offset < size
        ) {

            val count = try {
                input.read(
                    data,
                    offset,
                    size - offset
                )
            } catch (e: Exception) {
                throw SyncTransportException(
                    e.message ?: "Bluetooth read failed.",
                    e
                )
            }

            if (
                count < 0
            ) {

                throw SyncTransportException(
                    "Socket closed while reading."
                )
            }

            if (
                count == 0
            ) {

                continue
            }

            offset += count
        }

        return data
    }


    private fun readFrame(
        input: InputStream
    ): ByteArray {

        val header =
            readExact(
                input,
                4
            )

        val size =
            ByteBuffer
                .wrap(header)
                .order(
                    ByteOrder.BIG_ENDIAN
                )
                .int

        if (
            size < 0 ||
            size > MAX_FRAME_BYTES
        ) {

            throw SyncTransportException(
                "Invalid frame size: $size"
            )
        }

        return readExact(
            input,
            size
        )
    }


    private fun readFrameAsString(
        input: InputStream
    ): String {

        return String(
            readFrame(input),
            Charsets.UTF_8
        )
    }


    private fun requireSecureChannel(): SecureChannel {
        return secureChannel
            ?: throw SyncTransportException("Secure channel is not established.")
    }

    private fun sendSecureFrame(
        output: OutputStream,
        data: ByteArray,
        flush: Boolean = false
    ) {
        sendFrame(
            output,
            requireSecureChannel().encrypt(data)
        )
        if (flush) {
            try {
                output.flush()
            } catch (e: Exception) {
                throw SyncTransportException(
                    e.message ?: "Bluetooth flush failed.",
                    e
                )
            }
        }
    }

    private fun sendSecureFrame(
        output: OutputStream,
        data: ByteArray,
        length: Int,
        flush: Boolean = false
    ) {
        require(length in 0..data.size)
        val encrypted = requireSecureChannel().encrypt(data, 0, length)
        sendFrame(output, encrypted, encrypted.size)
        if (flush) {
            try {
                output.flush()
            } catch (e: Exception) {
                throw SyncTransportException(
                    e.message ?: "Bluetooth flush failed.",
                    e
                )
            }
        }
    }

    private fun sendSecureCommand(
        output: OutputStream,
        command: String
    ) {
        sendSecureFrame(
            output,
            command.toByteArray(Charsets.UTF_8),
            flush = true
        )
    }

    private fun readSecureFrame(input: InputStream): ByteArray {
        val frame = readFrame(input)
        return try {
            requireSecureChannel().decrypt(frame)
        } catch (e: Exception) {
            throw SyncTransportException(
                e.message ?: "Secure frame verification failed.",
                e
            )
        }
    }

    private fun readSecureFrameAsString(input: InputStream): String {
        return String(readSecureFrame(input), Charsets.UTF_8)
    }


    // ========================================================
    // CLOSE CONNECTION
    // ========================================================

    private fun closeBluetoothConnection() {

        try {
            bluetoothSocket?.close()
        } catch (_: Exception) {
        }

        bluetoothSocket =
            null

        bluetoothInput =
            null

        bluetoothOutput =
            null

        secureChannel =
            null

        runOnUiThread {

            syncButton.isEnabled =
                false
        }
    }


    // ========================================================
    // FILE SIZE
    // ========================================================

    private fun formatFileSize(
        bytes: Long
    ): String {

        return when {

            bytes < 1024 ->
                "$bytes B"

            bytes < 1024 * 1024 ->
                "%.1f KB".format(
                    bytes / 1024.0
                )

            bytes < 1024 * 1024 * 1024 ->
                "%.1f MB".format(
                    bytes /
                    (1024.0 * 1024.0)
                )

            else ->
                "%.1f GB".format(
                    bytes /
                    (1024.0 *
                     1024.0 *
                     1024.0)
                )
        }
    }


    // ========================================================
    // PERMISSIONS
    // ========================================================

    private fun bluetoothPermissionsGranted():
        Boolean {

        return if (
            Build.VERSION.SDK_INT >=
            Build.VERSION_CODES.S
        ) {

            checkSelfPermission(
                Manifest.permission.BLUETOOTH_SCAN
            ) ==
                PackageManager.PERMISSION_GRANTED &&

            checkSelfPermission(
                Manifest.permission.BLUETOOTH_CONNECT
            ) ==
                PackageManager.PERMISSION_GRANTED

        } else {

            true
        }
    }


    private fun requestBluetoothPermissions() {

        if (
            Build.VERSION.SDK_INT >=
            Build.VERSION_CODES.S
        ) {

            requestPermissions(
                arrayOf(
                    Manifest.permission.BLUETOOTH_SCAN,
                    Manifest.permission.BLUETOOTH_CONNECT
                ),
                100
            )
        }
    }


    // ========================================================
    // SCAN
    // ========================================================

    @SuppressLint("MissingPermission")
    private fun startBluetoothScan() {

        if (
            !bluetoothPermissionsGranted()
        ) {

            requestBluetoothPermissions()

            return
        }

        if (
            !bluetoothAdapter.isEnabled
        ) {

            setStatus(
                "● Bluetooth is disabled"
            )

            return
        }

        closeBluetoothConnection()

        devices.clear()

        deviceAdapter.notifyDataSetChanged()

        setStatus(
            "● Scanning for Bluetooth devices..."
        )

        if (
            bluetoothAdapter.isDiscovering
        ) {

            bluetoothAdapter.cancelDiscovery()
        }

        bluetoothAdapter.startDiscovery()

        for (
            device in
            bluetoothAdapter.bondedDevices
        ) {

            val name =
                device.name
                    ?: "Unknown device"

            val address =
                device.address

            val entry =
                "$name\n$address"

            if (
                !devices.contains(entry)
            ) {

                devices.add(entry)
            }
        }

        deviceAdapter.notifyDataSetChanged()
    }


    // ========================================================
    // LIFECYCLE
    // ========================================================

    override fun onResume() {
        super.onResume()

        // Re-check automatic startup after the activity returns to the
        // foreground. This covers the asynchronous Bluetooth enable and
        // connection lifecycle without requiring the user to press SYNC.
        if (::bluetoothAdapter.isInitialized) {
            tryAutoSync()
        }
    }


    // ========================================================
    // CLEANUP
    // ========================================================

    override fun onDestroy() {

        if (!sessionEndedLogged && currentSessionId != "------------") {
            sessionEndedLogged = true
            logEvent("SESSION_ENDED")
        }

        closeBluetoothConnection()

        localScanExecutor.shutdownNow()
        logExecutor.shutdown()

        if (receiverRegistered) {
            try {
                @Suppress("DEPRECATION")
                unregisterReceiver(
                    receiver
                )
            } catch (_: IllegalArgumentException) {
                // Receiver may already have been unregistered by the framework.
            }
            receiverRegistered = false
        }

        super.onDestroy()
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {

        super.onRequestPermissionsResult(
            requestCode,
            permissions,
            grantResults
        )

        if (requestCode == 100) {

            if (bluetoothPermissionsGranted()) {
                ensureBluetoothReady()
            } else {
                setStatus(
                    "● Bluetooth permission is required"
                )
            }
        }
    }

}
