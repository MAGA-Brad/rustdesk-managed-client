// RustDrop's native UI - a separate top-level Flutter app (launched via
// --rustdrop, see main.dart's runRustDropScreen()), not a multi_window
// sub-window of the main app. Ports the retired Electron client's
// renderer/app.js UI to Dart, faithfully mirroring its layout and behavior
// (see that client's renderer/{index.html,app.js} for the original): a
// single scrolling page - Incoming, Send a file, Send to
// (Favorites/Directory toggle over a device grid), Sent - rather than a
// tabbed Directory/Drops split.

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/desktop/widgets/tabbar_widget.dart';
import 'package:flutter_hbb/models/platform_model.dart';
import 'package:get/get.dart';

/// `state` mirrors rustdrop_transfer.rs's TransferState: "active",
/// "retrying" (automatic backoff, no user action), "paused" (user hit
/// Pause), or "stalled" (same gate as paused, set automatically after
/// prolonged zero progress - see that file's doc comment on why this
/// isn't just a bigger timeout).
class _ProgressInfo {
  final double fraction;
  final String state;
  const _ProgressInfo(this.fraction, this.state);
}

class DesktopRustDropScreen extends StatefulWidget {
  const DesktopRustDropScreen({super.key});

  @override
  State<DesktopRustDropScreen> createState() => _DesktopRustDropScreenState();
}

class _DesktopRustDropScreenState extends State<DesktopRustDropScreen> {
  final tabController = DesktopTabController(tabType: DesktopTabType.install);

  _DesktopRustDropScreenState() {
    Get.put<DesktopTabController>(tabController);
    const label = "rustdrop";
    tabController.add(TabInfo(
      key: label,
      label: "RustDrop",
      closable: false,
      page: const _RustDropBody(key: ValueKey(label)),
    ));
  }

  @override
  void dispose() {
    super.dispose();
    Get.delete<DesktopTabController>();
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      child: Scaffold(
        backgroundColor: Theme.of(context).colorScheme.surface,
        body: DesktopTab(controller: tabController),
      ),
    );
  }
}

// A stable color per device (by deviceId) rather than anything meaningful -
// purely so cards in a growing directory stay visually distinct at a glance.
// Same palette/hash as the retired Electron client's app.js.
const _kAvatarColors = [
  Color(0xFFc4622d),
  Color(0xFF3654c9),
  Color(0xFF0f9b8e),
  Color(0xFFa35bc9),
  Color(0xFFc94f6e),
  Color(0xFF5b8fc9),
  Color(0xFF8a9b3f),
  Color(0xFFc98f3f),
];

Color _avatarColor(String deviceId) {
  var hash = 0;
  for (final unit in deviceId.codeUnits) {
    hash = (hash * 31 + unit) & 0x7fffffff;
  }
  return _kAvatarColors[hash % _kAvatarColors.length];
}

class RustDropDevice {
  final String deviceId;
  final String rustdeskId;
  final String? friendlyName;
  final String? hostname;
  final String? publicKey;

  RustDropDevice.fromJson(Map<String, dynamic> json)
      : deviceId = json['device_id'],
        rustdeskId = json['rustdesk_id'],
        friendlyName = json['friendly_name'],
        hostname = json['hostname'],
        publicKey = json['public_key'];

  String get displayName => friendlyName ?? rustdeskId;
}

class RustDropDrop {
  final String id;
  final String senderDeviceId;
  final String recipientDeviceId;
  final String filename;
  final int declaredSize;
  final String status;
  final String? senderPublicKey;
  final String? peerFriendlyName;
  final String? peerHostname;
  final DateTime? expiresAt;

  RustDropDrop.fromJson(Map<String, dynamic> json)
      : id = json['id'],
        senderDeviceId = json['sender_device_id'],
        recipientDeviceId = json['recipient_device_id'],
        filename = json['filename'],
        declaredSize = json['declared_size'],
        status = json['status'],
        senderPublicKey = json['sender_public_key'],
        peerFriendlyName = json['peer_friendly_name'],
        peerHostname = json['peer_hostname'],
        expiresAt = json['expires_at'] == null
            ? null
            : DateTime.tryParse(json['expires_at'] as String);

  Map<String, dynamic> toJson() => {
        'id': id,
        'sender_device_id': senderDeviceId,
        'recipient_device_id': recipientDeviceId,
        'filename': filename,
        'declared_size': declaredSize,
        'status': status,
        'content_sha256': null,
        'sender_public_key': senderPublicKey,
        'peer_friendly_name': peerFriendlyName,
        'peer_hostname': peerHostname,
        'created_at': '',
        'expires_at': expiresAt?.toIso8601String(),
      };

  // Null while still uploading (the server only ever sets expires_at once
  // the upload completes, and renews it once a download starts - see
  // rustdrop.py) - "expires in..." only means anything once there's an
  // actual hold window ticking. Coarsened to the largest whole unit rather
  // than an exact countdown, since this refreshes on the same ~10s poll
  // cycle as everything else on this screen, not once a second.
  String? expiryLabel() {
    final at = expiresAt;
    if (at == null) return null;
    final remaining = at.difference(DateTime.now().toUtc());
    if (remaining.isNegative) return 'expired';
    if (remaining.inDays >= 1) {
      return 'expires in ${remaining.inDays}d';
    }
    if (remaining.inHours >= 1) {
      return 'expires in ${remaining.inHours}h';
    }
    return 'expires in ${remaining.inMinutes}m';
  }

  // Managed friendly names follow a "<Person>-<Device>" convention
  // (e.g. "Brad-Laptop") - the first part identifies who's on the other end
  // of the transfer, which matters more than which of their machines it is.
  // Based on the retired Electron client's peerFirstName(), minus its
  // hostname fallback - hostname never appears in the UI here.
  String get peerFirstName {
    final name = peerFriendlyName ?? 'someone';
    final parts = name.split('-');
    return parts.isNotEmpty && parts.first.isNotEmpty ? parts.first : name;
  }

  // The backend's raw status word for a Sent row is misleading as-is:
  // "complete" only means the upload to the relay finished, not that the
  // recipient has actually picked it up (that's the separate "delivered"
  // status, set once accept_drop's /complete call lands). Map to something
  // that reflects what's actually true from the sender's point of view.
  String outgoingStatusLabel() {
    switch (status) {
      case 'complete':
        return 'waiting for $peerFirstName to accept';
      case 'delivered':
        return 'delivered';
      default:
        return status;
    }
  }
}

String _formatBytes(int n) {
  if (n < 1024) return '$n B';
  if (n < 1024 * 1024) return '${(n / 1024).toStringAsFixed(1)} KB';
  return '${(n / (1024 * 1024)).toStringAsFixed(1)} MB';
}

class _RustDropBody extends StatefulWidget {
  const _RustDropBody({super.key});

  @override
  State<_RustDropBody> createState() => _RustDropBodyState();
}

const _kFavoritesOptionKey = 'rustdrop-favorite-devices';

class _PickedFile {
  final String path;
  final String name;
  final int size;
  _PickedFile(this.path, this.name, this.size);
}

class _RustDropBodyState extends State<_RustDropBody> {
  bool _initializing = true;
  String? _initError;
  List<RustDropDevice> _devices = [];
  List<RustDropDrop> _incoming = [];
  List<RustDropDrop> _outgoing = [];
  Timer? _refreshTimer;
  bool _refreshing = false;
  int _refreshTicks = 0;
  DateTime? _lastFailedRefresh;
  final Set<String> _busyDropIds = {};
  final Set<String> _declinedDropIds = {};
  Set<String> _favoriteIds = {};
  String _activeDeviceTab = 'directory'; // 'favorites' | 'directory'
  _PickedFile? _pickedFile;
  String _sendStatus = '';
  bool _sendStatusOk = false;
  String _directoryStatusText = 'Connecting...';
  String _directoryStatusState = 'unavailable';
  // "Stage a Send": if you hit Send while not yet connected to RDS, the
  // send waits (indefinitely, no timeout) for the same connection status
  // the footer already shows to become 'ready', then fires for real.
  // Session-only - closing the app drops a still-staged send, it does not
  // persist or auto-resume.
  RustDropDevice? _stagedSendDevice;
  Timer? _progressTimer;
  final Map<String, _ProgressInfo> _progressByDropId = {};

  @override
  void initState() {
    super.initState();
    _loadFavorites();
    _init();
    _progressTimer =
        Timer.periodic(const Duration(seconds: 1), (_) => _pollProgress());
  }

  void _pollProgress() {
    final activeIds = [
      for (final d in _outgoing)
        if (d.status == 'uploading') d.id,
      for (final d in _incoming)
        if (_busyDropIds.contains(d.id)) d.id,
    ];
    if (activeIds.isEmpty && _progressByDropId.isEmpty) return;
    final next = <String, _ProgressInfo>{};
    for (final id in activeIds) {
      final raw = bind.crateFlutterFfiRustdropTransferProgress(dropId: id);
      try {
        final parsed = jsonDecode(raw) as Map<String, dynamic>;
        if (parsed['active'] == true) {
          final done = (parsed['bytes_done'] as num).toDouble();
          final total = (parsed['total_bytes'] as num).toDouble();
          final state = parsed['state'] as String? ?? 'active';
          if (total > 0) {
            next[id] = _ProgressInfo((done / total).clamp(0.0, 1.0), state);
          }
        }
      } catch (_) {
        // Best-effort - a transient parse hiccup just skips this tick's bar.
      }
    }
    if (!mounted) return;
    setState(() {
      _progressByDropId
        ..clear()
        ..addAll(next);
    });
  }

  void _loadFavorites() {
    final raw =
        bind.crateFlutterFfiMainGetLocalOption(key: _kFavoritesOptionKey);
    if (raw.isEmpty) return;
    try {
      final list = jsonDecode(raw) as List;
      setState(() => _favoriteIds = list.cast<String>().toSet());
    } catch (_) {
      // Corrupt/empty option value - just start with no favorites.
    }
  }

  Future<void> _toggleFavorite(RustDropDevice device) async {
    setState(() {
      if (_favoriteIds.contains(device.deviceId)) {
        _favoriteIds.remove(device.deviceId);
      } else {
        _favoriteIds.add(device.deviceId);
      }
    });
    await bind.crateFlutterFfiMainSetLocalOption(
      key: _kFavoritesOptionKey,
      value: jsonEncode(_favoriteIds.toList()),
    );
  }

  @override
  void dispose() {
    _refreshTimer?.cancel();
    _progressTimer?.cancel();
    super.dispose();
  }

  Future<void> _init() async {
    final raw = await bind.crateFlutterFfiRustdropInit();
    if (!mounted) return;
    final parsed = jsonDecode(raw) as Map<String, dynamic>;
    if (parsed.containsKey('error')) {
      setState(() {
        _initializing = false;
        _initError = parsed['error'].toString();
      });
      return;
    }
    setState(() {
      _initializing = false;
    });
    await _refresh();
    if (!mounted) return;
    // On Windows the lists come from a local cache that is only refetched when RDS reports a
    // change (rustdrop_list_devices / rustdrop_list_drops in flutter_ffi.rs), so a short tick is
    // cheap there; elsewhere every tick is a real fetch.
    _refreshTimer = Timer.periodic(
        Duration(seconds: Platform.isWindows ? 2 : 10), (_) => _refreshFromTimer());
  }

  /// After a failed fetch the cache holds nothing, so fall back to the old 10-second pace; the
  /// directory status (a blocking IPC call) stays on that pace too.
  void _refreshFromTimer() {
    final failedAt = _lastFailedRefresh;
    if (failedAt != null &&
        DateTime.now().difference(failedAt) < const Duration(seconds: 10)) {
      return;
    }
    final every = Platform.isWindows ? 5 : 1;
    _refresh(withStatus: _refreshTicks++ % every == 0);
  }

  void _loadDirectoryStatus() {
    try {
      final raw = bind.crateFlutterFfiMainGetManagedDirectoryStatus();
      if (raw.isEmpty) return;
      final parsed = jsonDecode(raw) as Map<String, dynamic>;
      if (!mounted) return;
      final wasReady = _directoryStatusState == 'ready';
      setState(() {
        _directoryStatusText =
            (parsed['text'] as String?)?.trim().isNotEmpty == true
                ? parsed['text'] as String
                : 'Not connected';
        _directoryStatusState = (parsed['state'] as String?) ?? 'unavailable';
      });
      // Fire a staged send the moment the same connection status the footer
      // already shows flips to 'ready' - reuses that existing check rather
      // than inventing a separate connectivity probe.
      final staged = _stagedSendDevice;
      if (!wasReady && _directoryStatusState == 'ready' && staged != null) {
        _stagedSendDevice = null;
        _performSend(staged);
      }
    } catch (_) {
      // Best-effort - keep whatever status was last shown.
    }
  }

  Future<void> _refresh({bool withStatus = true}) async {
    // Timer.periodic doesn't wait for a previous tick to finish before
    // starting the next one - without this guard, a slow poll cycle (e.g.
    // during the known RDS-connectivity issues this feature has hit before)
    // could overlap with a newer one, and whichever response happens to
    // land last would win regardless of which was actually more recent.
    if (_refreshing) return;
    _refreshing = true;
    try {
      await _refreshOnce(withStatus);
    } finally {
      _refreshing = false;
    }
  }

  Future<void> _refreshOnce(bool withStatus) async {
    if (withStatus) _loadDirectoryStatus();
    final devicesRaw = await bind.crateFlutterFfiRustdropListDevices();
    final dropsRaw = await bind.crateFlutterFfiRustdropListDrops();
    if (!mounted) return;
    try {
      final devicesJson = jsonDecode(devicesRaw);
      final dropsJson = jsonDecode(dropsRaw) as Map<String, dynamic>;
      _lastFailedRefresh = devicesJson is List && !dropsJson.containsKey('error')
          ? null
          : DateTime.now();
      setState(() {
        if (devicesJson is List) {
          _devices = devicesJson
              .cast<Map<String, dynamic>>()
              .map((d) => RustDropDevice.fromJson(d))
              .toList();
        }
        if (dropsJson['incoming'] is List) {
          _incoming = (dropsJson['incoming'] as List)
              .cast<Map<String, dynamic>>()
              .map((d) => RustDropDrop.fromJson(d))
              .where((d) =>
                  (d.status == 'uploading' || d.status == 'complete') &&
                  !_declinedDropIds.contains(d.id))
              .toList();
        }
        if (dropsJson['outgoing'] is List) {
          _outgoing = (dropsJson['outgoing'] as List)
              .cast<Map<String, dynamic>>()
              .map((d) => RustDropDrop.fromJson(d))
              .take(10)
              .toList();
        }
      });
    } catch (_) {
      _lastFailedRefresh = DateTime.now();
      // Best-effort background refresh - a transient network hiccup just
      // means this poll cycle shows stale data, not a fatal error for the
      // window.
    }
  }

  Future<void> _browseForFile() async {
    final result = await FilePicker.pickFiles();
    final file = result.isEmpty ? null : result.first;
    if (file?.path == null) return;
    final path = file!.path!;
    final size = await File(path).length();
    if (!mounted) return;
    setState(() {
      _pickedFile = _PickedFile(path, file.name, size);
      _sendStatus = '';
      _sendStatusOk = false;
      _stagedSendDevice = null;
    });
  }

  Future<void> _sendTo(RustDropDevice device) async {
    final picked = _pickedFile;
    if (picked == null) {
      setState(() {
        _sendStatus = 'Choose a file first.';
        _sendStatusOk = false;
      });
      return;
    }
    if (_directoryStatusState != 'ready') {
      // Stage a Send: hold this until the same connection status the
      // footer shows flips to 'ready' (see _loadDirectoryStatus), no
      // timeout. Session-only - lost if the app closes while staged.
      setState(() {
        _stagedSendDevice = device;
        _sendStatus =
            'Waiting for connection to send ${picked.name} to ${device.displayName}...';
        _sendStatusOk = false;
      });
      return;
    }
    await _performSend(device);
  }

  Future<void> _performSend(RustDropDevice device) async {
    final picked = _pickedFile;
    if (picked == null) return;
    setState(() {
      _sendStatus = 'Sending ${picked.name} to ${device.displayName}...';
      _sendStatusOk = false;
    });
    final raw = await bind.crateFlutterFfiRustdropSendFile(
      recipientDeviceId: device.deviceId,
      localPath: picked.path,
    );
    if (!mounted) return;
    final parsed = jsonDecode(raw) as Map<String, dynamic>;
    if (parsed.containsKey('error')) {
      setState(() {
        _sendStatus = 'Failed to send: ${parsed['error']}';
        _sendStatusOk = false;
      });
    } else {
      setState(() {
        _sendStatus = 'Sent ${picked.name}.';
        _sendStatusOk = true;
        // Deliberately keep _pickedFile selected - Brad wants to send the same
        // file to multiple people without re-Browse-ing again. Cleared only by
        // the explicit Clear button (or app/computer restart, since this is
        // in-memory only and never persisted).
      });
      await _refresh();
    }
  }

  void _clearPickedFile() {
    setState(() {
      _pickedFile = null;
      _sendStatus = '';
      _sendStatusOk = false;
      _stagedSendDevice = null;
    });
  }

  Future<void> _accept(RustDropDrop drop) async {
    final defaultDir = await bind.crateFlutterFfiRustdropDefaultDownloadsDir();
    final chosenDir = await FilePicker.getDirectoryPath(
      dialogTitle: 'Save "${drop.filename}" to...',
      initialDirectory: defaultDir,
    );
    if (chosenDir == null) {
      return; // user cancelled the save dialog - leave the drop pending
    }
    if (!mounted) return;

    setState(() => _busyDropIds.add(drop.id));
    final raw = await bind.crateFlutterFfiRustdropAcceptDrop(
      dropJson: jsonEncode(drop.toJson()),
      destDir: chosenDir,
    );
    if (!mounted) return;
    final parsed = jsonDecode(raw) as Map<String, dynamic>;
    if (parsed.containsKey('error')) {
      setState(() => _busyDropIds.remove(drop.id));
      _showError(parsed['error'].toString());
    } else {
      setState(() => _declinedDropIds
          .add(drop.id)); // reuse: drop out of Incoming once accepted
      await _refresh();
    }
  }

  Future<void> _decline(RustDropDrop drop) async {
    setState(() => _busyDropIds.add(drop.id));
    final raw = await bind.crateFlutterFfiRustdropDeclineDrop(dropId: drop.id);
    if (!mounted) return;
    final parsed = jsonDecode(raw) as Map<String, dynamic>;
    if (parsed.containsKey('error')) {
      setState(() => _busyDropIds.remove(drop.id));
      _showError(parsed['error'].toString());
    } else {
      setState(() => _declinedDropIds.add(drop.id));
      await _refresh();
    }
  }

  void _showError(String message) {
    ScaffoldMessenger.of(context)
        .showSnackBar(SnackBar(content: Text(message)));
  }

  @override
  Widget build(BuildContext context) {
    if (_initializing) {
      return const Center(child: CircularProgressIndicator());
    }
    if (_initError != null) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Text(
            'RustDrop is not available on this device: $_initError',
            textAlign: TextAlign.center,
          ),
        ),
      );
    }
    final dimText =
        Theme.of(context).textTheme.bodySmall?.color?.withValues(alpha: 0.6);
    return Column(
      children: [
        Container(
          width: double.infinity,
          padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
          decoration: BoxDecoration(
            color: Theme.of(context).scaffoldBackgroundColor,
            border: Border(
                bottom: BorderSide(color: Theme.of(context).dividerColor)),
          ),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              loadIcon(20),
              const SizedBox(width: 8),
              const Text('RustDrop',
                  style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
            ],
          ),
        ),
        Expanded(
          child: Container(
            color: Theme.of(context).scaffoldBackgroundColor,
            child: _buildBody(dimText),
          ),
        ),
        Container(
          width: double.infinity,
          padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 10),
          decoration: BoxDecoration(
            color: Theme.of(context).colorScheme.surface,
            border:
                Border(top: BorderSide(color: Theme.of(context).dividerColor)),
          ),
          child: Row(
            children: [
              Container(
                width: 8,
                height: 8,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color:
                      _directoryStatusState == 'ready' ? Colors.green : dimText,
                ),
              ),
              const SizedBox(width: 8),
              Text(_directoryStatusText,
                  style: TextStyle(fontSize: 12, color: dimText)),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildBody(Color? dimText) {
    return RefreshIndicator(
      onRefresh: _refresh,
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          _sectionHeader('Incoming'),
          if (_incoming.isEmpty)
            Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: Text('Nothing waiting for you right now.',
                  style: TextStyle(fontSize: 12, color: dimText)),
            )
          else
            for (final drop in _incoming) _buildDropRow(drop, incoming: true),
          const SizedBox(height: 12),
          _sectionHeader('Send a file'),
          _buildFilePicker(),
          if (_sendStatus.isNotEmpty)
            Padding(
              padding: const EdgeInsets.only(top: 6),
              child: Row(
                children: [
                  if (_stagedSendDevice != null)
                    const Padding(
                      padding: EdgeInsets.only(right: 6),
                      child: SizedBox(
                          width: 12,
                          height: 12,
                          child: CircularProgressIndicator(strokeWidth: 2)),
                    ),
                  Flexible(
                    child: Text(_sendStatus,
                        style: TextStyle(
                            fontSize: 12,
                            color: _sendStatusOk
                                ? Colors.green
                                : _stagedSendDevice != null
                                    ? Colors.orange
                                    : dimText)),
                  ),
                ],
              ),
            ),
          const SizedBox(height: 12),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              _sectionHeader('Send to', padding: EdgeInsets.zero),
              _buildDeviceTabButtons(),
            ],
          ),
          const SizedBox(height: 8),
          _buildDeviceGrid(),
          const SizedBox(height: 12),
          _sectionHeader('Sent'),
          if (_outgoing.isEmpty)
            Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: Text('Nothing sent yet.',
                  style: TextStyle(fontSize: 12, color: dimText)),
            )
          else
            for (final drop in _outgoing) _buildDropRow(drop, incoming: false),
        ],
      ),
    );
  }

  Widget _sectionHeader(String text,
      {EdgeInsets padding = const EdgeInsets.fromLTRB(0, 4, 0, 8)}) {
    return Padding(
      padding: padding,
      child: Text(text,
          style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 15)),
    );
  }

  Widget _buildDeviceTabButtons() {
    Widget tabButton(String key, String label) {
      final active = _activeDeviceTab == key;
      return InkWell(
        onTap: () => setState(() => _activeDeviceTab = key),
        child: Padding(
          padding: const EdgeInsets.only(left: 14),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.center,
            children: [
              Text(
                label.toUpperCase(),
                style: TextStyle(
                  fontSize: 11,
                  letterSpacing: 0.5,
                  fontWeight: FontWeight.bold,
                  color: active
                      ? Theme.of(context).colorScheme.primary
                      : Theme.of(context)
                          .textTheme
                          .bodySmall
                          ?.color
                          ?.withValues(alpha: 0.6),
                ),
              ),
              const SizedBox(height: 4),
              Container(
                height: 2,
                width: label.length * 7,
                color: active
                    ? Theme.of(context).colorScheme.primary
                    : Colors.transparent,
              ),
            ],
          ),
        ),
      );
    }

    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        tabButton('favorites', 'Favorites'),
        tabButton('directory', 'Directory'),
      ],
    );
  }

  Widget _buildFilePicker() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(
        border: Border.all(
            color: Theme.of(context).dividerColor, style: BorderStyle.solid),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Row(
        children: [
          Expanded(
            child: Text(
              _pickedFile == null
                  ? 'No file chosen'
                  : '${_pickedFile!.name} (${_formatBytes(_pickedFile!.size)})',
              overflow: TextOverflow.ellipsis,
              style: TextStyle(
                fontSize: 13,
                color: _pickedFile == null
                    ? Theme.of(context)
                        .textTheme
                        .bodySmall
                        ?.color
                        ?.withValues(alpha: 0.6)
                    : null,
              ),
            ),
          ),
          const SizedBox(width: 8),
          OutlinedButton(
              onPressed: _browseForFile, child: const Text('Browse')),
          const SizedBox(width: 8),
          OutlinedButton(
            onPressed: _pickedFile == null ? null : _clearPickedFile,
            child: const Text('Clear'),
          ),
        ],
      ),
    );
  }

  Widget _buildDeviceGrid() {
    final visible = _activeDeviceTab == 'favorites'
        ? _devices.where((d) => _favoriteIds.contains(d.deviceId)).toList()
        : _devices;

    if (_devices.isEmpty) {
      return const Text('No other devices have RustDrop running right now.',
          style: TextStyle(fontSize: 13));
    }
    if (visible.isEmpty && _activeDeviceTab == 'favorites') {
      return const Text(
          'No favorites yet - star someone from the Directory tab.',
          style: TextStyle(fontSize: 13));
    }
    return Wrap(
      spacing: 8,
      runSpacing: 8,
      children: [
        for (final device in visible)
          ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 260),
            child: _buildDeviceCard(device),
          ),
      ],
    );
  }

  Widget _buildDeviceCard(RustDropDevice device) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 5),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        borderRadius: BorderRadius.circular(8),
      ),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          borderRadius: BorderRadius.circular(8),
          onTap: () => _sendTo(device),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                width: 26,
                height: 26,
                decoration: BoxDecoration(
                  color: _avatarColor(device.deviceId),
                  borderRadius: BorderRadius.circular(7),
                ),
                child: const Icon(Icons.desktop_windows,
                    size: 14, color: Colors.white),
              ),
              const SizedBox(width: 8),
              Flexible(
                child: Text(
                  device.displayName,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: const TextStyle(
                      fontWeight: FontWeight.w600, fontSize: 12),
                ),
              ),
              PopupMenuButton<void>(
                padding: EdgeInsets.zero,
                icon: const Text('⋯', style: TextStyle(fontSize: 14)),
                tooltip: 'More',
                itemBuilder: (context) {
                  final isFavorite = _favoriteIds.contains(device.deviceId);
                  return [
                    PopupMenuItem(
                      child: Text(isFavorite
                          ? '★ Remove from Favorites'
                          : '☆ Add to Favorites'),
                      onTap: () => _toggleFavorite(device),
                    ),
                  ];
                },
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildDropRow(RustDropDrop drop, {required bool incoming}) {
    final busy = _busyDropIds.contains(drop.id);
    final peerLabel =
        incoming ? 'From ${drop.peerFirstName}' : 'To ${drop.peerFirstName}';
    final progress = _progressByDropId[drop.id];
    final stateSuffix = switch (progress?.state) {
      'retrying' => ' - retrying...',
      'stalled' => ' - stalled',
      _ => '',
    };
    // Shown on both sides once the drop has a real hold window ticking -
    // the sender while it's sitting there waiting for the recipient to act,
    // and the recipient while they're deciding whether to accept/decline -
    // so neither party is surprised by it disappearing. Null (still
    // uploading, no expires_at yet) adds nothing.
    final expirySuffix =
        drop.expiryLabel() != null ? ' - ${drop.expiryLabel()}' : '';
    final sub = incoming
        ? '$peerLabel$expirySuffix'
        : '$peerLabel - ${drop.outgoingStatusLabel()}${drop.declaredSize > 0 ? " - ${_formatBytes(drop.declaredSize)}" : ""}$expirySuffix$stateSuffix';
    final showActions = incoming && !busy;
    final showPauseResume =
        !incoming && drop.status == 'uploading' && progress != null;

    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        border: Border.all(color: Theme.of(context).dividerColor),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: [
          Row(
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Tooltip(
                      message: drop.filename,
                      child: Text(
                        drop.filename,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: const TextStyle(
                            fontWeight: FontWeight.w600, fontSize: 13),
                      ),
                    ),
                    const SizedBox(height: 2),
                    Text(sub,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: TextStyle(
                            fontSize: 11,
                            color: Theme.of(context)
                                .textTheme
                                .bodySmall
                                ?.color
                                ?.withValues(alpha: 0.6))),
                  ],
                ),
              ),
              if (busy && progress == null)
                const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(strokeWidth: 2))
              else if (showActions) ...[
                TextButton(
                    onPressed: () => _decline(drop),
                    child: const Text('Decline')),
                const SizedBox(width: 4),
                ElevatedButton(
                    onPressed: () => _accept(drop),
                    child: const Text('Accept')),
              ] else if (showPauseResume)
                IconButton(
                  icon: Icon(
                    progress.state == 'paused' || progress.state == 'stalled'
                        ? Icons.play_arrow
                        : Icons.pause,
                    size: 18,
                  ),
                  tooltip:
                      progress.state == 'paused' || progress.state == 'stalled'
                          ? 'Resume'
                          : 'Pause',
                  onPressed: () {
                    final resuming = progress.state == 'paused' ||
                        progress.state == 'stalled';
                    final raw = resuming
                        ? bind.crateFlutterFfiRustdropResumeTransfer(
                            dropId: drop.id)
                        : bind.crateFlutterFfiRustdropPauseTransfer(
                            dropId: drop.id);
                    try {
                      final parsed = jsonDecode(raw) as Map<String, dynamic>;
                      // Wire format is {"ok": bool} (see rustdrop_pause_transfer/
                      // rustdrop_resume_transfer in flutter_ffi.rs) - false means
                      // the transfer already finished or was never tracked, not
                      // a parseable error string, so this is a plain fallback
                      // message rather than surfacing parsed['error'].
                      if (parsed['ok'] != true) {
                        _showError(resuming
                            ? 'Could not resume - the transfer may have already finished.'
                            : 'Could not pause - the transfer may have already finished.');
                      }
                    } catch (_) {
                      // Best-effort - an unparseable result just skips the
                      // error surface, matching this file's other handlers.
                    }
                    _pollProgress();
                  },
                ),
            ],
          ),
          if (progress != null) ...[
            const SizedBox(height: 6),
            ClipRRect(
              borderRadius: BorderRadius.circular(4),
              child: LinearProgressIndicator(
                value: progress.fraction,
                minHeight: 4,
                backgroundColor: Theme.of(context).dividerColor,
              ),
            ),
          ],
        ],
      ),
    );
  }
}
