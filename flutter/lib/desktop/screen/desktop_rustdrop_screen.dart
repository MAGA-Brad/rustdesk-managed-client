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

import 'package:desktop_drop/desktop_drop.dart';
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
  // The recipient is receiving it right now (RDS then refuses the sender's cancel).
  final bool downloading;

  // The sender picks the name: bidi and override marks could make "invoice\u202Efdp.exe" read as
  // "invoiceexe.pdf". Display only; the Rust side sanitizes the name it saves under.
  static final _bidiControls =
      RegExp('[\u200E\u200F\u202A-\u202E\u2066-\u2069]');
  String get displayFilename => filename.replaceAll(_bidiControls, '');

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
            : DateTime.tryParse(json['expires_at'] as String),
        downloading = json['downloading'] == true;

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
    if (downloading && (status == 'uploading' || status == 'complete')) {
      return status == 'uploading'
          ? 'uploading, $peerFirstName is downloading'
          : '$peerFirstName is downloading';
    }
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
  // A folder goes as one zip of it, made on the Rust side when its turn to send comes.
  final bool isFolder;
  // Null while a folder's total is still being counted.
  int? size;
  _PickedFile(this.path, this.name, this.size, {this.isFolder = false});
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
  final List<_PickedFile> _pickedFiles = [];
  // Files are being dragged over the window.
  bool _dragging = false;
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
  List<_PickedFile> _stagedFiles = [];
  Timer? _progressTimer;
  final Map<String, _ProgressInfo> _progressByDropId = {};
  // One upload at a time: parallel sends split a slow uplink and each holds an FFI worker, and a
  // queued file creates no drop (no early "uploading" row for the recipient) until it starts.
  String? _sendingKey;
  final List<(_PickedFile, RustDropDevice)> _sendQueue = [];
  // Accepted drops whose sender hasn't started uploading yet: drop id -> chosen folder.
  final Map<String, String> _waitingAcceptDirs = {};
  // When each waiting accept started retrying; it gives up after _acceptRetryLimit.
  final Map<String, DateTime> _waitingSince = {};
  static const _acceptRetryLimit = Duration(minutes: 30);
  // Accept all: drops still waiting their turn. They download one at a time, like sends, since
  // each download holds an FFI worker until it finishes.
  final Set<String> _acceptAllQueued = {};

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
        _sendAll(staged, _stagedFiles);
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
              .where((d) => !_declinedDropIds.contains(d.id)) // reuse: a cancelled send leaves at once
              .take(50) // one multi-file send can be more than 10
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

  Future<void> _browseForFiles() async {
    final result = await FilePicker.pickFiles();
    await _addPaths([
      for (final file in result)
        if (file.path != null) file.path!
    ]);
  }

  Future<void> _browseForFolder() async {
    final path = await FilePicker.getDirectoryPath(
        dialogTitle: 'Choose a folder to send');
    if (path != null) await _addPaths([path]);
  }

  /// From Browse or a drop on the window. A path already in the list is not added twice.
  Future<void> _addPaths(List<String> paths) async {
    final added = <_PickedFile>[];
    for (final path in paths) {
      if (_pickedFiles.any((f) => f.path == path) ||
          added.any((f) => f.path == path)) {
        continue;
      }
      final name = path.split(RegExp(r'[\\/]')).lastWhere((part) => part.isNotEmpty,
          orElse: () => path);
      switch (await FileSystemEntity.type(path)) {
        case FileSystemEntityType.file:
          added.add(_PickedFile(path, name, await File(path).length()));
        case FileSystemEntityType.directory:
          added.add(_PickedFile(path, name, null, isFolder: true));
        default:
          break; // gone since it was picked, or not a file (a device path)
      }
    }
    if (!mounted || added.isEmpty) return;
    setState(() {
      _pickedFiles.addAll(added);
      _sendStatus = '';
      _sendStatusOk = false;
      _stagedSendDevice = null;
    });
    for (final folder in added.where((f) => f.isFolder)) {
      _countFolderSize(folder);
    }
  }

  Future<void> _countFolderSize(_PickedFile folder) async {
    var total = 0;
    try {
      await for (final entity in Directory(folder.path)
          .list(recursive: true, followLinks: false)) {
        if (entity is File) total += await entity.length();
      }
    } catch (_) {
      return; // an unreadable subfolder: the row just shows no size
    }
    if (!mounted || !_pickedFiles.contains(folder)) return;
    setState(() => folder.size = total);
  }

  void _removePicked(_PickedFile file) {
    setState(() {
      _pickedFiles.remove(file);
      _stagedSendDevice = null;
    });
  }

  Future<void> _sendTo(RustDropDevice device) async {
    if (_pickedFiles.isEmpty) {
      setState(() {
        _sendStatus = 'Add files or a folder first.';
        _sendStatusOk = false;
      });
      return;
    }
    final files = List<_PickedFile>.of(_pickedFiles);
    if (_directoryStatusState != 'ready') {
      // Stage a Send: hold this until the same connection status the
      // footer shows flips to 'ready' (see _loadDirectoryStatus), no
      // timeout. Session-only - lost if the app closes while staged.
      setState(() {
        _stagedSendDevice = device;
        _stagedFiles = files;
        _sendStatus = files.length == 1
            ? 'Waiting for connection to send ${files.first.name} to ${device.displayName}...'
            : 'Waiting for connection to send ${files.length} files to ${device.displayName}...';
        _sendStatusOk = false;
      });
      return;
    }
    _sendAll(device, files);
  }

  /// Not awaited: the first file starts at once, and the rest wait in _sendQueue.
  void _sendAll(RustDropDevice device, List<_PickedFile> files) {
    for (final file in files) {
      _performSend(device, file);
    }
  }

  /// By entry, not position: a send finishing as the button is pressed shifts the queue.
  void _removeQueued((_PickedFile, RustDropDevice) entry) {
    if (!_sendQueue.remove(entry)) return;
    final (file, device) = entry;
    setState(() {
      _sendStatus = 'Removed ${file.name} for ${device.displayName} from the queue.';
      _sendStatusOk = false;
    });
  }

  Future<void> _performSend(RustDropDevice device, _PickedFile picked) async {
    String keyOf(_PickedFile f, RustDropDevice d) => '${f.path}|${d.deviceId}';
    final key = keyOf(picked, device);
    if (_sendingKey == key || _sendQueue.any((q) => keyOf(q.$1, q.$2) == key)) {
      setState(() {
        _sendStatus =
            '${picked.name} is already on its way to ${device.displayName}.';
        _sendStatusOk = false;
      });
      return;
    }
    if (_sendingKey != null) {
      setState(() {
        _sendQueue.add((picked, device));
        _sendStatus =
            'Queued ${picked.name} for ${device.displayName} (${_sendQueue.length} waiting).';
        _sendStatusOk = false;
      });
      return;
    }
    _sendingKey = key;
    setState(() {
      _sendStatus = 'Sending ${picked.name} to ${device.displayName}...';
      _sendStatusOk = false;
    });
    final raw = await bind.crateFlutterFfiRustdropSendFile(
      recipientDeviceId: device.deviceId,
      localPath: picked.path,
    );
    _sendingKey = null;
    if (!mounted) return;
    final parsed = jsonDecode(raw) as Map<String, dynamic>;
    if (parsed['cancelled'] == true) {
      setState(() {
        _sendStatus = 'Cancelled sending ${picked.name} to ${device.displayName}.';
        _sendStatusOk = false;
      });
    } else if (parsed.containsKey('error')) {
      setState(() {
        _sendStatus = 'Failed to send: ${parsed['error']}';
        _sendStatusOk = false;
      });
    } else {
      setState(() {
        _sendStatus = 'Sent ${picked.name}.';
        _sendStatusOk = true;
        // Deliberately keep _pickedFiles selected - Brad wants to send the same
        // files to multiple people without re-Browse-ing again. Cleared only by
        // a row's remove button or Clear all (or app/computer restart, since this
        // is in-memory only and never persisted).
      });
      await _refresh();
    }
    if (mounted && _sendQueue.isNotEmpty) {
      final next = _sendQueue.removeAt(0);
      _performSend(next.$2, next.$1);
    }
  }

  void _clearPickedFiles() {
    setState(() {
      _pickedFiles.clear();
      _sendStatus = '';
      _sendStatusOk = false;
      _stagedSendDevice = null;
    });
  }

  /// Every incoming drop into one folder chosen once, downloading one at a time. A drop that
  /// arrives after this starts still needs its own Accept.
  Future<void> _acceptAll() async {
    final drops = _incoming
        .where((d) =>
            !_busyDropIds.contains(d.id) &&
            !_waitingAcceptDirs.containsKey(d.id) &&
            !_acceptAllQueued.contains(d.id))
        .toList();
    if (drops.isEmpty) return;
    final defaultDir = await bind.crateFlutterFfiRustdropDefaultDownloadsDir();
    final dir = await FilePicker.getDirectoryPath(
      dialogTitle: 'Save ${drops.length} files to...',
      initialDirectory: defaultDir,
    );
    if (dir == null || !mounted) return;
    setState(() => _acceptAllQueued.addAll(drops.map((d) => d.id)));
    for (final drop in drops) {
      // Declined, or taken back by its sender, while it waited.
      if (!mounted) return;
      if (!_acceptAllQueued.contains(drop.id) ||
          !_incoming.any((d) => d.id == drop.id)) {
        setState(() => _acceptAllQueued.remove(drop.id));
        continue;
      }
      // RDS limits downloads per minute; a long run of small files can reach it.
      for (var tries = 1;; tries++) {
        final rateLimited =
            await _accept(drop, intoDir: dir, waitIfRateLimited: tries < 5);
        if (!rateLimited || !mounted) break;
        await Future.delayed(const Duration(seconds: 60));
      }
      if (!mounted) return;
      setState(() => _acceptAllQueued.remove(drop.id));
    }
  }

  /// True when RDS's rate limit refused it and `waitIfRateLimited` kept that quiet for a retry.
  Future<bool> _accept(RustDropDrop drop,
      {String? intoDir, bool waitIfRateLimited = false}) async {
    final String? chosenDir;
    if (intoDir != null) {
      chosenDir = intoDir;
    } else {
      final defaultDir =
          await bind.crateFlutterFfiRustdropDefaultDownloadsDir();
      chosenDir = await FilePicker.getDirectoryPath(
        dialogTitle: 'Save "${drop.displayFilename}" to...',
        initialDirectory: defaultDir,
      );
    }
    if (chosenDir == null) {
      return false; // user cancelled the save dialog - leave the drop pending
    }
    if (!mounted) return false;

    setState(() => _busyDropIds.add(drop.id));
    final raw = await bind.crateFlutterFfiRustdropAcceptDrop(
      dropJson: jsonEncode(drop.toJson()),
      destDir: chosenDir,
    );
    if (!mounted) return false;
    final parsed = jsonDecode(raw) as Map<String, dynamic>;
    if (parsed.containsKey('error')) {
      setState(() => _busyDropIds.remove(drop.id));
      if (parsed['rate_limited'] == true) {
        if (waitIfRateLimited) return true;
        _showError(
            'The server is limiting downloads right now. Accept ${drop.displayFilename} again in a minute.');
        return false;
      }
      if (parsed['waiting'] == true) {
        // The sender hasn't started uploading: keep the drop and try again, no error - for 30
        // minutes, then the recipient accepts again or declines.
        final since = _waitingSince.putIfAbsent(drop.id, DateTime.now);
        if (DateTime.now().difference(since) >= _acceptRetryLimit) {
          setState(() {
            _waitingAcceptDirs.remove(drop.id);
            _waitingSince.remove(drop.id);
          });
          _showError(
              '${drop.peerFirstName} has not started sending ${drop.displayFilename} in 30 minutes. Accept it again later, or decline it.');
          return false;
        }
        _waitingAcceptDirs[drop.id] = chosenDir;
        setState(() {});
        Timer(const Duration(seconds: 30), () => _retryWaitingAccept(drop.id));
        return false;
      }
      _waitingSince.remove(drop.id);
      setState(() => _waitingAcceptDirs.remove(drop.id));
      _showError(parsed['error'].toString());
    } else {
      _waitingSince.remove(drop.id);
      _waitingAcceptDirs.remove(drop.id);
      setState(() => _declinedDropIds
          .add(drop.id)); // reuse: drop out of Incoming once accepted
      await _refresh();
    }
    return false;
  }

  void _retryWaitingAccept(String dropId) {
    if (!mounted) return;
    final dir = _waitingAcceptDirs[dropId];
    RustDropDrop? drop;
    for (final d in _incoming) {
      if (d.id == dropId) drop = d;
    }
    if (dir == null || drop == null) {
      _waitingSince.remove(dropId);
      setState(() => _waitingAcceptDirs.remove(dropId));
      return;
    }
    _accept(drop, intoDir: dir);
  }

  Future<void> _decline(RustDropDrop drop) async {
    // Stops a waiting accept's retries; a failed decline leaves Accept to press again.
    _waitingAcceptDirs.remove(drop.id);
    _waitingSince.remove(drop.id);
    _acceptAllQueued.remove(drop.id);
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

  Future<void> _cancel(RustDropDrop drop) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Cancel sending?'),
        content: Text(
            '${drop.displayFilename} is removed from the server and ${drop.peerFirstName} can no longer download it.'),
        actions: [
          TextButton(
              onPressed: () => Navigator.of(context).pop(false),
              child: const Text('Keep sending')),
          ElevatedButton(
              onPressed: () => Navigator.of(context).pop(true),
              child: const Text('Cancel sending')),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;
    setState(() => _busyDropIds.add(drop.id));
    final raw = await bind.crateFlutterFfiRustdropCancelDrop(dropId: drop.id);
    if (!mounted) return;
    final parsed = jsonDecode(raw) as Map<String, dynamic>;
    setState(() {
      _busyDropIds.remove(drop.id);
      if (!parsed.containsKey('error')) _declinedDropIds.add(drop.id);
    });
    if (parsed.containsKey('error')) {
      final error = parsed['error'].toString();
      _showError(error.contains('already downloading')
          ? '${drop.peerFirstName} is already downloading ${drop.displayFilename}, so it can no longer be cancelled.'
          : 'Could not cancel: $error');
    }
    await _refresh();
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
    return DropTarget(
      onDragEntered: (_) => setState(() => _dragging = true),
      onDragExited: (_) => setState(() => _dragging = false),
      onDragDone: (details) {
        setState(() => _dragging = false);
        _addPaths([for (final file in details.files) file.path]);
      },
      child: Stack(
        children: [
          _buildWindow(dimText),
          if (_dragging) _buildDropOverlay(),
        ],
      ),
    );
  }

  Widget _buildDropOverlay() {
    final primary = Theme.of(context).colorScheme.primary;
    return Positioned.fill(
      child: IgnorePointer(
        child: Container(
          margin: const EdgeInsets.all(8),
          decoration: BoxDecoration(
            color: Theme.of(context)
                .scaffoldBackgroundColor
                .withValues(alpha: 0.9),
            border: Border.all(color: primary, width: 2),
            borderRadius: BorderRadius.circular(12),
          ),
          child: Center(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(Icons.file_download_outlined, size: 40, color: primary),
                const SizedBox(height: 8),
                Text('Drop to add to the send list',
                    style: TextStyle(
                        fontSize: 15,
                        fontWeight: FontWeight.w600,
                        color: primary)),
                const SizedBox(height: 4),
                const Text('A folder is sent as one .zip',
                    style: TextStyle(fontSize: 12)),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildWindow(Color? dimText) {
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
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              _sectionHeader('Incoming'),
              if (_acceptableCount() >= 2)
                Padding(
                  padding: const EdgeInsets.only(bottom: 8),
                  child: TextButton(
                      onPressed: _acceptAll,
                      child: Text('Accept all (${_acceptableCount()})')),
                ),
            ],
          ),
          if (_incoming.isEmpty)
            Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: Text('Nothing waiting for you right now.',
                  style: TextStyle(fontSize: 12, color: dimText)),
            )
          else
            for (final drop in _incoming) _buildDropRow(drop, incoming: true),
          const SizedBox(height: 12),
          _sectionHeader('Send files'),
          _buildSendList(),
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
          for (final entry in _sendQueue) _buildQueuedRow(entry),
          if (_outgoing.isEmpty && _sendQueue.isEmpty)
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

  Widget _buildSendList() {
    final dimText =
        Theme.of(context).textTheme.bodySmall?.color?.withValues(alpha: 0.6);
    final knownSizes = _pickedFiles.map((f) => f.size);
    final total = knownSizes.whereType<int>().fold<int>(0, (a, b) => a + b);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(
        border: Border.all(
            color: Theme.of(context).dividerColor, style: BorderStyle.solid),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (_pickedFiles.isEmpty)
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 4),
              child: Text('No files chosen. Drag files or folders onto this window, or add them below.',
                  style: TextStyle(fontSize: 13, color: dimText)),
            )
          else
            for (final file in _pickedFiles)
              Row(
                children: [
                  Icon(
                      file.isFolder
                          ? Icons.folder_outlined
                          : Icons.insert_drive_file_outlined,
                      size: 16,
                      color: dimText),
                  const SizedBox(width: 6),
                  Expanded(
                    child: Tooltip(
                      message: file.path,
                      child: Text(
                        file.isFolder
                            ? '${file.name} (folder, sent as ${file.name}.zip${file.size == null ? '' : ', ${_formatBytes(file.size!)}'})'
                            : '${file.name} (${_formatBytes(file.size ?? 0)})',
                        overflow: TextOverflow.ellipsis,
                        style: const TextStyle(fontSize: 13),
                      ),
                    ),
                  ),
                  IconButton(
                    icon: const Icon(Icons.close, size: 16),
                    tooltip: 'Remove from the list',
                    visualDensity: VisualDensity.compact,
                    onPressed: () => _removePicked(file),
                  ),
                ],
              ),
          const SizedBox(height: 6),
          Row(
            children: [
              OutlinedButton(
                  onPressed: _browseForFiles, child: const Text('Add files')),
              const SizedBox(width: 8),
              OutlinedButton(
                  onPressed: _browseForFolder, child: const Text('Add folder')),
              const Spacer(),
              if (_pickedFiles.length > 1)
                Padding(
                  padding: const EdgeInsets.only(right: 8),
                  child: Text(
                      '${_pickedFiles.length} items, ${_formatBytes(total)}${knownSizes.contains(null) ? '+' : ''}',
                      style: TextStyle(fontSize: 12, color: dimText)),
                ),
              OutlinedButton(
                onPressed: _pickedFiles.isEmpty ? null : _clearPickedFiles,
                child: const Text('Clear all'),
              ),
            ],
          ),
        ],
      ),
    );
  }

  int _acceptableCount() => _incoming
      .where((d) =>
          !_busyDropIds.contains(d.id) &&
          !_waitingAcceptDirs.containsKey(d.id) &&
          !_acceptAllQueued.contains(d.id))
      .length;

  /// A file waiting its turn to send: no drop exists for it yet, so it is only here.
  Widget _buildQueuedRow((_PickedFile, RustDropDevice) entry) {
    final (file, device) = entry;
    final firstName = device.displayName.split('-').first;
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        border: Border.all(color: Theme.of(context).dividerColor),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(file.isFolder ? '${file.name}.zip' : file.name,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(
                        fontWeight: FontWeight.w600, fontSize: 13)),
                const SizedBox(height: 2),
                Text('To $firstName - queued',
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
          IconButton(
            icon: const Icon(Icons.close, size: 18),
            tooltip: 'Remove from the queue',
            onPressed: () => _removeQueued(entry),
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
    final waiting = incoming && _waitingAcceptDirs.containsKey(drop.id);
    final queuedAccept =
        incoming && !busy && !waiting && _acceptAllQueued.contains(drop.id);
    final sub = waiting
        ? '$peerLabel - waiting for ${drop.peerFirstName} to start sending, it downloads automatically'
        : queuedAccept
            ? '$peerLabel - downloads after the ones before it'
            : incoming
                ? '$peerLabel$expirySuffix'
                : '$peerLabel - ${drop.outgoingStatusLabel()}${drop.declaredSize > 0 ? " - ${_formatBytes(drop.declaredSize)}" : ""}$expirySuffix$stateSuffix';
    final showActions = incoming && !busy && !waiting && !queuedAccept;
    final showPauseResume =
        !incoming && drop.status == 'uploading' && progress != null;
    final showCancel = !incoming &&
        !busy &&
        (drop.status == 'uploading' || drop.status == 'complete');

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
                      message: drop.displayFilename,
                      child: Text(
                        drop.displayFilename,
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
              if (waiting && !busy) ...[
                const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(strokeWidth: 2)),
                const SizedBox(width: 8),
                // Refuse instead of waiting for the sender.
                TextButton(
                    onPressed: () => _decline(drop),
                    child: const Text('Decline')),
              ] else if ((busy && progress == null) || waiting)
                const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(strokeWidth: 2))
              else if (queuedAccept)
                TextButton(
                    onPressed: () => _decline(drop),
                    child: const Text('Decline'))
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
              if (showCancel)
                IconButton(
                  icon: const Icon(Icons.close, size: 18),
                  tooltip: 'Cancel sending',
                  onPressed: () => _cancel(drop),
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
