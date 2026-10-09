import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/main.dart';
import 'package:flutter_hbb/mobile/pages/settings_page.dart';
import 'package:flutter_hbb/models/chat_model.dart';
import 'package:flutter_hbb/models/platform_model.dart';
import 'package:get/get.dart';
import 'package:window_manager/window_manager.dart';

import '../common.dart';
import '../common/formatter/id_formatter.dart';
import '../desktop/pages/server_page.dart' as desktop;
import '../desktop/widgets/tabbar_widget.dart';
import '../mobile/pages/server_page.dart';
import 'model.dart';

const kLoginDialogTag = "LOGIN";

const kUseTemporaryPassword = "use-temporary-password";
const kUsePermanentPassword = "use-permanent-password";
const kUseBothPasswords = "use-both-passwords";

class ServerModel with ChangeNotifier {
  bool _isStart = false; // Android MainService status
  bool _mediaOk = false;
  bool _inputOk = false;
  bool _audioOk = false;
  bool _fileOk = false;
  bool _clipboardOk = false;
  bool _showElevation = false;
  bool hideCm = false;
  bool _managedCmCollapsed = false;
  int _connectStatus = 0; // Rendezvous Server status
  String _verificationMethod = "";
  String _temporaryPasswordLength = "";
  bool _allowNumericOneTimePassword = false;
  String _approveMode = "";
  int _zeroClientLengthCounter = 0;

  late String _emptyIdShow;
  late final IDTextEditingController _serverId;
  final _serverPasswd =
      TextEditingController(text: translate("Generating ..."));

  final tabController = DesktopTabController(tabType: DesktopTabType.cm);

  final List<Client> _clients = [];

  Timer? cmHiddenTimer;

  final _wakelockKey = UniqueKey();

  bool get isStart => _isStart;

  bool get mediaOk => _mediaOk;

  bool get inputOk => _inputOk;

  bool get audioOk => _audioOk;

  bool get fileOk => _fileOk;

  bool get clipboardOk => _clipboardOk;

  bool get showElevation => _showElevation;

  int get connectStatus => _connectStatus;

  String get verificationMethod {
    final index = [
      kUseTemporaryPassword,
      kUsePermanentPassword,
      kUseBothPasswords
    ].indexOf(_verificationMethod);
    if (index < 0) {
      return kUseBothPasswords;
    }
    return _verificationMethod;
  }

  String get approveMode => _approveMode;

  Future<void> setVerificationMethod(String method) async {
    await bind.crateFlutterFfiMainSetOption(
        key: kOptionVerificationMethod, value: method);
    /*
    if (method != kUsePermanentPassword) {
      await bind.crateFlutterFfiMainSetOption(
          key: 'allow-hide-cm', value: bool2option('allow-hide-cm', false));
    }
    */
  }

  String get temporaryPasswordLength {
    final lengthIndex = ["6", "8", "10"].indexOf(_temporaryPasswordLength);
    if (lengthIndex < 0) {
      return "6";
    }
    return _temporaryPasswordLength;
  }

  Future<void> setTemporaryPasswordLength(String length) async {
    await bind.crateFlutterFfiMainSetOption(
        key: "temporary-password-length", value: length);
  }

  Future<void> setApproveMode(String mode) async {
    await bind.crateFlutterFfiMainSetOption(
        key: kOptionApproveMode, value: mode);
    /*
    if (mode != 'password') {
      await bind.crateFlutterFfiMainSetOption(
          key: 'allow-hide-cm', value: bool2option('allow-hide-cm', false));
    }
    */
  }

  bool get allowNumericOneTimePassword => _allowNumericOneTimePassword;
  Future<void> switchAllowNumericOneTimePassword() async {
    await mainSetBoolOption(
        kOptionAllowNumericOneTimePassword, !_allowNumericOneTimePassword);
  }

  TextEditingController get serverId => _serverId;

  TextEditingController get serverPasswd => _serverPasswd;

  List<Client> get clients => _clients;

  bool get isManagedDirectoryBuild =>
      isWindows &&
      bind.crateFlutterFfiMainGetManagedDirectoryStatus().isNotEmpty;

  bool get managedCmCollapsed => _managedCmCollapsed;

  String _managedFriendlyNameForPeer(String peerId) {
    if (!isManagedDirectoryBuild || peerId.trim().isEmpty) return '';
    try {
      final decoded =
          jsonDecode(bind.crateFlutterFfiMainGetManagedDirectoryStatus());
      if (decoded is! Map<String, dynamic>) return '';
      final devices = decoded['devices'];
      if (devices is! List) return '';
      for (final item in devices) {
        if (item is! Map) continue;
        if ((item['rustdesk_id'] ?? '').toString().trim() != peerId.trim()) {
          continue;
        }
        return (item['display_name'] ?? '').toString().trim();
      }
    } catch (e) {
      debugPrint('Managed friendly-name lookup failed for $peerId: $e');
    }
    return '';
  }

  void _applyManagedFriendlyName(Client client) {
    final friendly = _managedFriendlyNameForPeer(client.peerId);
    if (friendly.isNotEmpty) client.managedName = friendly;
  }

  void scheduleManagedCmCollapse(
      {Duration delay = const Duration(seconds: 4)}) {
    if (!isManagedDirectoryBuild ||
        !isDesktop ||
        desktopType != DesktopType.cm ||
        hideCm ||
        parent.target?.chatModel.isShowCMSidePage == true ||
        !_clients.any((c) => c.authorized && !c.disconnected)) {
      return;
    }
    cmHiddenTimer?.cancel();
    cmHiddenTimer = Timer(delay, () {
      cmHiddenTimer = null;
      unawaited(collapseManagedCmWindow());
    });
  }

  void noteManagedCmInteraction() {
    if (!isManagedDirectoryBuild || _managedCmCollapsed) return;
    scheduleManagedCmCollapse(delay: const Duration(seconds: 10));
  }

  Future<void> collapseManagedCmWindow() async {
    if (!isManagedDirectoryBuild ||
        !isDesktop ||
        desktopType != DesktopType.cm ||
        hideCm ||
        parent.target?.chatModel.isShowCMSidePage == true ||
        !_clients.any((c) => c.authorized && !c.disconnected)) {
      return;
    }
    if (!_managedCmCollapsed) {
      _managedCmCollapsed = true;
      notifyListeners();
    }
    await windowManager.show();
    // Resize only, don't re-anchor to a fixed corner - see the matching
    // note in expandManagedCmWindow() below.
    await windowManager.setSize(const Size(220, 72));
  }

  Future<void> expandManagedCmWindow({bool scheduleRecollapse = true}) async {
    if (!isManagedDirectoryBuild ||
        !isDesktop ||
        desktopType != DesktopType.cm) {
      return;
    }
    cmHiddenTimer?.cancel();
    cmHiddenTimer = null;
    if (_managedCmCollapsed) {
      _managedCmCollapsed = false;
      notifyListeners();
    }
    await windowManager.show();
    // Resize only - this collapse/expand cycle repeats on every connection
    // event, so re-anchoring to Alignment.topRight here was what made the
    // window feel pinned in place no matter where the user dragged it.
    final newSize = kConnectionManagerWindowSizeClosedChat;
    await windowManager.setSize(newSize);
    // The collapsed pill is small and often ends up dragged near a screen
    // edge; expanding to the much larger card size while keeping the same
    // top-left origin can then push most of the window off-screen (reported:
    // window appeared almost entirely off the right edge of the display).
    // Only nudge the position back on-screen when the new size no longer
    // fits - don't touch it when it already fits, to preserve the
    // don't-re-anchor behavior above.
    await _keepWindowOnScreen(newSize);
    await windowManager.focus();
    await windowOnTop(null);
    if (scheduleRecollapse) {
      scheduleManagedCmCollapse(delay: const Duration(seconds: 10));
    }
  }

  Future<void> _keepWindowOnScreen(Size size) async {
    try {
      final pos = await windowManager.getPosition();
      final rect = Rect.fromLTWH(pos.dx, pos.dy, size.width, size.height);
      final screens = await getScreenRectList();
      if (screens.isEmpty) return;
      Rect? screen;
      for (final s in screens) {
        if (s.overlaps(rect)) {
          screen = s;
          break;
        }
      }
      screen ??= screens.first;
      double left = pos.dx;
      double top = pos.dy;
      if (rect.right > screen.right) left = screen.right - size.width;
      if (rect.bottom > screen.bottom) top = screen.bottom - size.height;
      if (left < screen.left) left = screen.left;
      if (top < screen.top) top = screen.top;
      if (left != pos.dx || top != pos.dy) {
        await windowManager.setPosition(Offset(left, top));
      }
    } catch (e) {
      debugPrint('Failed to keep managed CM window on screen: $e');
    }
  }

  final controller = ScrollController();

  WeakReference<FFI> parent;

  ServerModel(this.parent) {
    _emptyIdShow = translate("Generating ...");
    _serverId = IDTextEditingController(text: _emptyIdShow);

    /*
    // initital _hideCm at startup
    final verificationMethod =
        bind.crateFlutterFfiMainGetOptionSync(key: kOptionVerificationMethod);
    final approveMode = bind.crateFlutterFfiMainGetOptionSync(key: kOptionApproveMode);
    _hideCm = option2bool(
        'allow-hide-cm', bind.crateFlutterFfiMainGetOptionSync(key: 'allow-hide-cm'));
    if (!(approveMode == 'password' &&
        verificationMethod == kUsePermanentPassword)) {
      _hideCm = false;
    }
    */

    timerCallback() async {
      final connectionStatus =
          jsonDecode(await bind.crateFlutterFfiMainGetConnectStatus())
              as Map<String, dynamic>;
      final statusNum = connectionStatus['status_num'] as int;
      if (statusNum != _connectStatus) {
        _connectStatus = statusNum;
        notifyListeners();
      }

      if (desktopType == DesktopType.cm) {
        final res = await bind.crateFlutterFfiCmCheckClientsLength(
            length: _clients.length);
        if (res != null) {
          debugPrint("clients not match!");
          updateClientState(res);
        } else {
          if (_clients.isEmpty) {
            hideCmWindow();
            if (_zeroClientLengthCounter++ == 12) {
              // 6 second
              windowManager.close();
            }
          } else {
            _zeroClientLengthCounter = 0;
            if (!hideCm) showCmWindow();
          }
        }
      }

      updatePasswordModel();
    }

    if (!isTest) {
      Future.delayed(Duration.zero, () async {
        if (await bind.crateFlutterFfiOptionSynced()) {
          await timerCallback();
        }
      });
      Timer.periodic(Duration(milliseconds: 500), (timer) async {
        await timerCallback();
      });
    }

    // Initial keyboard status is off on mobile
    if (isMobile) {
      bind.crateFlutterFfiMainSetOption(key: kOptionEnableKeyboard, value: 'N');
    }
  }

  /// 1. check android permission
  /// 2. check config
  /// audio true by default (if permission on) (false default < Android 10)
  /// file true by default (if permission on)
  Future<void> checkAndroidPermission() async {
    // audio
    if (androidVersion < 30 ||
        !await AndroidPermissionManager.check(kRecordAudio)) {
      _audioOk = false;
      bind.crateFlutterFfiMainSetOption(key: kOptionEnableAudio, value: "N");
    } else {
      final audioOption =
          await bind.crateFlutterFfiMainGetOption(key: kOptionEnableAudio);
      _audioOk = audioOption != 'N';
    }

    // Android file transfer is confined to app-specific storage. Files enter
    // and leave the workspace through Android's system document picker.
    final fileOption = await bind.crateFlutterFfiMainGetOption(key: kOptionEnableFileTransfer);
    _fileOk = fileOption != 'N';

    // clipboard
    final clipOption =
        await bind.crateFlutterFfiMainGetOption(key: kOptionEnableClipboard);
    _clipboardOk = clipOption != 'N';

    notifyListeners();
  }

  Future<void> updatePasswordModel() async {
    var update = false;
    final temporaryPassword =
        await bind.crateFlutterFfiMainGetTemporaryPassword();
    final verificationMethod =
        await bind.crateFlutterFfiMainGetOption(key: kOptionVerificationMethod);
    final temporaryPasswordLength = await bind.crateFlutterFfiMainGetOption(
        key: "temporary-password-length");
    final approveMode =
        await bind.crateFlutterFfiMainGetOption(key: kOptionApproveMode);
    final numericOneTimePassword =
        await mainGetBoolOption(kOptionAllowNumericOneTimePassword);
    /*
    var hideCm = option2bool(
        'allow-hide-cm', await bind.crateFlutterFfiMainGetOption(key: 'allow-hide-cm'));
    if (!(approveMode == 'password' &&
        verificationMethod == kUsePermanentPassword)) {
      hideCm = false;
    }
    */
    if (_approveMode != approveMode) {
      _approveMode = approveMode;
      update = true;
    }
    var stopped = await mainGetBoolOption(kOptionStopService);
    final oldPwdText = _serverPasswd.text;
    if (stopped ||
        verificationMethod == kUsePermanentPassword ||
        _approveMode == 'click') {
      _serverPasswd.text = '-';
    } else {
      if (_serverPasswd.text != temporaryPassword &&
          temporaryPassword.isNotEmpty) {
        _serverPasswd.text = temporaryPassword;
      }
    }
    if (oldPwdText != _serverPasswd.text) {
      update = true;
    }
    if (_verificationMethod != verificationMethod) {
      _verificationMethod = verificationMethod;
      update = true;
    }
    if (_temporaryPasswordLength != temporaryPasswordLength) {
      if (_temporaryPasswordLength.isNotEmpty) {
        bind.crateFlutterFfiMainUpdateTemporaryPassword();
      }
      _temporaryPasswordLength = temporaryPasswordLength;
      update = true;
    }
    if (_allowNumericOneTimePassword != numericOneTimePassword) {
      _allowNumericOneTimePassword = numericOneTimePassword;
      update = true;
    }
    /*
    if (_hideCm != hideCm) {
      _hideCm = hideCm;
      if (desktopType == DesktopType.cm) {
        if (hideCm) {
          await hideCmWindow();
        } else {
          await showCmWindow();
        }
      }
      update = true;
    }
    */
    if (update) {
      notifyListeners();
    }
  }

  Future<void> toggleAudio() async {
    if (clients.any((c) => !c.disconnected)) {
      await showClientsMayNotBeChangedAlert(parent.target);
    }
    if (!_audioOk && !await AndroidPermissionManager.check(kRecordAudio)) {
      final res = await AndroidPermissionManager.request(kRecordAudio);
      if (!res) {
        showToast(translate('Failed'));
        return;
      }
    }

    _audioOk = !_audioOk;
    bind.crateFlutterFfiMainSetOption(
        key: kOptionEnableAudio, value: _audioOk ? defaultOptionYes : 'N');
    notifyListeners();
  }

  Future<void> toggleFile() async {
    if (clients.any((c) => !c.disconnected)) {
      await showClientsMayNotBeChangedAlert(parent.target);
    }
    _fileOk = !_fileOk;
    bind.crateFlutterFfiMainSetOption(
        key: kOptionEnableFileTransfer,
        value: _fileOk ? defaultOptionYes : 'N');
    notifyListeners();
  }

  Future<void> toggleClipboard() async {
    _clipboardOk = !clipboardOk;
    bind.crateFlutterFfiMainSetOption(
        key: kOptionEnableClipboard,
        value: clipboardOk ? defaultOptionYes : 'N');
    notifyListeners();
  }

  Future<void> toggleInput() async {
    if (clients.any((c) => !c.disconnected)) {
      await showClientsMayNotBeChangedAlert(parent.target);
    }
    if (_inputOk) {
      parent.target?.invokeMethod("stop_input");
      bind.crateFlutterFfiMainSetOption(key: kOptionEnableKeyboard, value: 'N');
    } else {
      if (parent.target != null) {
        /// the result of toggle-on depends on user actions in the settings page.
        /// handle result, see [ServerModel.changeStatue]
        showInputWarnAlert(parent.target!);
      }
    }
  }

  Future<bool> checkRequestNotificationPermission() async {
    debugPrint("androidVersion $androidVersion");
    if (androidVersion < 33) {
      return true;
    }
    if (await AndroidPermissionManager.check(kAndroid13Notification)) {
      debugPrint("notification permission already granted");
      return true;
    }
    var res = await AndroidPermissionManager.request(kAndroid13Notification);
    debugPrint("notification permission request result: $res");
    return res;
  }

  Future<bool> checkFloatingWindowPermission() async {
    debugPrint("androidVersion $androidVersion");
    if (androidVersion < 23) {
      return false;
    }
    if (await AndroidPermissionManager.check(kSystemAlertWindow)) {
      debugPrint("alert window permission already granted");
      return true;
    }
    var res = await AndroidPermissionManager.request(kSystemAlertWindow);
    debugPrint("alert window permission request result: $res");
    return res;
  }

  /// Toggle the screen sharing service.
  Future<void> toggleService() async {
    if (_isStart) {
      final res = await parent.target?.dialogManager
          .show<bool>((setState, close, context) {
        submit() => close(true);
        return CustomAlertDialog(
          title: Row(children: [
            const Icon(Icons.warning_amber_sharp,
                color: Colors.redAccent, size: 28),
            const SizedBox(width: 10),
            Text(translate("Warning")),
          ]),
          content: Text(translate("android_stop_service_tip")),
          actions: [
            TextButton(onPressed: close, child: Text(translate("Cancel"))),
            TextButton(onPressed: submit, child: Text(translate("OK"))),
          ],
          onSubmit: submit,
          onCancel: close,
        );
      });
      if (res == true) {
        stopService();
      }
    } else {
      await checkRequestNotificationPermission();
      if (bind.crateFlutterFfiMainGetLocalOption(
              key: kOptionDisableFloatingWindow) !=
          'Y') {
        await checkFloatingWindowPermission();
      }
      final res = await parent.target?.dialogManager
          .show<bool>((setState, close, context) {
        submit() => close(true);
        return CustomAlertDialog(
          title: Row(children: [
            const Icon(Icons.warning_amber_sharp,
                color: Colors.redAccent, size: 28),
            const SizedBox(width: 10),
            Text(translate("Warning")),
          ]),
          content: Text(translate("android_service_will_start_tip")),
          actions: [
            dialogButton("Cancel", onPressed: close, isOutline: true),
            dialogButton("OK", onPressed: submit),
          ],
          onSubmit: submit,
          onCancel: close,
        );
      });
      if (res == true) {
        startService();
      }
    }
  }

  /// Start the screen sharing service.
  Future<void> startService() async {
    _isStart = true;
    notifyListeners();
    parent.target?.ffiModel.updateEventListener(parent.target!.sessionId, "");
    await parent.target?.invokeMethod("init_service");
    // ugly is here, because for desktop, below is useless
    await bind.crateFlutterFfiMainStartService();
    updateClientState();
    if (isAndroid) {
      androidUpdatekeepScreenOn();
    }
  }

  /// Stop the screen sharing service.
  Future<void> stopService() async {
    _isStart = false;
    closeAll();
    await parent.target?.invokeMethod("stop_service");
    await bind.crateFlutterFfiMainStopService();
    notifyListeners();
    // for androidUpdatekeepScreenOn only
    WakelockManager.disable(_wakelockKey);
  }

  Future<void> fetchID() async {
    final id = await bind.crateFlutterFfiMainGetMyId();
    if (id != _serverId.id) {
      _serverId.id = id;
      notifyListeners();
    }
  }

  void changeStatue(String name, bool value) {
    debugPrint("changeStatue value $value");
    switch (name) {
      case "media":
        _mediaOk = value;
        if (value && !_isStart) {
          startService();
        }
        break;
      case "input":
        if (_inputOk != value) {
          bind.crateFlutterFfiMainSetOption(
              key: kOptionEnableKeyboard,
              value: value ? defaultOptionYes : 'N');
        }
        _inputOk = value;
        break;
      default:
        return;
    }
    notifyListeners();
  }

  // force
  Future<void> updateClientState([String? json]) async {
    if (isTest) return;
    var res = await bind.crateFlutterFfiCmGetClientsState();
    List<dynamic> clientsJson;
    try {
      clientsJson = jsonDecode(res);
    } catch (e) {
      debugPrint("Failed to decode clientsJson: '$res', error $e");
      return;
    }

    final oldClientLenght = _clients.length;
    _clients.clear();
    tabController.state.value.tabs.clear();

    for (var clientJson in clientsJson) {
      try {
        final client = Client.fromJson(clientJson);
        _applyManagedFriendlyName(client);
        _clients.add(client);
        _addTab(client);
      } catch (e) {
        debugPrint("Failed to decode clientJson '$clientJson', error $e");
      }
    }
    if (desktopType == DesktopType.cm) {
      if (_clients.isEmpty) {
        hideCmWindow();
      } else if (!hideCm) {
        showCmWindow();
      }
    }
    if (_clients.length != oldClientLenght) {
      notifyListeners();
      if (isAndroid) androidUpdatekeepScreenOn();
    }
  }

  void _syncClientPermissionState(Client current, Client incoming) {
    current.keyboard = incoming.keyboard;
    current.clipboard = incoming.clipboard;
    current.audio = incoming.audio;
    current.file = incoming.file;
    current.restart = incoming.restart;
    current.recording = incoming.recording;
    current.blockInput = incoming.blockInput;
    current.privacyMode = incoming.privacyMode;
  }

  void addConnection(Map<String, dynamic> evt) {
    try {
      final client = Client.fromJson(jsonDecode(evt["client"]));
      _applyManagedFriendlyName(client);
      if (client.authorized) {
        parent.target?.dialogManager.dismissByTag(getLoginDialogTag(client.id));
        final index = _clients.indexWhere((c) => c.id == client.id);
        if (index < 0) {
          _clients.add(client);
        } else {
          if (_clients[index].authorized) {
            _syncClientPermissionState(_clients[index], client);
            if (client.managedName.isNotEmpty) {
              _clients[index].managedName = client.managedName;
            }
            if (isManagedDirectoryBuild && _managedCmCollapsed) {
              unawaited(expandManagedCmWindow());
            }
            notifyListeners();
            return;
          }
          _clients[index].authorized = true;
          _clients[index].connectedAt ??= DateTime.now();
          _syncClientPermissionState(_clients[index], client);
          if (client.managedName.isNotEmpty) {
            _clients[index].managedName = client.managedName;
          }
        }
      } else {
        final index = _clients.indexWhere((c) => c.id == client.id);
        if (index >= 0) {
          _syncClientPermissionState(_clients[index], client);
          notifyListeners();
          return;
        }
        _clients.add(client);
      }
      if (isManagedDirectoryBuild &&
          !client.authorized &&
          _managedCmCollapsed) {
        unawaited(expandManagedCmWindow(scheduleRecollapse: false));
      }
      _addTab(client);
      // remove disconnected
      final index_disconnected = _clients
          .indexWhere((c) => c.disconnected && c.peerId == client.peerId);
      if (index_disconnected >= 0) {
        _clients.removeAt(index_disconnected);
        tabController.remove(index_disconnected);
      }
      if (desktopType == DesktopType.cm && !hideCm) {
        showCmWindow();
      }
      scrollToBottom();
      notifyListeners();
      if (isAndroid && !client.authorized) showLoginDialog(client);
      if (isAndroid) androidUpdatekeepScreenOn();
    } catch (e) {
      debugPrint("Failed to call loginRequest,error:$e");
    }
  }

  void _addTab(Client client) {
    tabController.add(TabInfo(
        key: client.id.toString(),
        label: client.displayName,
        closable: false,
        onTap: () {},
        page: desktop.buildConnectionCard(client)));
    Future.delayed(Duration.zero, () async {
      if (!hideCm) windowOnTop(null);
    });
    // Preserve upstream minimization for non-managed builds. Managed builds
    // instead collapse to a small right-edge connection tab that remains
    // visibly present and can be reopened with one click.
    if (client.authorized && isDesktop) {
      if (isManagedDirectoryBuild) {
        scheduleManagedCmCollapse();
      } else {
        cmHiddenTimer = Timer(const Duration(seconds: 3), () {
          if (!hideCm) windowManager.minimize();
          cmHiddenTimer = null;
        });
      }
    }
    parent.target?.chatModel
        .updateConnIdOfKey(MessageKey(client.peerId, client.id));
  }

  void showLoginDialog(Client client) {
    showClientDialog(
      client,
      client.isFileTransfer
          ? "Transfer file"
          : client.isViewCamera
              ? "View camera"
              : client.isTerminal
                  ? "Terminal"
                  : "Share screen",
      'Do you accept?',
      'android_new_connection_tip',
      () => sendLoginResponse(client, false),
      () => sendLoginResponse(client, true),
    );
  }

  void handleVoiceCall(Client client, bool accept) {
    parent.target?.invokeMethod("cancel_notification", client.id);
    bind.crateFlutterFfiCmHandleIncomingVoiceCall(
        id: client.id, accept: accept);
  }

  void showVoiceCallDialog(Client client) {
    showClientDialog(
      client,
      'Voice call',
      'Do you accept?',
      'android_new_voice_call_tip',
      () => handleVoiceCall(client, false),
      () => handleVoiceCall(client, true),
    );
  }

  void showClientDialog(Client client, String title, String contentTitle,
      String content, VoidCallback onCancel, VoidCallback onSubmit) {
    parent.target?.dialogManager.show((setState, close, context) {
      cancel() {
        onCancel();
        close();
      }

      submit() {
        onSubmit();
        close();
      }

      return CustomAlertDialog(
        title:
            Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
          Text(translate(title)),
          IconButton(onPressed: close, icon: const Icon(Icons.close))
        ]),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          mainAxisAlignment: MainAxisAlignment.center,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(translate(contentTitle)),
            ClientInfo(client),
            Text(
              translate(content),
              style: Theme.of(globalKey.currentContext!).textTheme.bodyMedium,
            ),
          ],
        ),
        actions: [
          dialogButton("Dismiss", onPressed: cancel, isOutline: true),
          if (approveMode != 'password')
            dialogButton("Accept", onPressed: submit),
        ],
        onSubmit: submit,
        onCancel: cancel,
      );
    }, tag: getLoginDialogTag(client.id));
  }

  void scrollToBottom() {
    if (isDesktop) return;
    Future.delayed(Duration(milliseconds: 200), () {
      controller.animateTo(controller.position.maxScrollExtent,
          duration: Duration(milliseconds: 200),
          curve: Curves.fastLinearToSlowEaseIn);
    });
  }

  void sendLoginResponse(Client client, bool res) async {
    if (res) {
      bind.crateFlutterFfiCmLoginRes(connId: client.id, res: res);
      if (!client.isFileTransfer && !client.isTerminal) {
        parent.target?.invokeMethod("start_capture");
      }
      parent.target?.invokeMethod("cancel_notification", client.id);
      client.authorized = true;
      client.connectedAt ??= DateTime.now();
      notifyListeners();
      if (isDesktop && isManagedDirectoryBuild) {
        scheduleManagedCmCollapse();
      }
    } else {
      bind.crateFlutterFfiCmLoginRes(connId: client.id, res: res);
      parent.target?.invokeMethod("cancel_notification", client.id);
      final index = _clients.indexOf(client);
      tabController.remove(index);
      _clients.remove(client);
      if (isAndroid) androidUpdatekeepScreenOn();
    }
  }

  void onClientRemove(Map<String, dynamic> evt) {
    try {
      final id = int.parse(evt['id'] as String);
      final close = (evt['close'] as String) == 'true';
      if (_clients.any((c) => c.id == id)) {
        final index = _clients.indexWhere((client) => client.id == id);
        if (index >= 0) {
          if (close) {
            _clients.removeAt(index);
            tabController.remove(index);
          } else {
            _clients[index].disconnected = true;
            if (isManagedDirectoryBuild && _managedCmCollapsed) {
              unawaited(expandManagedCmWindow(scheduleRecollapse: false));
            }
          }
        }
        parent.target?.dialogManager.dismissByTag(getLoginDialogTag(id));
        parent.target?.invokeMethod("cancel_notification", id);
      }
      if (desktopType == DesktopType.cm && _clients.isEmpty) {
        hideCmWindow();
      }
      if (isAndroid) androidUpdatekeepScreenOn();
      notifyListeners();
    } catch (e) {
      debugPrint("onClientRemove failed,error:$e");
    }
  }

  /// `byOperator` false means the CM's window went away rather than a person asking for the
  /// peers to go. The sessions end either way; only the close reason differs, and with it
  /// whether the peer is allowed to reconnect. See `ipc::Data::CmWindowClosed`.
  Future<void> closeAll({bool byOperator = true}) async {
    await Future.wait(_clients.map((client) => byOperator
        ? bind.crateFlutterFfiCmCloseConnection(connId: client.id)
        : bind.crateFlutterFfiCmCloseConnectionWindow(connId: client.id)));
    _clients.clear();
    tabController.state.value.tabs.clear();
    if (isAndroid) androidUpdatekeepScreenOn();
  }

  void jumpTo(int id) {
    final index = _clients.indexWhere((client) => client.id == id);
    tabController.jumpTo(index);
  }

  void setShowElevation(bool show) {
    if (_showElevation != show) {
      _showElevation = show;
      notifyListeners();
    }
  }

  void updateVoiceCallState(Map<String, dynamic> evt) {
    try {
      final client = Client.fromJson(jsonDecode(evt["client"]));
      final index = _clients.indexWhere((element) => element.id == client.id);
      if (index != -1) {
        _clients[index].inVoiceCall = client.inVoiceCall;
        _clients[index].incomingVoiceCall = client.incomingVoiceCall;
        if (client.incomingVoiceCall) {
          if (isAndroid) {
            showVoiceCallDialog(client);
          } else {
            // Has incoming phone call, let's set the window on top.
            Future.delayed(Duration.zero, () {
              windowOnTop(null);
            });
          }
        }
        notifyListeners();
      }
    } catch (e) {
      debugPrint("updateVoiceCallState failed: $e");
    }
  }

  void androidUpdatekeepScreenOn() async {
    if (!isAndroid) return;
    var floatingWindowDisabled = bind.crateFlutterFfiMainGetLocalOption(
                key: kOptionDisableFloatingWindow) ==
            "Y" ||
        !await AndroidPermissionManager.check(kSystemAlertWindow);
    final keepScreenOn = floatingWindowDisabled
        ? KeepScreenOn.never
        : optionToKeepScreenOn(
            bind.crateFlutterFfiMainGetLocalOption(key: kOptionKeepScreenOn));
    final on = ((keepScreenOn == KeepScreenOn.serviceOn) && _isStart) ||
        (keepScreenOn == KeepScreenOn.duringControlled &&
            _clients.map((e) => !e.disconnected).isNotEmpty);
    if (on) {
      WakelockManager.enable(_wakelockKey, isServer: true);
    } else {
      WakelockManager.disable(_wakelockKey);
    }
  }
}

enum ClientType {
  remote,
  file,
  camera,
  portForward,
  terminal,
}

class Client {
  int id = 0; // client connections inner count id
  bool authorized = false;
  bool isFileTransfer = false;
  bool isViewCamera = false;
  bool isTerminal = false;
  String portForward = "";
  String name = "";
  String managedName = "";
  DateTime? connectedAt;
  String avatar = "";
  String peerId = ""; // peer user's id,show at app
  bool keyboard = false;
  bool clipboard = false;
  bool audio = false;
  bool file = false;
  bool restart = false;
  bool recording = false;
  bool blockInput = false;
  bool privacyMode = false;
  bool disconnected = false;
  bool fromSwitch = false;
  bool inVoiceCall = false;
  bool incomingVoiceCall = false;

  String get displayName =>
      managedName.trim().isNotEmpty ? managedName.trim() : name.trim();

  RxInt unreadChatMessageCount = 0.obs;

  Client(this.id, this.authorized, this.isFileTransfer, this.isViewCamera,
      this.name, this.peerId, this.keyboard, this.clipboard, this.audio);

  Client.fromJson(Map<String, dynamic> json) {
    id = json['id'];
    authorized = json['authorized'];
    isFileTransfer = json['is_file_transfer'];
    // TODO: no entry then default.
    isViewCamera = json['is_view_camera'];
    isTerminal = json['is_terminal'] ?? false;
    portForward = json['port_forward'];
    name = json['name'];
    avatar = json['avatar'] ?? '';
    peerId = json['peer_id'];
    keyboard = json['keyboard'];
    clipboard = json['clipboard'];
    audio = json['audio'];
    file = json['file'];
    restart = json['restart'];
    recording = json['recording'];
    blockInput = json['block_input'];
    privacyMode = json['privacy_mode'] ?? privacyMode;
    disconnected = json['disconnected'];
    fromSwitch = json['from_switch'];
    inVoiceCall = json['in_voice_call'];
    incomingVoiceCall = json['incoming_voice_call'];
    if (authorized) connectedAt = DateTime.now();
  }

  Map<String, dynamic> toJson() {
    final Map<String, dynamic> data = <String, dynamic>{};
    data['id'] = id;
    data['authorized'] = authorized;
    data['is_file_transfer'] = isFileTransfer;
    data['is_view_camera'] = isViewCamera;
    data['is_terminal'] = isTerminal;
    data['port_forward'] = portForward;
    data['name'] = name;
    data['avatar'] = avatar;
    data['peer_id'] = peerId;
    data['keyboard'] = keyboard;
    data['clipboard'] = clipboard;
    data['audio'] = audio;
    data['file'] = file;
    data['restart'] = restart;
    data['recording'] = recording;
    data['block_input'] = blockInput;
    data['privacy_mode'] = privacyMode;
    data['disconnected'] = disconnected;
    data['from_switch'] = fromSwitch;
    data['in_voice_call'] = inVoiceCall;
    data['incoming_voice_call'] = incomingVoiceCall;
    return data;
  }

  ClientType type_() {
    if (isFileTransfer) {
      return ClientType.file;
    } else if (isViewCamera) {
      return ClientType.camera;
    } else if (isTerminal) {
      return ClientType.terminal;
    } else if (portForward.isNotEmpty) {
      return ClientType.portForward;
    } else {
      return ClientType.remote;
    }
  }
}

String getLoginDialogTag(int id) {
  return kLoginDialogTag + id.toString();
}

void showInputWarnAlert(FFI ffi) {
  ffi.dialogManager.show((setState, close, context) {
    submit() {
      AndroidPermissionManager.startAction(kActionAccessibilitySettings);
      close();
    }

    return CustomAlertDialog(
      title: Text(translate("How to get Android input permission?")),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(translate("android_input_permission_tip1")),
          const SizedBox(height: 10),
          Text(translate("android_input_permission_tip2")),
        ],
      ),
      actions: [
        dialogButton("Cancel", onPressed: close, isOutline: true),
        dialogButton("Open System Setting", onPressed: submit),
      ],
      onSubmit: submit,
      onCancel: close,
    );
  });
}

Future<void> showClientsMayNotBeChangedAlert(FFI? ffi) async {
  await ffi?.dialogManager.show((setState, close, context) {
    return CustomAlertDialog(
      title: Text(translate("Permissions")),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(translate("android_permission_may_not_change_tip")),
        ],
      ),
      actions: [
        dialogButton("OK", onPressed: close),
      ],
      onSubmit: close,
      onCancel: close,
    );
  });
}
