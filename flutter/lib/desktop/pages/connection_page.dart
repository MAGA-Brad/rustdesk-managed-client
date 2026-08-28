// main window right pane

import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/widgets/connection_page_title.dart';
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/desktop/widgets/popup_menu.dart';
import 'package:flutter_hbb/models/state_model.dart';
import 'package:get/get.dart';
import 'package:url_launcher/url_launcher_string.dart';
import 'package:window_manager/window_manager.dart';
import 'package:flutter_hbb/models/peer_model.dart';

import '../../common.dart';
import '../../common/formatter/id_formatter.dart';
import '../../common/widgets/peer_tab_page.dart';
import '../../common/widgets/autocomplete.dart';
import '../../models/platform_model.dart';
import '../../desktop/widgets/material_mod_popup_menu.dart' as mod_menu;

class OnlineStatusWidget extends StatefulWidget {
  const OnlineStatusWidget({Key? key, this.onSvcStatusChanged})
      : super(key: key);

  final VoidCallback? onSvcStatusChanged;

  @override
  State<OnlineStatusWidget> createState() => _OnlineStatusWidgetState();
}

/// State for the connection page.
class _OnlineStatusWidgetState extends State<OnlineStatusWidget> {
  final _svcStopped = Get.find<RxBool>(tag: 'stop-service');
  final _svcIsUsingPublicServer = true.obs;
  final _directoryState = ''.obs;
  final _directoryStatusText = ''.obs;
  final _reenrollmentRequested = false.obs;
  final _reenrollmentAuthorized = false.obs;
  final _reenrollmentRequestBusy = false.obs;
  final RxnInt _managedOnlineClients = RxnInt();
  final RxnInt _managedActiveSessions = RxnInt();
  final RxnInt _pendingUpdateBuildNumber = RxnInt();
  final _pendingUpdateVersion = ''.obs;
  final _updateApplying = false.obs;
  DateTime? _updateApplyStartedAt;
  Timer? _updateTimer;

  // Managed clients auto-enroll into the directory, so the manual
  // "Control Remote Desktop" ID field is hidden and this status area
  // gets the freed-up space instead of its usual compact height.
  bool get _isManagedClient =>
      bind.mainGetManagedDirectoryStatus().isNotEmpty;

  double get em => 14.0;
  double? get height => bind.isIncomingOnly()
      ? null
      : (_isManagedClient ? em * 10 : em * 3);

  void onUsePublicServerGuide() {
    const url = "https://rustdesk.com/pricing";
    canLaunchUrlString(url).then((can) {
      if (can) {
        launchUrlString(url);
      }
    });
  }

  @override
  void initState() {
    super.initState();
    _updateTimer = periodic_immediate(Duration(seconds: 1), () async {
      updateStatus();
    });
  }

  @override
  void dispose() {
    _updateTimer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final isIncomingOnly = bind.isIncomingOnly();
    startServiceWidget() => Offstage(
          offstage: !_svcStopped.value,
          child: InkWell(
                  onTap: () async {
                    await start_service(true);
                  },
                  child: Text(translate("Start service"),
                      style: TextStyle(
                          decoration: TextDecoration.underline, fontSize: em)))
              .marginOnly(left: em),
        );

    setupServerWidget() => Flexible(
          child: Offstage(
            offstage: !(!_svcStopped.value &&
                stateGlobal.svcStatus.value == SvcStatus.ready &&
                _svcIsUsingPublicServer.value),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.center,
              children: [
                Text(', ', style: TextStyle(fontSize: em)),
                Flexible(
                  child: InkWell(
                    onTap: onUsePublicServerGuide,
                    child: Row(
                      children: [
                        Flexible(
                          child: Text(
                            translate('setup_server_tip'),
                            style: TextStyle(
                                decoration: TextDecoration.underline,
                                fontSize: em),
                          ),
                        ),
                      ],
                    ),
                  ),
                )
              ],
            ),
          ),
        );

    statsRow() => (!isIncomingOnly &&
            (_managedOnlineClients.value != null ||
                _managedActiveSessions.value != null))
        ? Row(
            children: [
              Text(
                '${translate("Clients online")}: ${_managedOnlineClients.value?.toString() ?? '—'}',
                style: TextStyle(
                    fontSize: em - 1,
                    color: Theme.of(context).textTheme.bodySmall?.color),
              ).marginOnly(right: 16),
              Text(
                '${translate("Active sessions")}: ${_managedActiveSessions.value?.toString() ?? '—'}',
                style: TextStyle(
                    fontSize: em - 1,
                    color: Theme.of(context).textTheme.bodySmall?.color),
              ),
            ],
          ).marginOnly(top: 4, left: em + 8)
        : const Offstage();

    statusRow() => Row(
          crossAxisAlignment: CrossAxisAlignment.center,
          children: [
            Container(
              height: 8,
              width: 8,
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(4),
                color: _directoryStatusText.value.isNotEmpty
                    ? (_directoryState.value == 'ready'
                        ? const Color.fromARGB(255, 50, 190, 166)
                        : (_directoryState.value == 'denied' ||
                                _directoryState.value == 'blocked' ||
                                _directoryState.value == 'revoked')
                            ? const Color.fromARGB(255, 224, 79, 95)
                            : kColorWarn)
                    : (_svcStopped.value ||
                            stateGlobal.svcStatus.value == SvcStatus.connecting
                        ? kColorWarn
                        : (stateGlobal.svcStatus.value == SvcStatus.ready
                            ? const Color.fromARGB(255, 50, 190, 166)
                            : const Color.fromARGB(255, 224, 79, 95))),
              ),
            ).marginSymmetric(horizontal: em),
            Container(
              width: isIncomingOnly ? 226 : null,
              child: _buildConnStatusMsg(),
            ),
            if (!isIncomingOnly &&
                ['denied', 'blocked', 'revoked'].contains(_directoryState.value))
              Obx(() => TextButton.icon(
                    onPressed: _reenrollmentRequested.value ||
                            _reenrollmentAuthorized.value ||
                            _reenrollmentRequestBusy.value
                        ? null
                        : () async {
                            _reenrollmentRequestBusy.value = true;
                            try {
                              await bind.mainSetOption(
                                key: 'managed-request-reenrollment',
                                value: 'Y',
                              );
                            } finally {
                              await Future<void>.delayed(
                                  const Duration(milliseconds: 750));
                              _reenrollmentRequestBusy.value = false;
                              updateStatus();
                            }
                          },
                    icon: const Icon(Icons.admin_panel_settings_outlined,
                        size: 16),
                    label: Text(
                      _reenrollmentAuthorized.value
                          ? 'Authorized'
                          : _reenrollmentRequested.value
                              ? 'Requested'
                              : 'Request re-enrollment',
                    ),
                  )).marginOnly(left: 8),
            // stop
            if (!isIncomingOnly) startServiceWidget(),
            // ready && public
            // No need to show the guide if is custom client.
            if (!isIncomingOnly) setupServerWidget(),
          ],
        );

    basicWidget() => Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: [
            statusRow(),
            statsRow(),
          ],
        );

    // Only shown once the background daily check has found and
    // signature-verified a newer build - fully hidden otherwise, same as
    // the rest of this managed-client status area.
    updateAvailableWidget() => Obx(() {
          if (_pendingUpdateBuildNumber.value == null) {
            return const Offstage();
          }
          return Row(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.center,
            children: [
              Icon(Icons.system_update_alt_outlined,
                      size: 16, color: kColorWarn)
                  .marginOnly(right: 6),
              Text(
                translate('Update available'),
                style: TextStyle(fontSize: em - 1, color: kColorWarn),
              ).marginOnly(right: 12),
              _updateApplying.value
                  ? SizedBox(
                      width: 14,
                      height: 14,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    ).marginOnly(right: 8)
                  : ElevatedButton(
                      onPressed: () {
                        _updateApplying.value = true;
                        _updateApplyStartedAt = DateTime.now();
                        bind.mainTriggerManagedUpdateNow();
                      },
                      child: Text(translate('Update Now')),
                    ),
            ],
          );
        });

    return Container(
      height: height,
      alignment: (!isIncomingOnly && _isManagedClient)
          ? Alignment.centerLeft
          : null,
      child: Obx(() => isIncomingOnly
          ? Column(
              children: [
                basicWidget(),
                Align(
                        child: startServiceWidget(),
                        alignment: Alignment.centerLeft)
                    .marginOnly(top: 2.0, left: 22.0),
              ],
            )
          : (_isManagedClient
              ? Row(
                  crossAxisAlignment: CrossAxisAlignment.end,
                  children: [
                    basicWidget(),
                    Expanded(
                      child: Align(
                        alignment: Alignment.bottomRight,
                        child: updateAvailableWidget(),
                      ),
                    ),
                  ],
                )
              : basicWidget())),
    ).paddingOnly(right: isIncomingOnly ? 8 : 0);
  }

  _buildConnStatusMsg() {
    widget.onSvcStatusChanged?.call();

    final friendlyName =
        bind.mainGetOptionSync(key: 'preset-device-name').trim();
    final readyText = friendlyName.isEmpty
        ? translate('Ready')
        : 'Ready \u2014 $friendlyName';

    return Text(
      _directoryStatusText.value.isNotEmpty
          ? _directoryStatusText.value
          : _svcStopped.value
              ? translate("Service is not running")
              : stateGlobal.svcStatus.value == SvcStatus.connecting
                  ? translate("connecting_status")
                  : stateGlobal.svcStatus.value == SvcStatus.notReady
                      ? translate("not_ready_status")
                      : readyText,
      style: TextStyle(fontSize: em),
    );
  }

  updateStatus() async {
    final status =
        jsonDecode(await bind.mainGetConnectStatus()) as Map<String, dynamic>;
    final statusNum = status['status_num'] as int;
    if (statusNum == 0) {
      stateGlobal.svcStatus.value = SvcStatus.connecting;
    } else if (statusNum == -1) {
      stateGlobal.svcStatus.value = SvcStatus.notReady;
    } else if (statusNum == 1) {
      stateGlobal.svcStatus.value = SvcStatus.ready;
    } else {
      stateGlobal.svcStatus.value = SvcStatus.notReady;
    }
    _svcIsUsingPublicServer.value = await bind.mainIsUsingPublicServer();

    final managedDirectory = bind.mainGetManagedDirectoryStatus();

    if (managedDirectory.isEmpty) {
      _directoryState.value = '';
      _directoryStatusText.value = '';
      _reenrollmentRequested.value = false;
      _reenrollmentAuthorized.value = false;
      _managedOnlineClients.value = null;
      _managedActiveSessions.value = null;
    } else {
      try {
        final directory = jsonDecode(managedDirectory) as Map<String, dynamic>;

        _directoryState.value = directory['state'] as String? ?? 'unavailable';
        _reenrollmentRequested.value =
            directory['reenrollment_requested'] as bool? ?? false;
        _reenrollmentAuthorized.value =
            directory['reenrollment_authorized'] as bool? ?? false;

        final serverStats = directory['server_stats'];
        if (serverStats is Map) {
          _managedOnlineClients.value =
              (serverStats['online_clients'] as num?)?.toInt();
          _managedActiveSessions.value =
              (serverStats['active_sessions'] as num?)?.toInt();
        } else {
          _managedOnlineClients.value = null;
          _managedActiveSessions.value = null;
        }

        final directoryText = directory['text'] as String? ?? '';

        if (directoryText.isNotEmpty) {
          _directoryStatusText.value = directoryText;
        } else {
          final friendlyName = bind
              .mainGetOptionSync(
                key: 'preset-device-name',
              )
              .trim();

          _directoryStatusText.value =
              'Directory unavailable \u2014 $friendlyName';
        }
      } catch (_) {
        _directoryState.value = 'unavailable';
        _reenrollmentRequested.value = false;
        _reenrollmentAuthorized.value = false;
        _managedOnlineClients.value = null;
        _managedActiveSessions.value = null;

        final friendlyName = bind
            .mainGetOptionSync(
              key: 'preset-device-name',
            )
            .trim();

        _directoryStatusText.value =
            'Directory unavailable \u2014 $friendlyName';
      }
    }
    try {
      stateGlobal.videoConnCount.value = status['video_conn_count'] as int;
    } catch (_) {}

    final pendingUpdateJson = bind.mainGetPendingManagedUpdate();
    if (pendingUpdateJson.isEmpty) {
      _pendingUpdateBuildNumber.value = null;
      _pendingUpdateVersion.value = '';
      _updateApplying.value = false;
      _updateApplyStartedAt = null;
    } else {
      try {
        final pending =
            jsonDecode(pendingUpdateJson) as Map<String, dynamic>;
        _pendingUpdateBuildNumber.value =
            (pending['build_number'] as num?)?.toInt();
        _pendingUpdateVersion.value = pending['version'] as String? ?? '';
      } catch (_) {
        _pendingUpdateBuildNumber.value = null;
        _pendingUpdateVersion.value = '';
      }
      // The pending state only clears on a successful apply. A failed
      // attempt (network blip, transient server error) never clears it,
      // which would otherwise leave the spinner stuck forever with no way
      // to retry - fall back to the button after a generous timeout.
      final startedAt = _updateApplyStartedAt;
      if (_updateApplying.value &&
          startedAt != null &&
          DateTime.now().difference(startedAt) > const Duration(seconds: 45)) {
        _updateApplying.value = false;
        _updateApplyStartedAt = null;
      }
    }
  }
}

/// Connection page for connecting to a remote peer.
class ConnectionPage extends StatefulWidget {
  const ConnectionPage({Key? key}) : super(key: key);

  @override
  State<ConnectionPage> createState() => _ConnectionPageState();
}

/// State for the connection page.
class _ConnectionPageState extends State<ConnectionPage>
    with SingleTickerProviderStateMixin, WindowListener {
  /// Controller for the id input bar.
  final _idController = IDTextEditingController();

  final RxBool _idInputFocused = false.obs;
  final FocusNode _idFocusNode = FocusNode();
  final TextEditingController _idEditingController = TextEditingController();

  String selectedConnectionType = 'Connect';

  bool isWindowMinimized = false;

  final AllPeersLoader _allPeersLoader = AllPeersLoader();

  // https://github.com/flutter/flutter/issues/157244
  Iterable<Peer> _autocompleteOpts = [];

  final _menuOpen = false.obs;

  @override
  void initState() {
    super.initState();
    _allPeersLoader.init(setState);
    _idFocusNode.addListener(onFocusChanged);
    if (_idController.text.isEmpty) {
      WidgetsBinding.instance.addPostFrameCallback((_) async {
        final lastRemoteId = await bind.mainGetLastRemoteId();
        if (lastRemoteId != _idController.id) {
          setState(() {
            _idController.id = lastRemoteId;
          });
        }
      });
    }
    Get.put<TextEditingController>(_idEditingController);
    Get.put<IDTextEditingController>(_idController);
    windowManager.addListener(this);
  }

  @override
  void dispose() {
    _idController.dispose();
    windowManager.removeListener(this);
    _allPeersLoader.clear();
    _idFocusNode.removeListener(onFocusChanged);
    _idFocusNode.dispose();
    _idEditingController.dispose();
    if (Get.isRegistered<IDTextEditingController>()) {
      Get.delete<IDTextEditingController>();
    }
    if (Get.isRegistered<TextEditingController>()) {
      Get.delete<TextEditingController>();
    }
    super.dispose();
  }

  @override
  void onWindowEvent(String eventName) {
    super.onWindowEvent(eventName);
    if (eventName == 'minimize') {
      isWindowMinimized = true;
    } else if (eventName == 'maximize' || eventName == 'restore') {
      if (isWindowMinimized && isWindows) {
        // windows can't update when minimized.
        Get.forceAppUpdate();
      }
      isWindowMinimized = false;
    }
  }

  @override
  void onWindowEnterFullScreen() {
    // Remove edge border by setting the value to zero.
    stateGlobal.resizeEdgeSize.value = 0;
  }

  @override
  void onWindowLeaveFullScreen() {
    // Restore edge border to default edge size.
    stateGlobal.resizeEdgeSize.value = stateGlobal.isMaximized.isTrue
        ? kMaximizeEdgeSize
        : windowResizeEdgeSize;
  }

  @override
  void onWindowClose() {
    super.onWindowClose();
    bind.mainOnMainWindowClose();
  }

  void onFocusChanged() {
    _idInputFocused.value = _idFocusNode.hasFocus;
    if (_idFocusNode.hasFocus) {
      if (_allPeersLoader.needLoad) {
        _allPeersLoader.getAllPeers();
      }

      final textLength = _idEditingController.value.text.length;
      // Select all to facilitate removing text, just following the behavior of address input of chrome.
      _idEditingController.selection =
          TextSelection(baseOffset: 0, extentOffset: textLength);
    }
  }

  @override
  Widget build(BuildContext context) {
    final isOutgoingOnly = bind.isOutgoingOnly();
    // Managed clients auto-enroll into the directory below, so the manual
    // "Control Remote Desktop" ID field isn't needed and is hidden.
    final isManagedClient = bind.mainGetManagedDirectoryStatus().isNotEmpty;
    return Column(
      children: [
        Expanded(
            child: Column(
          children: [
            if (!isManagedClient)
              Row(
                children: [
                  Flexible(child: _buildRemoteIDTextField(context)),
                ],
              ).marginOnly(top: 22),
            if (!isManagedClient) SizedBox(height: 12),
            Divider().paddingOnly(right: 12),
            Expanded(child: PeerTabPage()),
          ],
        ).paddingOnly(left: 12.0)),
        if (!isOutgoingOnly) const Divider(height: 1),
        if (!isOutgoingOnly) OnlineStatusWidget()
      ],
    );
  }

  /// Callback for the connect button.
  /// Connects to the selected peer.
  void onConnect(
      {bool isFileTransfer = false,
      bool isViewCamera = false,
      bool isTerminal = false}) {
    var id = _idController.id;
    connect(context, id,
        isFileTransfer: isFileTransfer,
        isViewCamera: isViewCamera,
        isTerminal: isTerminal);
  }

  /// UI for the remote ID TextField.
  /// Search for a peer.
  Widget _buildRemoteIDTextField(BuildContext context) {
    var w = Container(
      width: 320 + 20 * 2,
      padding: const EdgeInsets.fromLTRB(20, 24, 20, 22),
      decoration: BoxDecoration(
          borderRadius: const BorderRadius.all(Radius.circular(13)),
          border: Border.all(color: Theme.of(context).colorScheme.background)),
      child: Ink(
        child: Column(
          children: [
            getConnectionPageTitle(context, false).marginOnly(bottom: 15),
            Row(
              children: [
                Expanded(
                    child: RawAutocomplete<Peer>(
                  optionsBuilder: (TextEditingValue textEditingValue) {
                    if (textEditingValue.text == '') {
                      _autocompleteOpts = const Iterable<Peer>.empty();
                    } else if (_allPeersLoader.peers.isEmpty &&
                        !_allPeersLoader.isPeersLoaded) {
                      Peer emptyPeer = Peer(
                        id: '',
                        username: '',
                        hostname: '',
                        alias: '',
                        platform: '',
                        tags: [],
                        hash: '',
                        password: '',
                        forceAlwaysRelay: false,
                        rdpPort: '',
                        rdpUsername: '',
                        loginName: '',
                        device_group_name: '',
                        note: '',
                      );
                      _autocompleteOpts = [emptyPeer];
                    } else {
                      String textWithoutSpaces =
                          textEditingValue.text.replaceAll(" ", "");
                      if (int.tryParse(textWithoutSpaces) != null) {
                        textEditingValue = TextEditingValue(
                          text: textWithoutSpaces,
                          selection: textEditingValue.selection,
                        );
                      }
                      String textToFind = textEditingValue.text.toLowerCase();
                      _autocompleteOpts = _allPeersLoader.peers
                          .where((peer) =>
                              peer.id.toLowerCase().contains(textToFind) ||
                              peer.username
                                  .toLowerCase()
                                  .contains(textToFind) ||
                              peer.hostname
                                  .toLowerCase()
                                  .contains(textToFind) ||
                              peer.alias.toLowerCase().contains(textToFind))
                          .toList();
                      _allPeersLoader.queryOnlines(_autocompleteOpts);
                    }
                    return _autocompleteOpts;
                  },
                  focusNode: _idFocusNode,
                  textEditingController: _idEditingController,
                  fieldViewBuilder: (
                    BuildContext context,
                    TextEditingController fieldTextEditingController,
                    FocusNode fieldFocusNode,
                    VoidCallback onFieldSubmitted,
                  ) {
                    updateTextAndPreserveSelection(
                        fieldTextEditingController, _idController.text);
                    return Obx(() => TextField(
                          autocorrect: false,
                          enableSuggestions: false,
                          keyboardType: TextInputType.visiblePassword,
                          focusNode: fieldFocusNode,
                          style: const TextStyle(
                            fontFamily: 'WorkSans',
                            fontSize: 22,
                            height: 1.4,
                          ),
                          maxLines: 1,
                          cursorColor:
                              Theme.of(context).textTheme.titleLarge?.color,
                          decoration: InputDecoration(
                              filled: false,
                              counterText: '',
                              hintText: _idInputFocused.value
                                  ? null
                                  : translate('Enter Remote ID'),
                              contentPadding: const EdgeInsets.symmetric(
                                  horizontal: 15, vertical: 13)),
                          controller: fieldTextEditingController,
                          inputFormatters: [IDTextInputFormatter()],
                          onChanged: (v) {
                            _idController.id = v;
                          },
                          onSubmitted: (_) {
                            onConnect();
                          },
                        ).workaroundFreezeLinuxMint());
                  },
                  onSelected: (option) {
                    setState(() {
                      _idController.id = option.id;
                      FocusScope.of(context).unfocus();
                    });
                  },
                  optionsViewBuilder: (BuildContext context,
                      AutocompleteOnSelected<Peer> onSelected,
                      Iterable<Peer> options) {
                    options = _autocompleteOpts;
                    double maxHeight = options.length * 50;
                    if (options.length == 1) {
                      maxHeight = 52;
                    } else if (options.length == 3) {
                      maxHeight = 146;
                    } else if (options.length == 4) {
                      maxHeight = 193;
                    }
                    maxHeight = maxHeight.clamp(0, 200);

                    return Align(
                      alignment: Alignment.topLeft,
                      child: Container(
                          decoration: BoxDecoration(
                            boxShadow: [
                              BoxShadow(
                                color: Colors.black.withOpacity(0.3),
                                blurRadius: 5,
                                spreadRadius: 1,
                              ),
                            ],
                          ),
                          child: ClipRRect(
                              borderRadius: BorderRadius.circular(5),
                              child: Material(
                                elevation: 4,
                                child: ConstrainedBox(
                                  constraints: BoxConstraints(
                                    maxHeight: maxHeight,
                                    maxWidth: 319,
                                  ),
                                  child: _allPeersLoader.peers.isEmpty &&
                                          !_allPeersLoader.isPeersLoaded
                                      ? Container(
                                          height: 80,
                                          child: Center(
                                            child: CircularProgressIndicator(
                                              strokeWidth: 2,
                                            ),
                                          ))
                                      : Padding(
                                          padding:
                                              const EdgeInsets.only(top: 5),
                                          child: ListView(
                                            children: options
                                                .map((peer) =>
                                                    AutocompletePeerTile(
                                                        onSelect: () =>
                                                            onSelected(peer),
                                                        peer: peer))
                                                .toList(),
                                          ),
                                        ),
                                ),
                              ))),
                    );
                  },
                )),
              ],
            ),
            Padding(
              padding: const EdgeInsets.only(top: 13.0),
              child: Row(mainAxisAlignment: MainAxisAlignment.end, children: [
                SizedBox(
                  height: 28.0,
                  child: ElevatedButton(
                    onPressed: () {
                      onConnect();
                    },
                    child: Text(translate("Connect")),
                  ),
                ),
                const SizedBox(width: 8),
                Container(
                  height: 28.0,
                  width: 28.0,
                  decoration: BoxDecoration(
                    border: Border.all(color: Theme.of(context).dividerColor),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Center(
                    child: StatefulBuilder(
                      builder: (context, setState) {
                        var offset = Offset(0, 0);
                        return Obx(() => InkWell(
                              child: _menuOpen.value
                                  ? Transform.rotate(
                                      angle: pi,
                                      child: Icon(IconFont.more, size: 14),
                                    )
                                  : Icon(IconFont.more, size: 14),
                              onTapDown: (e) {
                                offset = e.globalPosition;
                              },
                              onTap: () async {
                                _menuOpen.value = true;
                                final x = offset.dx;
                                final y = offset.dy;
                                await mod_menu
                                    .showMenu(
                                  context: context,
                                  position: RelativeRect.fromLTRB(x, y, x, y),
                                  items: [
                                    (
                                      'Transfer file',
                                      () => onConnect(isFileTransfer: true)
                                    ),
                                    (
                                      'View camera',
                                      () => onConnect(isViewCamera: true)
                                    ),
                                    (
                                      '${translate('Terminal')} (beta)',
                                      () => onConnect(isTerminal: true)
                                    ),
                                  ]
                                      .map((e) => MenuEntryButton<String>(
                                            childBuilder: (TextStyle? style) =>
                                                Text(
                                              translate(e.$1),
                                              style: style,
                                            ),
                                            proc: () => e.$2(),
                                            padding: EdgeInsets.symmetric(
                                                horizontal:
                                                    kDesktopMenuPadding.left),
                                            dismissOnClicked: true,
                                          ))
                                      .map((e) => e.build(
                                          context,
                                          const MenuConfig(
                                              commonColor: CustomPopupMenuTheme
                                                  .commonColor,
                                              height:
                                                  CustomPopupMenuTheme.height,
                                              dividerHeight:
                                                  CustomPopupMenuTheme
                                                      .dividerHeight)))
                                      .expand((i) => i)
                                      .toList(),
                                  elevation: 8,
                                )
                                    .then((_) {
                                  _menuOpen.value = false;
                                });
                              },
                            ));
                      },
                    ),
                  ),
                ),
              ]),
            ),
          ],
        ),
      ),
    );
    return Container(
        constraints: const BoxConstraints(maxWidth: 600), child: w);
  }
}
