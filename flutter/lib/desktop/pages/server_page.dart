// original cm window in Sciter version.

import 'dart:async';

import 'package:bot_toast/bot_toast.dart';
import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/widgets/audio_input.dart';
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/desktop/widgets/tabbar_widget.dart';
import 'package:flutter_hbb/models/chat_model.dart';
import 'package:flutter_hbb/utils/platform_channel.dart';
import 'package:get/get.dart';
import 'package:provider/provider.dart';
import 'package:window_manager/window_manager.dart';
import 'package:flutter_svg/flutter_svg.dart';

import '../../common.dart';
import '../../common/widgets/chat_page.dart';
import '../../common/widgets/managed_chat_dialog.dart';
import '../../models/platform_model.dart';
import '../../models/server_model.dart';

/// Set only by this window's own close control, and only once the user has confirmed. Any other
/// way the window can go - a session logout closing every window, the window manager, a native
/// title-bar button this app does not draw - leaves it false, which is the honest answer:
/// nothing in that close says who asked for it. It lives at file scope because the control that
/// sets it (`ConnectionManagerState`) and the handler that reads it (`_DesktopServerPageState`)
/// are different widgets.
bool _cmClosedByOperator = false;

class DesktopServerPage extends StatefulWidget {
  const DesktopServerPage({super.key});

  @override
  State<DesktopServerPage> createState() => _DesktopServerPageState();
}

class _DesktopServerPageState extends State<DesktopServerPage>
    with WindowListener, AutomaticKeepAliveClientMixin {
  final tabController = gFFI.serverModel.tabController;

  _DesktopServerPageState() {
    gFFI.ffiModel.updateEventListener(gFFI.sessionId, "");
    Get.put<DesktopTabController>(tabController);
    tabController.onRemoved = (_, id) {
      onRemoveId(id);
    };
  }

  @override
  void initState() {
    windowManager.addListener(this);
    super.initState();
  }

  @override
  void dispose() {
    windowManager.removeListener(this);
    super.dispose();
  }

  @override
  void onWindowClose() {
    // Other platforms keep the old behaviour exactly: the ambiguity this guards against is a
    // Linux session logout, which closes every window in the session.
    final byOperator = _cmClosedByOperator || !isLinux;
    Future.wait(
            [gFFI.serverModel.closeAll(byOperator: byOperator), gFFI.close()])
        .then((_) {
      if (isMacOS) {
        RdPlatformChannel.instance.terminate();
      } else {
        windowManager.setPreventClose(false);
        windowManager.close();
      }
    });
    super.onWindowClose();
  }

  void onRemoveId(String id) {
    if (tabController.state.value.tabs.isEmpty) {
      windowManager.close();
    }
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    return MultiProvider(
      providers: [
        ChangeNotifierProvider.value(value: gFFI.serverModel),
        ChangeNotifierProvider.value(value: gFFI.chatModel),
      ],
      child: Consumer<ServerModel>(
        builder: (context, serverModel, child) {
          if (serverModel.isManagedDirectoryBuild &&
              serverModel.managedCmCollapsed &&
              serverModel.clients.isNotEmpty) {
            return Scaffold(
              backgroundColor: Colors.transparent,
              body: _ManagedCmCollapsedPill(serverModel: serverModel),
            );
          }
          final body = Scaffold(
            backgroundColor: Theme.of(context).colorScheme.surface,
            body: ConnectionManager(),
          );
          return isLinux
              ? buildVirtualWindowFrame(context, body)
              : workaroundWindowBorder(
                  context,
                  Container(
                    decoration: BoxDecoration(
                        border:
                            Border.all(color: MyTheme.color(context).border!)),
                    child: body,
                  ));
        },
      ),
    );
  }

  @override
  bool get wantKeepAlive => true;
}

class _ManagedCmCollapsedPill extends StatelessWidget {
  final ServerModel serverModel;

  const _ManagedCmCollapsedPill({required this.serverModel});

  @override
  Widget build(BuildContext context) {
    final client = serverModel.clients
            .firstWhereOrNull((c) => c.authorized && !c.disconnected) ??
        serverModel.clients.first;
    final rawName =
        client.displayName.isNotEmpty ? client.displayName : client.peerId;
    // Fleet friendly names follow a "Name-DeviceType" convention (e.g.
    // "Brad-Laptop") - show just the name part, matching the same
    // truncation getActiveSessionPill uses for the client-window "in
    // session" indicator.
    final name = rawName.split('-').first;

    return Padding(
      padding: const EdgeInsets.all(5),
      child: GestureDetector(
        onPanStart: (_) => windowManager.startDragging(),
        child: Material(
          color: Colors.transparent,
          child: InkWell(
            borderRadius: BorderRadius.circular(18),
            onTap: () => unawaited(serverModel.expandManagedCmWindow()),
            child: Container(
              decoration: BoxDecoration(
                color: Theme.of(context)
                    .colorScheme
                    .surface
                    .withValues(alpha: 0.88),
                borderRadius: BorderRadius.circular(18),
                border: Border.all(
                    color: Theme.of(context)
                        .colorScheme
                        .outline
                        .withValues(alpha: 0.45)),
                boxShadow: [
                  BoxShadow(
                    color: Colors.black.withValues(alpha: 0.20),
                    blurRadius: 6,
                    offset: const Offset(0, 2),
                  ),
                ],
              ),
              padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 5),
              child: Row(
                children: [
                  Container(
                    width: 9,
                    height: 9,
                    decoration: const BoxDecoration(
                      color: Colors.green,
                      shape: BoxShape.circle,
                    ),
                  ),
                  const SizedBox(width: 7),
                  Expanded(
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'Incoming from $name',
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: const TextStyle(
                              fontSize: 12, fontWeight: FontWeight.w600),
                        ),
                        StreamBuilder<int>(
                          stream: Stream<int>.periodic(
                              const Duration(seconds: 1), (value) => value),
                          builder: (context, snapshot) {
                            final connectedAt =
                                client.connectedAt ?? DateTime.now();
                            final elapsed =
                                DateTime.now().difference(connectedAt);
                            return Text(
                              formatDurationToTime(elapsed),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                              style: TextStyle(
                                fontSize: 10,
                                color: Theme.of(context)
                                    .colorScheme
                                    .onSurfaceVariant,
                              ),
                            );
                          },
                        ),
                      ],
                    ),
                  ),
                  Tooltip(
                    message: translate('Disconnect'),
                    child: IconButton(
                      visualDensity: VisualDensity.compact,
                      padding: EdgeInsets.zero,
                      constraints:
                          const BoxConstraints.tightFor(width: 30, height: 30),
                      icon: const Icon(Icons.link_off_rounded,
                          color: Colors.redAccent, size: 19),
                      onPressed: () {
                        unawaited(serverModel.expandManagedCmWindow(
                            scheduleRecollapse: false));
                        bind.crateFlutterFfiCmCloseConnection(
                            connId: client.id);
                      },
                    ),
                  ),
                  const Icon(Icons.chevron_left_rounded, size: 19),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class ConnectionManager extends StatefulWidget {
  @override
  State<StatefulWidget> createState() => ConnectionManagerState();
}

class ConnectionManagerState extends State<ConnectionManager>
    with WidgetsBindingObserver {
  final RxBool _controlPageBlock = false.obs;
  final RxBool _sidePageBlock = false.obs;

  ConnectionManagerState() {
    gFFI.serverModel.tabController.onSelected = (client_id_str) {
      final client_id = int.tryParse(client_id_str);
      if (client_id != null) {
        final client =
            gFFI.serverModel.clients.firstWhereOrNull((e) => e.id == client_id);
        if (client != null) {
          gFFI.chatModel.changeCurrentKey(MessageKey(client.peerId, client.id));
          if (client.unreadChatMessageCount.value > 0) {
            WidgetsBinding.instance.addPostFrameCallback((_) {
              client.unreadChatMessageCount.value = 0;
              gFFI.chatModel.showChatPage(MessageKey(client.peerId, client.id));
            });
          }
          windowManager.setTitle(getWindowNameWithId(client.peerId));
        }
      }
    };
    gFFI.chatModel.isConnManager = true;
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    super.didChangeAppLifecycleState(state);
    if (state == AppLifecycleState.resumed) {
      if (!allowRemoteCMModification()) {
        shouldBeBlocked(_controlPageBlock, null);
        shouldBeBlocked(_sidePageBlock, null);
      }
    }
  }

  @override
  void initState() {
    gFFI.serverModel.updateClientState();
    WidgetsBinding.instance.addObserver(this);
    WidgetsBinding.instance.addPostFrameCallback((_) async {
      await windowManager.setAlwaysOnTop(true);
      await windowManager.show();
      await windowManager.focus();
    });
    super.initState();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final serverModel = Provider.of<ServerModel>(context);
    pointerHandler(PointerEvent e) {
      if (serverModel.isManagedDirectoryBuild) {
        serverModel.noteManagedCmInteraction();
        return;
      }
      if (serverModel.cmHiddenTimer != null) {
        serverModel.cmHiddenTimer!.cancel();
        serverModel.cmHiddenTimer = null;
        debugPrint("CM hidden timer has been canceled");
      }
    }

    return serverModel.clients.isEmpty
        ? Column(
            children: [
              buildTitleBar(),
              Expanded(
                child: Center(
                  child: Text(translate("Waiting")),
                ),
              ),
            ],
          )
        : Listener(
            onPointerDown: pointerHandler,
            onPointerMove: pointerHandler,
            child: DesktopTab(
              showTitle: false,
              showMaximize: false,
              showMinimize: true,
              showClose: true,
              onWindowCloseButton: handleWindowCloseButton,
              controller: serverModel.tabController,
              selectedBorderColor: MyTheme.accent,
              maxLabelWidth: 100,
              tail: null, //buildScrollJumper(),
              tabBuilder: (key, icon, label, themeConf) {
                final client = serverModel.clients
                    .firstWhereOrNull((client) => client.id.toString() == key);
                return Row(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Tooltip(
                        message: key,
                        waitDuration: Duration(seconds: 1),
                        child: label),
                    unreadMessageCountBuilder(client?.unreadChatMessageCount)
                        .marginOnly(left: 4),
                  ],
                );
              },
              pageViewBuilder: (pageView) => LayoutBuilder(
                builder: (context, constrains) {
                  var borderWidth = 0.0;
                  if (constrains.maxWidth >
                      kConnectionManagerWindowSizeClosedChat.width) {
                    borderWidth = kConnectionManagerWindowSizeOpenChat.width -
                        constrains.maxWidth;
                  } else {
                    borderWidth = kConnectionManagerWindowSizeClosedChat.width -
                        constrains.maxWidth;
                  }
                  if (borderWidth < 0 || borderWidth > 50) {
                    borderWidth = 0;
                  }
                  final realClosedWidth =
                      kConnectionManagerWindowSizeClosedChat.width -
                          borderWidth;
                  final realChatPageWidth =
                      constrains.maxWidth - realClosedWidth;
                  final row = Row(children: [
                    if (constrains.maxWidth >
                        kConnectionManagerWindowSizeClosedChat.width)
                      Consumer<ChatModel>(
                          builder: (_, model, child) => SizedBox(
                                width: realChatPageWidth,
                                child: allowRemoteCMModification()
                                    ? buildSidePage()
                                    : buildRemoteBlock(
                                        child: buildSidePage(),
                                        block: _sidePageBlock,
                                        mask: true),
                              )),
                    SizedBox(
                        width: realClosedWidth,
                        child: SizedBox(
                            width: realClosedWidth,
                            child: allowRemoteCMModification()
                                ? pageView
                                : buildRemoteBlock(
                                    child: _buildKeyEventBlock(pageView),
                                    block: _controlPageBlock,
                                    mask: false,
                                  ))),
                  ]);
                  return Container(
                    color: Theme.of(context).scaffoldBackgroundColor,
                    child: row,
                  );
                },
              ),
            ),
          );
  }

  Widget buildSidePage() {
    final selected = gFFI.serverModel.tabController.state.value.selected;
    if (selected < 0 || selected >= gFFI.serverModel.clients.length) {
      return Offstage();
    }
    return ChatPage(type: ChatPageType.desktopCM);
  }

  Widget _buildKeyEventBlock(Widget child) {
    return ExcludeFocus(child: child, excluding: true);
  }

  Widget buildTitleBar() {
    return SizedBox(
      height: kDesktopRemoteTabBarHeight,
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.center,
        children: [
          const _AppIcon(),
          Expanded(
            child: GestureDetector(
              onPanStart: (d) {
                windowManager.startDragging();
              },
              child: Container(
                color: Theme.of(context).colorScheme.surface,
              ),
            ),
          ),
          const SizedBox(
            width: 4.0,
          ),
          const _CloseButton()
        ],
      ),
    );
  }

  Widget buildScrollJumper() {
    final offstage = gFFI.serverModel.clients.length < 2;
    final sc = gFFI.serverModel.tabController.state.value.scrollController;
    return Offstage(
        offstage: offstage,
        child: Row(
          children: [
            ActionIcon(
                icon: Icons.arrow_left, iconSize: 22, onTap: sc.backward),
            ActionIcon(
                icon: Icons.arrow_right, iconSize: 22, onTap: sc.forward),
          ],
        ));
  }

  Future<bool> handleWindowCloseButton() async {
    var tabController = gFFI.serverModel.tabController;
    final connLength = tabController.length;
    if (connLength <= 1) {
      _cmClosedByOperator = true;
      windowManager.close();
      return true;
    } else {
      final bool res;
      if (!option2bool(
          kOptionEnableConfirmClosingTabs,
          bind.crateFlutterFfiMainGetLocalOption(
              key: kOptionEnableConfirmClosingTabs))) {
        res = true;
      } else {
        res = await closeConfirmDialog();
      }
      if (res) {
        // After the dialog, never before it: an external close while it is open must not
        // inherit an intent the user had not expressed yet.
        _cmClosedByOperator = true;
        windowManager.close();
      }
      return res;
    }
  }
}

Widget buildConnectionCard(Client client) {
  return Consumer<ServerModel>(
    builder: (context, value, child) => Column(
      mainAxisAlignment: MainAxisAlignment.start,
      crossAxisAlignment: CrossAxisAlignment.start,
      key: ValueKey(client.id),
      children: [
        _CmHeader(client: client),
        client.type_() == ClientType.file ||
                client.type_() == ClientType.portForward ||
                client.type_() == ClientType.terminal ||
                client.disconnected
            ? Offstage()
            : _PrivilegeBoard(client: client),
        if (!client.disconnected) _StandaloneChatButton(client: client),
        client.authorized
            ? Expanded(
                child: Align(
                  alignment: Alignment.bottomCenter,
                  child: _CmControlPanel(client: client),
                ),
              )
            : _CmControlPanel(client: client),
      ],
    ).paddingSymmetric(vertical: 2.0, horizontal: 6.0),
  );
}

class _AppIcon extends StatelessWidget {
  const _AppIcon();

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: EdgeInsets.symmetric(horizontal: 4.0),
      child: loadIcon(30),
    );
  }
}

class _CloseButton extends StatelessWidget {
  const _CloseButton();

  @override
  Widget build(BuildContext context) {
    return IconButton(
      onPressed: () {
        windowManager.close();
      },
      icon: const Icon(
        IconFont.close,
        size: 18,
      ),
      splashColor: Colors.transparent,
      hoverColor: Colors.transparent,
    );
  }
}

class _CmHeader extends StatefulWidget {
  final Client client;

  const _CmHeader({required this.client});

  @override
  State<_CmHeader> createState() => _CmHeaderState();
}

class _CmHeaderState extends State<_CmHeader>
    with AutomaticKeepAliveClientMixin {
  Client get client => widget.client;

  final _time = 0.obs;
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _timer = Timer.periodic(Duration(seconds: 1), (_) {
      if (client.authorized && !client.disconnected) {
        _time.value = _time.value + 1;
      }
    });
    // Call onSelected in post frame callback, since we cannot guarantee that the callback will not call setState.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      gFFI.serverModel.tabController.onSelected?.call(client.id.toString());
    });
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    return Container(
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(10.0),
        gradient: LinearGradient(
          begin: Alignment.topRight,
          end: Alignment.bottomLeft,
          colors: [
            Color(0xff00bfe1),
            Color(0xff0071ff),
          ],
        ),
      ),
      margin: EdgeInsets.symmetric(horizontal: 3.0, vertical: 5.0),
      padding: EdgeInsets.only(
        top: 6.0,
        bottom: 6.0,
        left: 6.0,
        right: 3.0,
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _buildClientAvatar().marginOnly(right: 6.0),
          Expanded(
            child: Column(
              mainAxisAlignment: MainAxisAlignment.start,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                FittedBox(
                    child: Text(
                  translate('Incoming from'),
                  style: TextStyle(
                    color: Colors.white,
                    fontWeight: FontWeight.bold,
                    fontSize: 16,
                    overflow: TextOverflow.ellipsis,
                  ),
                  maxLines: 1,
                )),
                FittedBox(
                  child: Text(
                    // Fleet friendly names follow a "Name-DeviceType"
                    // convention - show just the name part here, matching
                    // the same truncation _ManagedCmCollapsedPill already
                    // uses, instead of the raw numeric peer ID.
                    client.displayName.split('-').first,
                    style: TextStyle(color: Colors.white, fontSize: 12),
                  ),
                ),
                if (client.type_() == ClientType.terminal)
                  FittedBox(
                    child: Text(
                      translate("Terminal"),
                      style: TextStyle(color: Colors.white70, fontSize: 12),
                    ),
                  ),
                if (client.type_() == ClientType.file)
                  FittedBox(
                    child: Text(
                      translate("Transfer file"),
                      style: TextStyle(color: Colors.white70, fontSize: 12),
                    ),
                  ),
                if (client.type_() == ClientType.camera)
                  FittedBox(
                    child: Text(
                      translate("View camera"),
                      style: TextStyle(color: Colors.white70, fontSize: 12),
                    ),
                  ),
                if (client.portForward.isNotEmpty)
                  FittedBox(
                    child: Text(
                      "Port Forward: ${client.portForward}",
                      style: TextStyle(color: Colors.white70, fontSize: 12),
                    ),
                  ),
                SizedBox(height: 4.0),
                FittedBox(
                    child: Row(
                  children: [
                    Text(
                      client.authorized
                          ? client.disconnected
                              ? translate("Disconnected")
                              : translate("Connected")
                          : "${translate("Request access to your device")}...",
                      style: TextStyle(color: Colors.white, fontSize: 12),
                    ).marginOnly(right: 8.0),
                    if (client.authorized)
                      Obx(
                        () => Text(
                          formatDurationToTime(
                            Duration(seconds: _time.value),
                          ),
                          style: TextStyle(color: Colors.white, fontSize: 12),
                        ),
                      )
                  ],
                ))
              ],
            ),
          ),
          Offstage(
            offstage: !client.authorized ||
                (client.type_() != ClientType.remote &&
                    client.type_() != ClientType.file &&
                    client.type_() != ClientType.camera),
            child: IconButton(
              onPressed: () => checkClickTime(client.id, () {
                if (client.type_() == ClientType.file) {
                  gFFI.chatModel.toggleCMFilePage();
                } else if (gFFI.serverModel.isManagedDirectoryBuild) {
                  unawaited(openManagedChatWithPeer(client.peerId));
                } else {
                  gFFI.chatModel
                      .toggleCMChatPage(MessageKey(client.peerId, client.id));
                }
              }),
              icon: SvgPicture.asset(client.type_() == ClientType.file
                  ? 'assets/file_transfer.svg'
                  : 'assets/chat2.svg'),
              splashRadius: kDesktopIconButtonSplashRadius,
            ),
          ),
          // Launches this machine's own local RustDrop.exe (the controlled
          // side's copy) - mirrors the controller-side button in
          // remote_toolbar.dart's _RustDropMenu. No signaling between the
          // two machines; each side only ever launches its own local copy.
          Offstage(
            offstage:
                !client.authorized || !gFFI.serverModel.isManagedDirectoryBuild,
            child: Tooltip(
              message: translate('RustDrop'),
              child: InkWell(
                borderRadius: BorderRadius.circular(16),
                onTap: () => checkClickTime(client.id, () {
                  if (!bind.crateFlutterFfiMainLaunchRustdrop()) {
                    BotToast.showText(
                      text: translate(
                          'RustDrop is not installed on this machine.'),
                      contentColor: Colors.red,
                    );
                  }
                }),
                child: Container(
                  width: 32,
                  height: 32,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: MyTheme.button,
                  ),
                  child: const Icon(Icons.send_and_archive_outlined,
                      color: Colors.white, size: 16),
                ),
              ),
            ).marginSymmetric(horizontal: 4),
          )
        ],
      ),
    );
  }

  @override
  bool get wantKeepAlive => true;

  Widget _buildClientAvatar() {
    return buildAvatarWidget(
          avatar: client.avatar,
          size: 48,
          borderRadius: 10,
          fallback: _buildInitialAvatar(),
        ) ??
        _buildInitialAvatar();
  }

  Widget _buildInitialAvatar() {
    return Container(
      width: 48,
      height: 48,
      alignment: Alignment.center,
      decoration: BoxDecoration(
        color: str2color(client.displayName),
        borderRadius: BorderRadius.circular(10.0),
      ),
      child: Text(
        client.displayName.isNotEmpty ? client.displayName[0] : '?',
        style: TextStyle(
          fontWeight: FontWeight.bold,
          color: Colors.white,
          fontSize: 34,
        ),
      ),
    );
  }
}

class _PrivilegeBoard extends StatefulWidget {
  final Client client;

  const _PrivilegeBoard({required this.client});

  @override
  State<StatefulWidget> createState() => _PrivilegeBoardState();
}

class _PrivilegeBoardState extends State<_PrivilegeBoard> {
  late final client = widget.client;

  Widget buildPermissionButton(
      bool enabled, String label, Function(bool)? onTap, String tooltipText,
      {required bool canModify}) {
    return Tooltip(
      message: "$tooltipText: ${enabled ? "ON" : "OFF"}",
      waitDuration: Duration.zero,
      child: Container(
        decoration: BoxDecoration(
          color: enabled
              ? (canModify
                  ? MyTheme.accent
                  : MyTheme.accent.withValues(alpha: 0.6))
              : Colors.grey[700],
          borderRadius: BorderRadius.circular(8.0),
        ),
        child: InkWell(
          borderRadius: BorderRadius.circular(8.0),
          onTap: canModify
              ? () =>
                  checkClickTime(widget.client.id, () => onTap?.call(!enabled))
              : null,
          child: Align(
            alignment: Alignment.center,
            child: Text(
              translate(label),
              textAlign: TextAlign.center,
              style: TextStyle(color: Colors.white, fontSize: 12),
            ),
          ),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final managed = gFFI.serverModel.isManagedDirectoryBuild;
    final spacing = 6.0;
    final canModifyPermission = bind.crateFlutterFfiMainGetBuildinOption(
            key: kOptionEnablePermChangeInAcceptWindow) !=
        'N';
    // Managed clients get the simplified, text-labeled button row; the
    // stock (non-managed) icon grid is untouched below.
    if (managed) {
      return Container(
        width: double.infinity,
        height: 56.0,
        margin: EdgeInsets.all(3.0),
        padding: EdgeInsets.all(4.0),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(10.0),
          color: Theme.of(context).colorScheme.surface,
          boxShadow: [
            BoxShadow(
              color: Colors.black.withValues(alpha: 0.2),
              spreadRadius: 1,
              blurRadius: 1,
              offset: Offset(0, 1.5),
            ),
          ],
        ),
        child: Row(
          children: [
            Expanded(
              // client.keyboard mirrors the host's OPTION_ENABLE_KEYBOARD
              // policy setting, not per-connection authorization - it is
              // true by default even while this connection is still
              // pending. Force the button to show denied/grey and be
              // non-interactive until the connection is actually
              // authorized, so it never visually implies remote control
              // has been granted before Accept is clicked.
              child: buildPermissionButton(
                client.authorized && client.keyboard,
                'Remote Control',
                (enabled) {
                  bind.crateFlutterFfiCmSwitchPermission(
                      connId: client.id, name: "keyboard", enabled: enabled);
                  setState(() => client.keyboard = enabled);
                },
                translate('Enable keyboard/mouse'),
                canModify: client.authorized && canModifyPermission,
              ),
            ),
            SizedBox(width: spacing),
            Expanded(
              child: buildPermissionButton(
                client.clipboard,
                'Clipboard',
                (enabled) {
                  bind.crateFlutterFfiCmSwitchPermission(
                      connId: client.id, name: "clipboard", enabled: enabled);
                  setState(() => client.clipboard = enabled);
                },
                translate('Enable clipboard'),
                canModify: canModifyPermission,
              ),
            ),
          ],
        ),
      );
    }
    return Container(
      width: double.infinity,
      height: 112.0,
      margin: EdgeInsets.all(3.0),
      padding: EdgeInsets.all(4.0),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(10.0),
        color: Theme.of(context).colorScheme.surface,
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.2),
            spreadRadius: 1,
            blurRadius: 1,
            offset: Offset(0, 1.5),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.center,
        children: [
          Text(
            translate("Permissions"),
            style: TextStyle(fontSize: 13, fontWeight: FontWeight.bold),
            textAlign: TextAlign.center,
          ).marginOnly(left: 2.0, bottom: 4.0),
          Expanded(
            child: GridView.count(
              crossAxisCount: 4,
              padding: EdgeInsets.symmetric(horizontal: spacing),
              mainAxisSpacing: spacing,
              crossAxisSpacing: spacing,
              children: [
                Tooltip(
                  message:
                      "${translate('Enable keyboard/mouse')}: ${client.keyboard ? "ON" : "OFF"}",
                  waitDuration: Duration.zero,
                  child: Container(
                    decoration: BoxDecoration(
                      color: client.keyboard
                          ? (canModifyPermission
                              ? MyTheme.accent
                              : MyTheme.accent.withValues(alpha: 0.6))
                          : Colors.grey[700],
                      borderRadius: BorderRadius.circular(8.0),
                    ),
                    padding: EdgeInsets.all(5.0),
                    child: InkWell(
                      onTap: canModifyPermission
                          ? () => checkClickTime(widget.client.id, () {
                                bind.crateFlutterFfiCmSwitchPermission(
                                    connId: client.id,
                                    name: "keyboard",
                                    enabled: !client.keyboard);
                                setState(
                                    () => client.keyboard = !client.keyboard);
                              })
                          : null,
                      child: Column(
                        mainAxisAlignment: MainAxisAlignment.spaceAround,
                        children: [
                          Expanded(
                            child: Icon(Icons.keyboard, color: Colors.white),
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
                Tooltip(
                  message:
                      "${translate('Enable clipboard')}: ${client.clipboard ? "ON" : "OFF"}",
                  waitDuration: Duration.zero,
                  child: Container(
                    decoration: BoxDecoration(
                      color: client.clipboard
                          ? (canModifyPermission
                              ? MyTheme.accent
                              : MyTheme.accent.withValues(alpha: 0.6))
                          : Colors.grey[700],
                      borderRadius: BorderRadius.circular(8.0),
                    ),
                    padding: EdgeInsets.all(5.0),
                    child: InkWell(
                      onTap: canModifyPermission
                          ? () => checkClickTime(widget.client.id, () {
                                bind.crateFlutterFfiCmSwitchPermission(
                                    connId: client.id,
                                    name: "clipboard",
                                    enabled: !client.clipboard);
                                setState(
                                    () => client.clipboard = !client.clipboard);
                              })
                          : null,
                      child: Column(
                        mainAxisAlignment: MainAxisAlignment.spaceAround,
                        children: [
                          Expanded(
                            child: Icon(Icons.assignment_rounded,
                                color: Colors.white),
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
                Tooltip(
                  message:
                      "${translate('Enable file copy and paste')}: ${client.file ? "ON" : "OFF"}",
                  waitDuration: Duration.zero,
                  child: Container(
                    decoration: BoxDecoration(
                      color: client.file
                          ? (canModifyPermission
                              ? MyTheme.accent
                              : MyTheme.accent.withValues(alpha: 0.6))
                          : Colors.grey[700],
                      borderRadius: BorderRadius.circular(8.0),
                    ),
                    padding: EdgeInsets.all(5.0),
                    child: InkWell(
                      onTap: canModifyPermission
                          ? () => checkClickTime(widget.client.id, () {
                                bind.crateFlutterFfiCmSwitchPermission(
                                    connId: client.id,
                                    name: "file",
                                    enabled: !client.file);
                                setState(() => client.file = !client.file);
                              })
                          : null,
                      child: Column(
                        mainAxisAlignment: MainAxisAlignment.spaceAround,
                        children: [
                          Expanded(
                            child: Icon(Icons.upload_file_rounded,
                                color: Colors.white),
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
                Tooltip(
                  message:
                      "${translate('Enable remote restart')}: ${client.restart ? "ON" : "OFF"}",
                  waitDuration: Duration.zero,
                  child: Container(
                    decoration: BoxDecoration(
                      color: client.restart
                          ? (canModifyPermission
                              ? MyTheme.accent
                              : MyTheme.accent.withValues(alpha: 0.6))
                          : Colors.grey[700],
                      borderRadius: BorderRadius.circular(8.0),
                    ),
                    padding: EdgeInsets.all(5.0),
                    child: InkWell(
                      onTap: canModifyPermission
                          ? () => checkClickTime(widget.client.id, () {
                                bind.crateFlutterFfiCmSwitchPermission(
                                    connId: client.id,
                                    name: "restart",
                                    enabled: !client.restart);
                                setState(
                                    () => client.restart = !client.restart);
                              })
                          : null,
                      child: Column(
                        mainAxisAlignment: MainAxisAlignment.spaceAround,
                        children: [
                          Expanded(
                            child: Icon(Icons.restart_alt_rounded,
                                color: Colors.white),
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

const double buttonBottomMargin = 8;

// A standalone "Chat" button shown while a connection is still pending
// approval, so the local user can ask the requester a question before
// deciding whether to accept - reuses the same chat page toggle already
// used for authorized sessions (see the chat icon in _CmHeaderState), just
// made available earlier in the flow instead of gated on client.authorized.
class _StandaloneChatButton extends StatelessWidget {
  final Client client;

  const _StandaloneChatButton({required this.client});

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      height: 28.0,
      margin: EdgeInsets.symmetric(horizontal: 3.0),
      child: ElevatedButton.icon(
        onPressed: () => checkClickTime(client.id, () {
          // Managed builds route chat through the persistent managed-chat
          // conversation (keyed by the peer's numeric RustDesk id) instead
          // of the old ephemeral peer-to-peer ChatMessage protocol, so
          // in-session messages show up in the same history as
          // out-of-session ones. Stock builds keep the original behavior.
          if (gFFI.serverModel.isManagedDirectoryBuild) {
            unawaited(openManagedChatWithPeer(client.peerId));
          } else {
            gFFI.chatModel
                .toggleCMChatPage(MessageKey(client.peerId, client.id));
          }
        }),
        icon: Icon(Icons.chat_bubble_outline_rounded, size: 14),
        label: Text(translate('Chat'), style: TextStyle(fontSize: 12)),
        style: ElevatedButton.styleFrom(
          padding: EdgeInsets.zero,
          backgroundColor: MyTheme.accent,
          foregroundColor: Colors.white,
        ),
      ),
    );
  }
}

class _CmControlPanel extends StatelessWidget {
  final Client client;

  const _CmControlPanel({required this.client});

  @override
  Widget build(BuildContext context) {
    return client.authorized
        ? client.disconnected
            ? buildDisconnected(context)
            : buildAuthorized(context)
        : buildUnAuthorized(context);
  }

  Widget buildAuthorized(BuildContext context) {
    final bool canElevate = bind.crateFlutterFfiCmCanElevate();
    final model = Provider.of<ServerModel>(context);
    final showElevation = canElevate &&
        model.showElevation &&
        client.type_() == ClientType.remote;
    return Column(
      mainAxisAlignment: MainAxisAlignment.end,
      children: [
        Offstage(
          offstage: true,
          child: Row(
            children: [
              Expanded(
                child: buildButton(context,
                    color: MyTheme.accent,
                    onClick: null, onTapDown: (details) async {
                  final devicesInfo =
                      await AudioInput.getDevicesInfo(true, true);
                  List<String> devices = devicesInfo['devices'] as List<String>;
                  if (devices.isEmpty) {
                    msgBox(
                      gFFI.sessionId,
                      'custom-nocancel-info',
                      'Prompt',
                      'no_audio_input_device_tip',
                      '',
                      gFFI.dialogManager,
                    );
                    return;
                  }

                  String currentDevice = devicesInfo['current'] as String;
                  final x = details.globalPosition.dx;
                  final y = details.globalPosition.dy;
                  final position = RelativeRect.fromLTRB(x, y, x, y);
                  showMenu(
                    context: context,
                    position: position,
                    items: devices
                        .map((d) => PopupMenuItem<String>(
                              value: d,
                              height: 18,
                              padding: EdgeInsets.zero,
                              onTap: () => AudioInput.setDevice(d, true, true),
                              child: IgnorePointer(
                                  child: RadioMenuButton(
                                value: d,
                                groupValue: currentDevice,
                                onChanged: (v) {
                                  if (v != null) {
                                    AudioInput.setDevice(v, true, true);
                                  }
                                },
                                child: Container(
                                  child: Text(
                                    d,
                                    overflow: TextOverflow.ellipsis,
                                    maxLines: 1,
                                  ),
                                  constraints: BoxConstraints(
                                      maxWidth:
                                          kConnectionManagerWindowSizeClosedChat
                                                  .width -
                                              80),
                                ),
                              )),
                            ))
                        .toList(),
                  );
                },
                    icon: Icon(
                      Icons.call_rounded,
                      color: Colors.white,
                      size: 14,
                    ),
                    text: "Audio input",
                    textColor: Colors.white),
              ),
              Expanded(
                child: buildButton(
                  context,
                  color: Colors.red,
                  onClick: () => closeVoiceCall(),
                  icon: Icon(
                    Icons.call_end_rounded,
                    color: Colors.white,
                    size: 14,
                  ),
                  text: "Stop voice call",
                  textColor: Colors.white,
                ),
              )
            ],
          ),
        ),
        Offstage(
          offstage: true,
          child: Row(
            children: [
              Expanded(
                child: buildButton(context,
                    color: MyTheme.accent,
                    onClick: () => handleVoiceCall(true),
                    icon: Icon(
                      Icons.call_rounded,
                      color: Colors.white,
                      size: 14,
                    ),
                    text: "Accept",
                    textColor: Colors.white),
              ),
              Expanded(
                child: buildButton(
                  context,
                  color: Colors.red,
                  onClick: () => handleVoiceCall(false),
                  icon: Icon(
                    Icons.phone_disabled_rounded,
                    color: Colors.white,
                    size: 14,
                  ),
                  text: "Dismiss",
                  textColor: Colors.white,
                ),
              )
            ],
          ),
        ),
        Offstage(
          offstage: !client.fromSwitch,
          child: buildButton(context,
              color: Colors.purple,
              onClick: () => handleSwitchBack(context),
              icon: Icon(Icons.reply, color: Colors.white),
              text: "Switch Sides",
              textColor: Colors.white),
        ),
        Offstage(
          offstage: !showElevation,
          child: buildButton(
            context,
            color: MyTheme.accent,
            onClick: () {
              handleElevate(context);
            },
            icon: Icon(
              Icons.security_rounded,
              color: Colors.white,
              size: 14,
            ),
            text: 'Elevate',
            textColor: Colors.white,
          ),
        ),
        Row(
          children: [
            Expanded(
              child: buildButton(context,
                  color: Colors.redAccent,
                  onClick: handleDisconnect,
                  text: 'Disconnect',
                  icon: Icon(
                    Icons.link_off_rounded,
                    color: Colors.white,
                    size: 14,
                  ),
                  textColor: Colors.white),
            ),
          ],
        )
      ],
    ).marginOnly(bottom: buttonBottomMargin);
  }

  Widget buildDisconnected(BuildContext context) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        Expanded(
            child: buildButton(context,
                color: MyTheme.accent,
                onClick: handleClose,
                text: 'Close',
                textColor: Colors.white)),
      ],
    ).marginOnly(bottom: buttonBottomMargin);
  }

  Widget buildUnAuthorized(BuildContext context) {
    final bool canElevate = bind.crateFlutterFfiCmCanElevate();
    final model = Provider.of<ServerModel>(context);
    final showElevation = canElevate &&
        model.showElevation &&
        client.type_() == ClientType.remote &&
        bind.crateFlutterFfiMainGetBuildinOption(
                key: kOptionHideElevateButtonInAcceptWindow) !=
            'Y';
    final showAccept = model.approveMode != 'password';
    return Column(
      mainAxisAlignment: MainAxisAlignment.end,
      children: [
        Offstage(
          offstage: !showElevation || !showAccept,
          child: buildButton(context, color: Colors.green[700], onClick: () {
            handleAccept(context);
            handleElevate(context);
          },
              text: 'Accept and Elevate',
              icon: Icon(
                Icons.security_rounded,
                color: Colors.white,
                size: 14,
              ),
              textColor: Colors.white,
              tooltip: 'accept_and_elevate_btn_tooltip'),
        ),
        Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            if (showAccept)
              Expanded(
                child: Column(
                  children: [
                    buildButton(
                      context,
                      color: MyTheme.accent,
                      onClick: () {
                        handleAccept(context);
                      },
                      text: 'Accept',
                      textColor: Colors.white,
                    ),
                  ],
                ),
              ),
            Expanded(
              child: buildButton(
                context,
                color: Colors.transparent,
                border: Border.all(color: Colors.grey),
                onClick: handleDisconnect,
                text: 'Cancel',
                textColor: null,
              ),
            ),
          ],
        ),
      ],
    ).marginOnly(bottom: buttonBottomMargin);
  }

  Widget buildButton(BuildContext context,
      {required Color? color,
      GestureTapCallback? onClick,
      Widget? icon,
      BoxBorder? border,
      required String text,
      required Color? textColor,
      String? tooltip,
      GestureTapDownCallback? onTapDown}) {
    assert(!(onClick == null && onTapDown == null));
    Widget textWidget;
    if (icon != null) {
      textWidget = Text(
        translate(text),
        style: TextStyle(color: textColor),
        textAlign: TextAlign.center,
      );
    } else {
      textWidget = Expanded(
        child: Text(
          translate(text),
          style: TextStyle(color: textColor),
          textAlign: TextAlign.center,
        ),
      );
    }
    final borderRadius = BorderRadius.circular(10.0);
    final btn = Container(
      height: 28,
      decoration: BoxDecoration(
          color: color, borderRadius: borderRadius, border: border),
      child: InkWell(
        borderRadius: borderRadius,
        onTap: () {
          if (onClick == null) return;
          checkClickTime(client.id, onClick);
        },
        onTapDown: (details) {
          if (onTapDown == null) return;
          checkClickTime(client.id, () {
            onTapDown.call(details);
          });
        },
        child: Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Offstage(offstage: icon == null, child: icon).marginOnly(right: 5),
            textWidget,
          ],
        ),
      ),
    );
    return (tooltip != null
            ? Tooltip(
                message: translate(tooltip),
                child: btn,
              )
            : btn)
        .marginAll(4);
  }

  void handleDisconnect() {
    bind.crateFlutterFfiCmCloseConnection(connId: client.id);
  }

  void handleAccept(BuildContext context) {
    final model = Provider.of<ServerModel>(context, listen: false);
    model.sendLoginResponse(client, true);
  }

  void handleElevate(BuildContext context) {
    final model = Provider.of<ServerModel>(context, listen: false);
    model.setShowElevation(false);
    bind.crateFlutterFfiCmElevatePortable(connId: client.id);
  }

  void handleClose() async {
    await bind.crateFlutterFfiCmRemoveDisconnectedConnection(connId: client.id);
    if (await bind.crateFlutterFfiCmGetClientsLength() == 0) {
      windowManager.close();
    }
  }

  void handleSwitchBack(BuildContext context) {
    bind.crateFlutterFfiCmSwitchBack(connId: client.id);
  }

  void handleVoiceCall(bool accept) {
    bind.crateFlutterFfiCmHandleIncomingVoiceCall(
        id: client.id, accept: accept);
  }

  void closeVoiceCall() {
    bind.crateFlutterFfiCmCloseVoiceCall(id: client.id);
  }
}

void checkClickTime(int id, Function() callback) async {
  if (allowRemoteCMModification()) {
    callback();
    return;
  }
  var clickCallbackTime = DateTime.now().millisecondsSinceEpoch;
  await bind.crateFlutterFfiCmCheckClickTime(connId: id);
  Timer(const Duration(milliseconds: 120), () async {
    var d = clickCallbackTime - await bind.crateFlutterFfiCmGetClickTime();
    if (d > 120) callback();
  });
}

bool allowRemoteCMModification() {
  return false;
}
