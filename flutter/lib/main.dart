import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:bot_toast/bot_toast.dart';
import 'package:desktop_multi_window/desktop_multi_window.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common/widgets/managed_chat_dialog.dart';
import 'package:flutter_hbb/common/widgets/overlay.dart';
import 'package:flutter_hbb/desktop/pages/desktop_tab_page.dart';
import 'package:flutter_hbb/desktop/pages/install_page.dart';
import 'package:flutter_hbb/desktop/pages/server_page.dart';
import 'package:flutter_hbb/desktop/screen/desktop_managed_chat_screen.dart';
import 'package:flutter_hbb/desktop/screen/desktop_view_camera_screen.dart';
import 'package:flutter_hbb/desktop/screen/desktop_port_forward_screen.dart';
import 'package:flutter_hbb/desktop/screen/desktop_remote_screen.dart';
import 'package:flutter_hbb/desktop/screen/desktop_rustdrop_screen.dart';
import 'package:flutter_hbb/desktop/screen/desktop_terminal_screen.dart';
import 'package:flutter_hbb/desktop/widgets/refresh_wrapper.dart';
import 'package:flutter_hbb/models/state_model.dart';
import 'package:flutter_hbb/utils/multi_window_manager.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:get/get.dart';
import 'package:provider/provider.dart';
import 'package:window_manager/window_manager.dart';

import 'common.dart';
import 'consts.dart';
import 'mobile/pages/home_page.dart';
import 'mobile/pages/server_page.dart';
import 'mobile/widgets/deploy_dialog.dart';
import 'models/platform_model.dart';

/// Basic window and launch properties.
int? kWindowId;
WindowType? kWindowType;
late List<String> kBootArgs;

Future<void> main(List<String> args) async {
  earlyAssert();
  WidgetsFlutterBinding.ensureInitialized();

  debugPrint("launch args: $args");
  kBootArgs = List.from(args);

  if (!isDesktop) {
    runMobileApp();
    return;
  }
  // main window
  if (args.isNotEmpty && args.first == 'multi_window') {
    kWindowId = int.parse(args[1]);
    stateGlobal.setWindowId(kWindowId!);
    final argument = args[2].isEmpty
        ? <String, dynamic>{}
        : jsonDecode(args[2]) as Map<String, dynamic>;
    int type = argument['type'] ?? -1;
    // to-do: No need to parse window id ?
    // Because stateGlobal.windowId is a global value.
    argument['windowId'] = kWindowId;
    kWindowType = type.windowType;
    // Every sub window (including chat) draws its own frameless custom
    // title bar - see tabbar_widget.dart / desktop_managed_chat_screen.dart.
    // This isn't just cosmetic: with setPreventClose(true) below, the
    // native OS close button's WM_CLOSE never reaches Dart at all (it's
    // silently swallowed), so every window type needs its own explicit
    // close control wired to windowManager.close(), which IS intercepted.
    if (!isMacOS) {
      WindowController.fromWindowId(kWindowId!).showTitleBar(false);
    }
    switch (kWindowType) {
      case WindowType.RemoteDesktop:
        desktopType = DesktopType.remote;
        runMultiWindow(
          argument,
          kAppTypeDesktopRemote,
        );
        break;
      case WindowType.FileTransfer:
        desktopType = DesktopType.fileTransfer;
        runMultiWindow(
          argument,
          kAppTypeDesktopFileTransfer,
        );
        break;
      case WindowType.ViewCamera:
        desktopType = DesktopType.viewCamera;
        runMultiWindow(
          argument,
          kAppTypeDesktopViewCamera,
        );
        break;
      case WindowType.PortForward:
        desktopType = DesktopType.portForward;
        runMultiWindow(
          argument,
          kAppTypeDesktopPortForward,
        );
        break;
      case WindowType.Terminal:
        desktopType = DesktopType.terminal;
        runMultiWindow(
          argument,
          kAppTypeDesktopTerminal,
        );
        break;
      case WindowType.ManagedChat:
        desktopType = DesktopType.managedChat;
        runMultiWindow(
          argument,
          kAppTypeDesktopManagedChat,
        );
        break;
      default:
        break;
    }
  } else if (args.isNotEmpty && args.first == '--cm') {
    debugPrint("--cm started");
    desktopType = DesktopType.cm;
    await windowManager.ensureInitialized();
    runConnectionManagerScreen();
  } else if (args.isNotEmpty && args.first == '--rustdrop') {
    debugPrint("--rustdrop started");
    desktopType = DesktopType.rustdrop;
    await windowManager.ensureInitialized();
    runRustDropScreen();
  } else if (args.contains('--install')) {
    runInstallPage();
  } else {
    desktopType = DesktopType.main;
    await windowManager.ensureInitialized();
    windowManager.setPreventClose(true);
    if (isMacOS) {
      disableWindowMovable(kWindowId);
    }
    runMainApp(true);
  }
}

Future<void> initEnv(String appType) async {
  // global shared preference
  await platformFFI.init(appType);
  // global FFI, use this **ONLY** for global configuration
  // for convenience, use global FFI on mobile platform
  // focus on multi-ffi on desktop first
  await initGlobalFFI();
  // await Firebase.initializeApp();
  _registerEventHandler();
  // Update the system theme.
  updateSystemWindowTheme();
}

void runMainApp(bool startService) async {
  // register uni links
  await initEnv(kAppTypeMain);
  checkUpdate();
  // trigger connection status updater
  await bind.crateFlutterFfiMainCheckConnectStatus();
  if (startService) {
    gFFI.serverModel.startService();
  }
  await Future.wait([gFFI.abModel.loadCache(), gFFI.groupModel.loadCache()]);
  gFFI.userModel.refreshCurrentUser();
  // So the Directory tab's unread-mail badge (see peer_card.dart) has
  // correct state from a cold start, not just after the first live push.
  unawaited(gFFI.managedChatModel.loadLocalConversations());
  runApp(App());

  bool? alwaysOnTop;
  if (isDesktop) {
    alwaysOnTop = bind.crateFlutterFfiMainGetBuildinOption(
            key: "main-window-always-on-top") ==
        'Y';
  }

  // Set window option.
  WindowOptions windowOptions = getHiddenTitleBarWindowOptions(
      isMainWindow: true, alwaysOnTop: alwaysOnTop);

  // Same belt-and-suspenders and same auto-retry-once as runRustDropScreen()
  // below: waitUntilReadyToShow's callback can silently never fire (no
  // exception, no window, no error). Unlike RustDrop there's no
  // single-instance mutex here to wedge, but a hung, windowless process is
  // still worth cleaning up, and a fresh relaunch has a real chance of
  // landing where the first attempt didn't. Multiple main windows can
  // already coexist (no single-instance guard for this path), so spawning
  // one more here is exactly as safe as the user launching it by hand.
  final isRetryAttempt = Platform.environment['WINDOW_LAUNCH_RETRY'] == '1';
  bool windowShown = false;
  Timer(const Duration(seconds: 5), () {
    if (windowShown) return;
    if (isRetryAttempt) {
      _rustdropWindowDiag(
          'runMainApp: TIMEOUT on retry attempt, giving up, exiting');
      exit(0);
    }
    _rustdropWindowDiag(
        'runMainApp: TIMEOUT waiting for window, relaunching fresh attempt in 2s');
    Future.delayed(const Duration(seconds: 2), () async {
      try {
        await Process.start(
          Platform.resolvedExecutable,
          [],
          environment: {'WINDOW_LAUNCH_RETRY': '1'},
          mode: ProcessStartMode.detached,
        );
        _rustdropWindowDiag('runMainApp: retry relaunch spawned');
      } catch (e) {
        _rustdropWindowDiag('runMainApp: retry relaunch FAILED: $e');
      }
      exit(0);
    });
  });

  _rustdropWindowDiag('runMainApp: calling waitUntilReadyToShow');
  windowManager.waitUntilReadyToShow(windowOptions, () async {
    windowShown = true;
    _rustdropWindowDiag('runMainApp: waitUntilReadyToShow callback fired');
    try {
      // Restore the location of the main window before window hide or show.
      await restoreWindowPosition(WindowType.Main);
      _rustdropWindowDiag('runMainApp: restoreWindowPosition done');
      // Check the startup argument, if we successfully handle the argument, we keep the main window hidden.
      final handledByUniLinks = await initUniLinks();
      debugPrint("handled by uni links: $handledByUniLinks");
      _rustdropWindowDiag(
          'runMainApp: initUniLinks done, handledByUniLinks=$handledByUniLinks');
      if (handledByUniLinks || handleUriLink(cmdArgs: kBootArgs)) {
        windowManager.hide();
        _rustdropWindowDiag('runMainApp: hide() (handled by uni link)');
      } else {
        windowManager.show();
        windowManager.focus();
        _rustdropWindowDiag('runMainApp: show()+focus() done');
        // Move registration of active main window here to prevent from async visible check.
        rustDeskWinManager.registerActiveWindow(kWindowMainId);
      }
      windowManager.setOpacity(1);
      windowManager.setTitle(getWindowName());
      // Do not use `windowManager.setResizable()` here.
      setResizable(!bind.crateFlutterFfiIsIncomingOnly());
      _rustdropWindowDiag('runMainApp: all complete');
    } catch (e, st) {
      _rustdropWindowDiag('runMainApp: EXCEPTION: $e\n$st');
    }
  });
  _rustdropWindowDiag(
      'runMainApp: waitUntilReadyToShow call returned (registration, not completion)');
}

void runMobileApp() async {
  await initEnv(kAppTypeMain);
  checkUpdate();
  if (isAndroid) androidChannelInit();
  if (isAndroid) platformFFI.syncAndroidServiceAppDirConfigPath();
  draggablePositions.load();
  await Future.wait([gFFI.abModel.loadCache(), gFFI.groupModel.loadCache()]);
  gFFI.userModel.refreshCurrentUser();
  runApp(App());
  await initUniLinks();
}

void runMultiWindow(
  Map<String, dynamic> argument,
  String appType,
) async {
  await initEnv(appType);
  final title = getWindowName();
  // set prevent close to true, we handle close event manually
  WindowController.fromWindowId(kWindowId!).setPreventClose(true);
  if (isMacOS) {
    disableWindowMovable(kWindowId);
  }
  late Widget widget;
  switch (appType) {
    case kAppTypeDesktopRemote:
      draggablePositions.load();
      widget = DesktopRemoteScreen(
        params: argument,
      );
      break;
    case kAppTypeDesktopViewCamera:
      draggablePositions.load();
      widget = DesktopViewCameraScreen(
        params: argument,
      );
      break;
    case kAppTypeDesktopPortForward:
      widget = DesktopPortForwardScreen(
        params: argument,
      );
      break;
    case kAppTypeDesktopTerminal:
      widget = DesktopTerminalScreen(
        params: argument,
      );
      break;
    case kAppTypeDesktopManagedChat:
      widget = DesktopManagedChatScreen(
        params: argument,
      );
      break;
    default:
      // no such appType
      exit(0);
  }
  _runApp(
    title,
    widget,
    MyTheme.currentThemeMode(),
  );
  // we do not hide titlebar on win7 because of the frame overflow.
  if (kUseCompatibleUiMode) {
    WindowController.fromWindowId(kWindowId!).showTitleBar(true);
  }
  switch (appType) {
    case kAppTypeDesktopRemote:
      // If screen rect is set, the window will be moved to the target screen and then set fullscreen.
      if (argument['screen_rect'] == null) {
        // display can be used to control the offset of the window.
        await restoreWindowPosition(
          WindowType.RemoteDesktop,
          windowId: kWindowId!,
          peerId: argument['id'] as String?,
          display: argument['display'] as int?,
        );
      }
      break;
    case kAppTypeDesktopFileTransfer:
      await restoreWindowPosition(WindowType.FileTransfer,
          windowId: kWindowId!);
      break;
    case kAppTypeDesktopViewCamera:
      // If screen rect is set, the window will be moved to the target screen and then set fullscreen.
      if (argument['screen_rect'] == null) {
        // display can be used to control the offset of the window.
        await restoreWindowPosition(
          WindowType.ViewCamera,
          windowId: kWindowId!,
          peerId: argument['id'] as String?,
          // FIXME: fix display index.
          display: argument['display'] as int?,
        );
      }
      break;
    case kAppTypeDesktopPortForward:
      await restoreWindowPosition(WindowType.PortForward, windowId: kWindowId!);
      break;
    case kAppTypeDesktopTerminal:
      await restoreWindowPosition(WindowType.Terminal, windowId: kWindowId!);
      break;
    case kAppTypeDesktopManagedChat:
      if (!_isLegacyDefaultManagedChatFrame()) {
        await restoreWindowPosition(WindowType.ManagedChat,
            windowId: kWindowId!);
      }
      break;
    default:
      // no such appType
      exit(0);
  }
  // show window from hidden status
  WindowController.fromWindowId(kWindowId!).show();
}

// Chat windows used to open at a fixed 950x840, and every install that ever
// quit with one open saved exactly that as its "remembered" frame. Treat
// that frame as never customized, so those installs get the compact
// default; a size the user actually chose is still restored.
bool _isLegacyDefaultManagedChatFrame() {
  final saved = LastWindowPosition.loadFromString(
      bind.crateFlutterFfiGetLocalFlutterOption(
          k: windowFramePrefix + WindowType.ManagedChat.name));
  return saved != null && saved.width == 950 && saved.height == 840;
}

void runConnectionManagerScreen() async {
  await initEnv(kAppTypeConnectionManager);
  _runApp(
    '',
    const DesktopServerPage(),
    MyTheme.currentThemeMode(),
  );
  final hide = await bind.crateFlutterFfiCmGetConfig(name: "hide_cm") == 'true';
  gFFI.serverModel.hideCm = hide;
  if (hide) {
    await hideCmWindow(isStartup: true);
  } else {
    await showCmWindow(isStartup: true);
  }
  setResizable(false);
  // Start the uni links handler and redirect links to Native, not for Flutter.
  listenUniLinks(handleByFlutter: false);
}

bool _isCmReadyToShow = false;

Future<void> showCmWindow({bool isStartup = false}) async {
  if (isStartup) {
    WindowOptions windowOptions = getHiddenTitleBarWindowOptions(
        size: kConnectionManagerWindowSizeClosedChat, alwaysOnTop: true);
    await windowManager.waitUntilReadyToShow(windowOptions, null);
    bind.crateFlutterFfiMainHideDock();
    await Future.wait([
      windowManager.show(),
      windowManager.focus(),
      windowManager.setOpacity(1)
    ]);
    // ensure initial window size to be changed
    await windowManager.setSizeAlignment(
        kConnectionManagerWindowSizeClosedChat, Alignment.topRight);
    _isCmReadyToShow = true;
  } else if (_isCmReadyToShow) {
    if (await windowManager.getOpacity() != 1) {
      await windowManager.setOpacity(1);
      await windowManager.focus();
      await windowManager.minimize(); //needed
      // Deliberately does NOT reset position/size here (unlike the isStartup
      // branch above) - this runs every time a new connection re-shows an
      // already-initialized window, and snapping it back to a fixed corner
      // on every connection is exactly the "can't keep it moved" behavior
      // that made this window feel pinned rather than a normal floating,
      // freely-movable window. Whatever position the user last left it at
      // (dragged via buildTitleBar()'s startDragging(), or the OS's own
      // move/resize) is preserved across show/hide cycles.
      windowOnTop(null);
    }
  }
}

Future<void> hideCmWindow({bool isStartup = false}) async {
  if (isStartup) {
    WindowOptions windowOptions = getHiddenTitleBarWindowOptions(
        size: kConnectionManagerWindowSizeClosedChat);
    windowManager.setOpacity(0);
    await windowManager.waitUntilReadyToShow(windowOptions, null);
    bind.crateFlutterFfiMainHideDock();
    await windowManager.minimize();
    await windowManager.hide();
    _isCmReadyToShow = true;
  } else if (_isCmReadyToShow) {
    if (await windowManager.getOpacity() != 0) {
      await windowManager.setOpacity(0);
      bind.crateFlutterFfiMainHideDock();
      await windowManager.minimize();
      await windowManager.hide();
    }
  }
}

void _rustdropWindowDiag(String message) {
  try {
    final line = '${DateTime.now().toIso8601String()} pid=$pid $message\n';
    File('${Platform.environment['TEMP']}\\rustdrop_window_diag.txt')
        .writeAsStringSync(line, mode: FileMode.append, flush: true);
  } catch (_) {
    // Best-effort diagnostic only.
  }
}

// RustDrop's window has no hide-to-tray-on-close lifecycle like the
// managed-chat/CM windows do - register/poll/notify runs continuously in
// --server regardless of whether this window is even open (see
// rustdrop_service.rs's doc comment), so closing this window doesn't stop
// anything and can just exit the process normally, same as install_page.dart.
void runRustDropScreen() async {
  _rustdropWindowDiag('runRustDropScreen: start, calling initEnv');
  await initEnv(kAppTypeRustDrop);
  _rustdropWindowDiag('runRustDropScreen: initEnv done, calling _runApp');
  _runApp(
    'RustDrop',
    const DesktopRustDropScreen(),
    MyTheme.currentThemeMode(),
  );
  _rustdropWindowDiag(
      'runRustDropScreen: _runApp returned, building WindowOptions');
  WindowOptions windowOptions = getHiddenTitleBarWindowOptions(
    size: const Size(480, 640),
    center: true,
  );
  // Belt-and-suspenders against waitUntilReadyToShow's callback silently
  // never firing (no exception, no timeout of its own - the native window
  // just never gets created). Without this, a --rustdrop process that hits
  // that stays alive holding the single-instance mutex
  // (core_main.rs's try_lock_rustdrop_single_instance) forever, so every
  // later click just hits "Another RustDrop window is already running" and
  // does nothing - one silent failure permanently wedges the feature until
  // someone kills the process by hand. Real launches show the window in
  // well under a second per this file's own diagnostics, so 5s is a
  // generous margin.
  //
  // On timeout, don't just exit - relaunch fresh once. The one confirmed
  // occurrence of this (on a test client, receiving side of an active
  // session) looked like transient contention rather than something
  // permanently broken, so a second attempt a couple seconds later has a
  // real chance of landing cleanly instead of leaving the user to notice
  // the failure and retry by hand. WINDOW_LAUNCH_RETRY caps this at one retry -
  // the relaunched process sees it set and just gives up on its own
  // timeout, so a sustained failure still fails fast instead of looping.
  final isRetryAttempt = Platform.environment['WINDOW_LAUNCH_RETRY'] == '1';
  bool windowShown = false;
  Timer(const Duration(seconds: 5), () {
    if (windowShown) return;
    if (isRetryAttempt) {
      _rustdropWindowDiag(
          'runRustDropScreen: TIMEOUT on retry attempt, giving up, exiting to release single-instance lock');
      exit(0);
    }
    _rustdropWindowDiag(
        'runRustDropScreen: TIMEOUT waiting for window, relaunching fresh attempt in 2s');
    Future.delayed(const Duration(seconds: 2), () async {
      try {
        await Process.start(
          Platform.resolvedExecutable,
          ['--rustdrop'],
          environment: {'WINDOW_LAUNCH_RETRY': '1'},
          mode: ProcessStartMode.detached,
        );
        _rustdropWindowDiag('runRustDropScreen: retry relaunch spawned');
      } catch (e) {
        _rustdropWindowDiag('runRustDropScreen: retry relaunch FAILED: $e');
      }
      exit(0);
    });
  });

  _rustdropWindowDiag('runRustDropScreen: calling waitUntilReadyToShow');
  windowManager.waitUntilReadyToShow(windowOptions, () async {
    windowShown = true;
    _rustdropWindowDiag('waitUntilReadyToShow: callback fired');
    try {
      await windowManager.show();
      _rustdropWindowDiag('waitUntilReadyToShow: show() done');
      await windowManager.focus();
      _rustdropWindowDiag('waitUntilReadyToShow: focus() done');
      await windowManager.setOpacity(1);
      _rustdropWindowDiag('waitUntilReadyToShow: setOpacity(1) done');
      windowManager.setTitle('RustDrop');
      _rustdropWindowDiag('waitUntilReadyToShow: setTitle done, all complete');
    } catch (e, st) {
      _rustdropWindowDiag('waitUntilReadyToShow: EXCEPTION: $e\n$st');
    }
  });
  _rustdropWindowDiag(
      'runRustDropScreen: waitUntilReadyToShow call returned (registration, not completion)');
}

void _runApp(
  String title,
  Widget home,
  ThemeMode themeMode,
) {
  final botToastBuilder = BotToastInit();
  runApp(RefreshWrapper(
    builder: (context) => GetMaterialApp(
      navigatorKey: globalKey,
      debugShowCheckedModeBanner: false,
      title: title,
      theme: MyTheme.lightTheme,
      darkTheme: MyTheme.darkTheme,
      themeMode: themeMode,
      home: home,
      localizationsDelegates: const [
        GlobalMaterialLocalizations.delegate,
        GlobalWidgetsLocalizations.delegate,
        GlobalCupertinoLocalizations.delegate,
      ],
      supportedLocales: supportedLocales,
      navigatorObservers: [
        // FirebaseAnalyticsObserver(analytics: analytics),
        BotToastNavigatorObserver(),
      ],
      builder: (context, child) {
        child = _keepScaleBuilder(context, child);
        child = botToastBuilder(context, child);
        return child;
      },
    ),
  ));
}

void runInstallPage() async {
  await windowManager.ensureInitialized();
  await initEnv(kAppTypeMain);
  _runApp('', const InstallPage(), MyTheme.currentThemeMode());
  WindowOptions windowOptions =
      getHiddenTitleBarWindowOptions(size: Size(800, 600), center: true);
  windowManager.waitUntilReadyToShow(windowOptions, () async {
    windowManager.show();
    windowManager.focus();
    windowManager.setOpacity(1);
    windowManager.setAlignment(Alignment.center); // ensure
  });
}

WindowOptions getHiddenTitleBarWindowOptions(
    {bool isMainWindow = false,
    Size? size,
    bool center = false,
    bool? alwaysOnTop}) {
  var defaultTitleBarStyle = TitleBarStyle.hidden;
  // we do not hide titlebar on win7 because of the frame overflow.
  if (kUseCompatibleUiMode) {
    defaultTitleBarStyle = TitleBarStyle.normal;
  }
  return WindowOptions(
    size: size,
    center: center,
    backgroundColor: (isMacOS && isMainWindow) ? null : Colors.transparent,
    skipTaskbar: false,
    titleBarStyle: defaultTitleBarStyle,
    alwaysOnTop: alwaysOnTop,
  );
}

class App extends StatefulWidget {
  @override
  State<App> createState() => _AppState();
}

class _AppState extends State<App> with WidgetsBindingObserver {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.window.onPlatformBrightnessChanged = () {
      final userPreference = MyTheme.getThemeModePreference();
      if (userPreference != ThemeMode.system) return;
      WidgetsBinding.instance.handlePlatformBrightnessChanged();
      final systemIsDark =
          WidgetsBinding.instance.platformDispatcher.platformBrightness ==
              Brightness.dark;
      final ThemeMode to;
      if (systemIsDark) {
        to = ThemeMode.dark;
      } else {
        to = ThemeMode.light;
      }
      Get.changeThemeMode(to);
      // Synchronize the window theme of the system.
      updateSystemWindowTheme();
      if (desktopType == DesktopType.main) {
        bind.crateFlutterFfiMainChangeTheme(dark: to.toShortString());
      }
    };
    WidgetsBinding.instance.addObserver(this);
    WidgetsBinding.instance.addPostFrameCallback((_) => _updateOrientation());
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeMetrics() {
    _updateOrientation();
  }

  void _updateOrientation() {
    if (isDesktop) return;

    // Don't use `MediaQuery.of(context).orientation` in `didChangeMetrics()`,
    // my test (Flutter 3.19.6, Android 14) is always the reverse value.
    // https://github.com/flutter/flutter/issues/60899
    // stateGlobal.isPortrait.value =
    //     MediaQuery.of(context).orientation == Orientation.portrait;

    final orientation = View.of(context).physicalSize.aspectRatio > 1
        ? Orientation.landscape
        : Orientation.portrait;
    stateGlobal.isPortrait.value = orientation == Orientation.portrait;
  }

  @override
  Widget build(BuildContext context) {
    // final analytics = FirebaseAnalytics.instance;
    final botToastBuilder = BotToastInit();
    return RefreshWrapper(builder: (context) {
      return MultiProvider(
        providers: [
          // global configuration
          // use session related FFI when in remote control or file transfer page
          ChangeNotifierProvider.value(value: gFFI.ffiModel),
          ChangeNotifierProvider.value(value: gFFI.imageModel),
          ChangeNotifierProvider.value(value: gFFI.cursorModel),
          ChangeNotifierProvider.value(value: gFFI.canvasModel),
          ChangeNotifierProvider.value(value: gFFI.peerTabModel),
        ],
        child: GetMaterialApp(
          navigatorKey: globalKey,
          debugShowCheckedModeBanner: false,
          title: isWeb
              ? '${bind.crateFlutterFfiMainGetAppNameSync()} Web Client V2 (Preview)'
              : bind.crateFlutterFfiMainGetAppNameSync(),
          theme: MyTheme.lightTheme,
          darkTheme: MyTheme.darkTheme,
          themeMode: MyTheme.currentThemeMode(),
          home: isDesktop
              ? const DesktopTabPage()
              : isWeb
                  ? WebHomePage()
                  : HomePage(),
          localizationsDelegates: const [
            GlobalMaterialLocalizations.delegate,
            GlobalWidgetsLocalizations.delegate,
            GlobalCupertinoLocalizations.delegate,
          ],
          supportedLocales: supportedLocales,
          navigatorObservers: [
            // FirebaseAnalyticsObserver(analytics: analytics),
            BotToastNavigatorObserver(),
          ],
          builder: isAndroid
              ? (context, child) => AccessibilityListener(
                    child: MediaQuery(
                      data: MediaQuery.of(context).copyWith(
                        textScaler: TextScaler.linear(1.0),
                      ),
                      child: child ?? Container(),
                    ),
                  )
              : (context, child) {
                  child = _keepScaleBuilder(context, child);
                  child = botToastBuilder(context, child);
                  if ((isDesktop && desktopType == DesktopType.main) ||
                      isWebDesktop) {
                    child = keyListenerBuilder(context, child);
                  }
                  if (isLinux) {
                    return buildVirtualWindowFrame(context, child);
                  } else {
                    return workaroundWindowBorder(context, child);
                  }
                },
        ),
      );
    });
  }
}

Widget _keepScaleBuilder(BuildContext context, Widget? child) {
  return MediaQuery(
    data: MediaQuery.of(context).copyWith(
      textScaler: TextScaler.linear(1.0),
    ),
    child: child ?? Container(),
  );
}

void _registerEventHandler() {
  if (isDesktop && desktopType != DesktopType.main) {
    platformFFI.registerEventHandler('theme', 'theme', (evt) async {
      String? dark = evt['dark'];
      if (dark != null) {
        await MyTheme.changeDarkMode(MyTheme.themeModeFromString(dark));
      }
    });
    platformFFI.registerEventHandler('language', 'language', (_) async {
      reloadAllWindows();
    });
  }
  if (isDesktop) {
    platformFFI.registerEventHandler(
        'managed_chat_message', 'managed_chat_message', (evt) async {
      final conversationId = evt['conversation_id'];
      if (conversationId is String) {
        await handleManagedChatPush(conversationId);
      }
    });
    platformFFI.registerEventHandler(
        'managed_chat_delivered', 'managed_chat_delivered', (evt) async {
      final conversationId = evt['conversation_id'];
      if (conversationId is String) {
        await handleManagedChatDelivered(conversationId);
      }
    });
  }
  if (isAndroid) {
    platformFFI.registerEventHandler(
        'android_needs_deploy', 'android_needs_deploy', (_) async {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        showDeployPromptDialog();
      });
    });
  }
}

Widget keyListenerBuilder(BuildContext context, Widget? child) {
  return RawKeyboardListener(
    // `skipTraversal: isWeb` is to fix "Bad state: RenderBox was not laid out: minified:aeL#c19e4"
    focusNode: FocusNode(skipTraversal: isWeb),
    child: child ?? Container(),
    onKey: (RawKeyEvent event) {
      if (event.logicalKey == LogicalKeyboardKey.shiftLeft) {
        if (event is RawKeyDownEvent) {
          gFFI.peerTabModel.setShiftDown(true);
        } else if (event is RawKeyUpEvent) {
          gFFI.peerTabModel.setShiftDown(false);
        }
      }
    },
  );
}
