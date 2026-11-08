// Root widget for a managed-chat window: a genuinely independent native
// window (via desktop_multi_window), not an in-app dialog - it can be
// dragged, minimized, and moved outside the main RustDesk window's bounds.
// See utils/multi_window_manager.dart's openManagedChatWindow for how this
// window gets created, and common/widgets/managed_chat_dialog.dart for the
// two entry points (manual "Message" action, incoming push) that decide
// when to call it.

import 'package:desktop_multi_window/desktop_multi_window.dart';
import 'package:flutter/material.dart';
import 'package:get/get.dart';
import 'package:window_manager/window_manager.dart';

import '../../common.dart';
import '../../consts.dart';
import '../../main.dart';
import '../../models/managed_chat_model.dart';
import '../../utils/multi_window_manager.dart';

String _retentionLabel(int days) {
  if (days == kManagedChatRetentionForever) return translate('Forever');
  if (days == kManagedChatRetentionOff) return translate('No Retention');
  return '$days ${translate('days')}';
}

class DesktopManagedChatScreen extends StatefulWidget {
  final Map<String, dynamic> params;

  const DesktopManagedChatScreen({super.key, required this.params});

  @override
  State<DesktopManagedChatScreen> createState() =>
      _DesktopManagedChatScreenState();
}

class _DesktopManagedChatScreenState extends State<DesktopManagedChatScreen>
    with MultiWindowListener, WindowListener {
  late final String conversationId = widget.params['conversation_id'] as String;
  final TextEditingController _textController = TextEditingController();
  final FocusNode _composeFocusNode = FocusNode();
  String? _selfDeviceId;
  // Enter sends only after the user has engaged with this window: an
  // incoming message can bring it up while they type elsewhere, and those
  // keystrokes must not reach the other device. Opening it themselves, or a
  // click in the compose box once the window has been up and active for a
  // moment, engages it - not the click that brings it forward.
  late bool _enterSends = widget.params['activate'] == true;
  bool _enterRefused = false;
  bool _windowFocused = false;
  // When this window last came up or became active.
  DateTime _shownAt = DateTime.now();
  bool _sending = false;
  late bool _muted = gFFI.managedChatModel.isMuted(conversationId);

  @override
  void initState() {
    super.initState();
    // Both registrations are required: on Windows, the native close
    // signal for a desktop_multi_window sub-window is actually delivered
    // through DesktopMultiWindow's own listener channel, not
    // window_manager's - window_manager's hook only ever seems to fire
    // for the main window. window_manager's addListener is still needed
    // for onWindowMoved/other events used elsewhere in this codebase.
    // See tabbar_widget.dart, which registers both for the same reason.
    DesktopMultiWindow.addListener(this);
    windowManager.addListener(this);
    // This window has its own, freshly-constructed ManagedChatModel (each
    // window/isolate gets its own FFI instance) - it always needs its own
    // initial load, whether it was just created for a brand-new push or
    // the main window is re-showing an already-open window.
    _load();
    rustDeskWinManager.setMethodHandler((call, fromWindowId) async {
      if (call.arguments != conversationId) return null;
      if (call.method == kWindowEventManagedChatMessage) {
        await _load();
      } else if (call.method == kWindowEventManagedChatSurface) {
        // The main window brings this window up (openManagedChatWindow).
        if (!_windowFocused) _disengage();
        _shownAt = DateTime.now();
        await _load();
      } else if (call.method == kWindowEventManagedChatActivate) {
        _engage();
        _composeFocusNode.requestFocus();
      }
      return null;
    });
  }

  void _engage() {
    if (_enterSends && !_enterRefused) return;
    setState(() {
      _enterSends = true;
      _enterRefused = false;
    });
  }

  // A pointer-down while the window is not active yet, or within a second of
  // it coming up or becoming active, is most likely the click that brought it
  // forward while the user was busy elsewhere, not a decision to chat.
  void _onComposePointerDown(PointerDownEvent _) {
    if (!_windowFocused ||
        DateTime.now().difference(_shownAt) < const Duration(seconds: 1)) {
      return;
    }
    _engage();
  }

  void _disengage() {
    _composeFocusNode.unfocus();
    setState(() {
      _enterSends = false;
      _enterRefused = false;
    });
  }

  void _submit() {
    if (_enterSends) {
      _send();
    } else {
      setState(() => _enterRefused = true);
    }
  }

  Future<void> _toggleMute() async {
    final muted = !_muted;
    await gFFI.managedChatModel.setMuted(conversationId, muted);
    if (mounted) setState(() => _muted = muted);
  }

  @override
  void onWindowFocus() {
    _windowFocused = true;
    _shownAt = DateTime.now();
    _markReadIfViewed();
  }

  @override
  void onWindowBlur() {
    _windowFocused = false;
  }

  Future<void> _load() async {
    final model = gFFI.managedChatModel;
    _selfDeviceId = await model.selfDeviceId();
    await model.loadLocalMessages(conversationId);
    await model.syncConversations();
    await _markReadIfViewed();
    if (mounted) setState(() {});
  }

  // Only the user looking at this window reads its messages. A refresh while
  // it is hidden (a closed chat window is only hidden, so every conversation
  // muted this session has one) or in the background leaves them unread.
  Future<void> _markReadIfViewed() async {
    final model = gFFI.managedChatModel;
    if (!_windowFocused ||
        !model.messagesFor(conversationId).any((m) => !m.isRead)) {
      return;
    }
    if (await WindowController.fromWindowId(kWindowId!).isHidden()) return;
    await model.markRead(conversationId);
  }

  @override
  void onWindowClose() async {
    // "No retention" messages live only as long as this window is open -
    // purge them now, before hiding.
    await gFFI.managedChatModel.purgeConversationIfNoRetention(conversationId);
    // Matches every other sub window in this codebase (see
    // tabbar_widget.dart's notMainWindowClose): hide, don't destroy. The
    // native window keeps existing so a later message for this same
    // conversation can just show/focus it again instead of creating a
    // second window - see RustDeskMultiWindowManager.openManagedChatWindow.
    await WindowController.fromWindowId(kWindowId!).hide();
    await rustDeskWinManager
        .call(WindowType.Main, kWindowEventHide, {"id": kWindowId!});
  }

  @override
  void dispose() {
    DesktopMultiWindow.removeListener(this);
    windowManager.removeListener(this);
    _textController.dispose();
    _composeFocusNode.dispose();
    super.dispose();
  }

  // The text stays in the field until RDS has taken it: a refused send (rate
  // limit, offline) would otherwise lose what the user typed.
  Future<void> _send() async {
    final text = _textController.text.trim();
    if (text.isEmpty || _sending) return;
    _sending = true;
    // Sending (whether via the send button or the Enter key) otherwise
    // moves focus away from the field - explicitly request it back so
    // the user can keep typing/sending without re-clicking each time.
    _composeFocusNode.requestFocus();
    final model = gFFI.managedChatModel;
    var sent = false;
    try {
      sent = await model.sendMessage(conversationId, text);
    } catch (e) {
      debugPrint('managed chat: sending failed: $e');
    } finally {
      _sending = false;
    }
    if (!mounted) return;
    if (sent) {
      if (_textController.text.trim() == text) _textController.clear();
      return;
    }
    if (_textController.text.trim().isEmpty) {
      _textController.value = TextEditingValue(
          text: text, selection: TextSelection.collapsed(offset: text.length));
    }
    showToast(translate(model.lastSendRateLimited
        ? 'Sending too fast - wait a minute'
        : 'Message not sent'));
  }

  @override
  Widget build(BuildContext context) {
    final model = gFFI.managedChatModel;
    return _buildScaffold(model);
  }

  Widget _buildScaffold(ManagedChatModel model) {
    return Scaffold(
      body: Column(
        children: [
          GestureDetector(
            behavior: HitTestBehavior.translucent,
            onPanStart: (_) =>
                WindowController.fromWindowId(kWindowId!).startDragging(),
            child: Padding(
              padding: const EdgeInsets.fromLTRB(16, 12, 8, 12),
              child: Obx(() {
                final conversation = model.conversations
                    .firstWhereOrNull((c) => c.id == conversationId);
                return Row(
                  children: [
                    Container(
                      margin: const EdgeInsets.only(right: 8),
                      child: loadIcon(20),
                    ),
                    Expanded(
                      child: Text(
                        conversation?.otherPartyName(_selfDeviceId) ??
                            translate('Chat'),
                        style: const TextStyle(
                            fontWeight: FontWeight.bold, fontSize: 16),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                    IconButton(
                      tooltip: translate(_muted ? 'Unmute' : 'Mute'),
                      icon: Icon(
                          _muted
                              ? Icons.notifications_off_outlined
                              : Icons.notifications_none,
                          size: 20),
                      onPressed: _toggleMute,
                    ),
                    _RetentionButton(conversationId: conversationId),
                    IconButton(
                      icon: const Icon(Icons.close),
                      // Sub-windows must close via their own
                      // WindowController, not the bare windowManager
                      // singleton (which only ever targets the main
                      // window) - see tabbar_widget.dart's ActionIcon
                      // close handler for the same pattern. This is what
                      // gets intercepted by setPreventClose(true) and
                      // routed to onWindowClose() below.
                      onPressed: () =>
                          WindowController.fromWindowId(kWindowId!).close(),
                    ),
                  ],
                );
              }),
            ),
          ),
          const Divider(height: 1),
          Expanded(
            child: Obx(() {
              final messages = model.messagesFor(conversationId);
              if (messages.isEmpty) {
                return Center(
                    child: Text(translate('No messages yet'),
                        style: TextStyle(color: Colors.grey[600])));
              }
              return ListView.builder(
                reverse: true,
                itemCount: messages.length,
                itemBuilder: (context, index) {
                  final message = messages[messages.length - 1 - index];
                  final isSelf = _selfDeviceId != null &&
                      message.senderDeviceId == _selfDeviceId;
                  return _MessageBubble(message: message, isSelf: isSelf);
                },
              );
            }),
          ),
          const Divider(height: 1),
          Padding(
            padding: const EdgeInsets.all(8),
            child: Row(
              children: [
                Expanded(
                  child: Listener(
                    onPointerDown: _onComposePointerDown,
                    child: TextField(
                      controller: _textController,
                      focusNode: _composeFocusNode,
                      // Only a window the user opened takes the keyboard.
                      autofocus: _enterSends,
                      decoration: InputDecoration(
                        hintText: translate('Type a message'),
                        helperText: _enterRefused
                            ? translate(
                                'Click in the message box to send with Enter')
                            : null,
                      ),
                      onSubmitted: (_) => _submit(),
                    ),
                  ),
                ),
                IconButton(icon: const Icon(Icons.send), onPressed: _send),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _RetentionButton extends StatelessWidget {
  final String conversationId;

  const _RetentionButton({required this.conversationId});

  @override
  Widget build(BuildContext context) {
    final model = gFFI.managedChatModel;
    return Obx(() {
      final conversation =
          model.conversations.firstWhereOrNull((c) => c.id == conversationId);
      final current =
          conversation?.retentionDays ?? kManagedChatRetentionForever;
      return PopupMenuButton<int>(
        tooltip: translate('Keep history'),
        onSelected: (days) => model.setRetention(conversationId, days),
        itemBuilder: (context) => kManagedChatRetentionPresets
            .map((days) => PopupMenuItem<int>(
                  value: days,
                  child: Text(_retentionLabel(days)),
                ))
            .toList(),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.history, size: 18),
            const SizedBox(width: 4),
            Text(_retentionLabel(current),
                style: const TextStyle(fontSize: 13)),
          ],
        ),
      );
    });
  }
}

class _MessageBubble extends StatelessWidget {
  final ManagedChatMessage message;
  final bool isSelf;

  const _MessageBubble({required this.message, required this.isSelf});

  // Only a self-sent message's delivered flag is meaningful - a received
  // one is always trivially "delivered" (it's already here). Dark red
  // rather than a lighter/desaturated tint specifically because it needs
  // to read clearly as "pending" against both a light and a dark theme
  // background, not just against one of them.
  bool get _notYetDelivered => isSelf && !message.delivered;

  Widget _body() {
    switch (message.openState) {
      case kManagedChatOpenStateOpened:
        return Text(message.body);
      case kManagedChatOpenStatePending:
        return Text(translate('Waiting to decrypt this message'),
            style: TextStyle(
                fontStyle: FontStyle.italic, color: Colors.grey[600]));
      default:
        return Text(translate('This message could not be decrypted'),
            style: TextStyle(
                fontStyle: FontStyle.italic, color: Colors.grey[600]));
    }
  }

  @override
  Widget build(BuildContext context) {
    final time = DateTime.tryParse(message.sentAt)?.toLocal();
    return Align(
      alignment: isSelf ? Alignment.centerRight : Alignment.centerLeft,
      child: Container(
        constraints: const BoxConstraints(maxWidth: 280),
        margin: const EdgeInsets.symmetric(vertical: 3),
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
        decoration: BoxDecoration(
          color: _notYetDelivered
              ? Colors.red.shade900.withValues(alpha: 0.35)
              : isSelf
                  ? Colors.blue.withValues(alpha: 0.18)
                  : Colors.grey.withValues(alpha: 0.18),
          borderRadius: BorderRadius.circular(10),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: [
            _body(),
            Padding(
              padding: const EdgeInsets.only(top: 2),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  if (time != null)
                    Text(
                      TimeOfDay.fromDateTime(time).format(context),
                      style: TextStyle(fontSize: 10, color: Colors.grey[600]),
                    ),
                  if (_notYetDelivered)
                    Padding(
                      padding: const EdgeInsets.only(left: 6),
                      child: Text(
                        translate('Pending delivery'),
                        style: TextStyle(
                            fontSize: 10,
                            fontWeight: FontWeight.bold,
                            color: Colors.red.shade900),
                      ),
                    ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
