// Root widget for a managed-chat window: a genuinely independent native
// window (via desktop_multi_window), not an in-app dialog - it can be
// dragged, minimized, and moved outside the main RustDesk window's bounds.
// See utils/multi_window_manager.dart's openManagedChatWindow for how this
// window gets created, and common/widgets/managed_chat_dialog.dart for the
// two entry points (manual "Message" action, incoming push) that decide
// when to call it.

import 'package:desktop_multi_window/desktop_multi_window.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
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

  const DesktopManagedChatScreen({Key? key, required this.params})
      : super(key: key);

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
      if (call.method == kWindowEventManagedChatMessage &&
          call.arguments == conversationId) {
        await _load();
      }
      return null;
    });
  }

  Future<void> _load() async {
    final model = gFFI.managedChatModel;
    _selfDeviceId = await model.selfDeviceId();
    await model.loadLocalMessages(conversationId);
    await model.syncConversations();
    await model.markRead(conversationId);
    if (mounted) setState(() {});
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

  void _send() {
    final text = _textController.text.trim();
    if (text.isEmpty) return;
    _textController.clear();
    gFFI.managedChatModel.sendMessage(conversationId, text);
    // Sending (whether via the send button or the Enter key) otherwise
    // moves focus away from the field - explicitly request it back so
    // the user can keep typing/sending without re-clicking each time.
    _composeFocusNode.requestFocus();
  }

  @override
  Widget build(BuildContext context) {
    final model = gFFI.managedChatModel;
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
                  child: TextField(
                    controller: _textController,
                    focusNode: _composeFocusNode,
                    autofocus: true,
                    decoration:
                        InputDecoration(hintText: translate('Type a message')),
                    onSubmitted: (_) => _send(),
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
      final current = conversation?.retentionDays ?? kManagedChatRetentionForever;
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
              ? Colors.red.shade900.withOpacity(0.35)
              : isSelf
                  ? Colors.blue.withOpacity(0.18)
                  : Colors.grey.withOpacity(0.18),
          borderRadius: BorderRadius.circular(10),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(message.body),
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
