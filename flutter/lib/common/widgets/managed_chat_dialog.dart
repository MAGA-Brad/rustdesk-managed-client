// Entry points for out-of-session managed chat, opened from the
// Directory tab's ellipsis "Message" action or from an incoming push.
// Kept separate from RustDesk's own in-session chat overlay
// (chat_model.dart / widgets/chat_page.dart) - this one has no active
// remote session, and its history/retention are entirely local (see
// managed_chat_store.rs). The actual UI lives in its own independent
// window (desktop/screen/desktop_managed_chat_screen.dart via
// utils/multi_window_manager.dart's openManagedChatWindow), not an
// in-app dialog, so it can be dragged/floated outside the main window.

import 'dart:async';

import '../../common.dart';
import '../../utils/multi_window_manager.dart';

/// What the service starts this app with to show an incoming message
/// (managed_chat.rs's GUI_HIDDEN_LAUNCH_ARG): the main window stays hidden,
/// and a muted conversation shows nothing at all.
const String kManagedChatHiddenLaunchArg = 'managed-chat-hidden';

// A chat window created while the main window is still starting can leave
// the main window never shown, so pushes wait until it has started, shown or
// kept hidden.
final Completer<void> _mainWindowStarted = Completer<void>();

/// Called by main.dart once the main window has finished starting.
void onManagedChatMainWindowStarted({required bool startedForChat}) {
  if (_mainWindowStarted.isCompleted) return;
  _mainWindowStarted.complete();
  // The message the service started this app for can reach it before it
  // listens, and is then dropped: every conversation with unread messages is
  // handled as if it had just been pushed instead.
  if (startedForChat) unawaited(_handleUnreadConversations());
}

Future<void> _handleUnreadConversations() async {
  final model = gFFI.managedChatModel;
  await model.loadLocalConversations();
  for (final conversation in model.conversations.toList()) {
    if (conversation.unreadCount > 0) {
      await handleManagedChatPush(conversation.id);
    }
  }
}

/// Starts (or resumes) a 1:1 chat with [peerRustdeskId] - the RustDesk
/// numeric id already shown in the Directory tab - and opens its window.
Future<void> openManagedChatWithPeer(String peerRustdeskId) async {
  final model = gFFI.managedChatModel;
  final conversation = await model.startConversation(peerRustdeskId);
  if (conversation == null) {
    showToast(translate('Failed to start conversation'));
    return;
  }
  await rustDeskWinManager.openManagedChatWindow(conversation.id);
}

/// Called from the `managed_chat_message` global event handler when a
/// push arrives - the Rust side has already stored the message locally
/// by the time this fires. Opens a window for the conversation if one
/// isn't already open, or pushes a refresh to it if one is - without
/// taking the keyboard (see openManagedChatWindow's `activate`).
Future<void> handleManagedChatPush(String conversationId) async {
  await _mainWindowStarted.future;
  // Refreshes the *main* window's own ManagedChatModel - each window has
  // its own separate instance, and this is what the Directory tab's
  // unread-mail badge (peer_card.dart) reads from. Without this, a badge
  // could only ever appear after some unrelated action happened to
  // refresh main's model.
  unawaited(gFFI.managedChatModel.loadLocalConversations());
  // Muted: stored and counted as unread, but nothing comes up.
  if (gFFI.managedChatModel.isMuted(conversationId)) {
    await rustDeskWinManager.refreshManagedChatWindowIfOpen(conversationId);
    return;
  }
  await rustDeskWinManager.openManagedChatWindow(conversationId,
      activate: false);
}

/// Called from the `managed_chat_delivered` global event handler: a
/// message this device sent earlier has now actually reached the
/// recipient. Unlike a new message, this should never pop a window open
/// on its own - it only refreshes one the user already has open, so its
/// "pending delivery" marker clears live instead of staying stuck until
/// the window is reopened.
Future<void> handleManagedChatDelivered(String conversationId) async {
  await rustDeskWinManager.refreshManagedChatWindowIfOpen(conversationId);
}
