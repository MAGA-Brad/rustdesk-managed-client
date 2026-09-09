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
/// isn't already open, or pushes a refresh to it if one is.
Future<void> handleManagedChatPush(String conversationId) async {
  // Refreshes the *main* window's own ManagedChatModel - each window has
  // its own separate instance, and this is what the Directory tab's
  // unread-mail badge (peer_card.dart) reads from. Without this, a badge
  // could only ever appear after some unrelated action happened to
  // refresh main's model.
  unawaited(gFFI.managedChatModel.loadLocalConversations());
  await rustDeskWinManager.openManagedChatWindow(conversationId);
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
