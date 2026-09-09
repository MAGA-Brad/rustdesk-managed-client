// Out-of-session chat between managed devices. Named ManagedChatModel
// (not ChatModel) to avoid colliding with the existing in-session text
// chat feature in chat_model.dart - the two are unrelated: this one has
// no active remote-control session, works from the Directory tab's
// ellipsis menu, and its history/retention live entirely on this device
// (see managed_chat_store.rs on the Rust side).

import 'dart:convert';

import 'package:get/get.dart';

import 'model.dart';
import 'platform_model.dart';

class ManagedChatParticipant {
  final String deviceId;
  final String? friendlyName;
  final String hostname;

  ManagedChatParticipant({
    required this.deviceId,
    required this.friendlyName,
    required this.hostname,
  });

  factory ManagedChatParticipant.fromJson(Map<String, dynamic> json) {
    return ManagedChatParticipant(
      deviceId: json['device_id'] as String? ?? '',
      friendlyName: json['friendly_name'] as String?,
      hostname: json['hostname'] as String? ?? '',
    );
  }

  String get displayName =>
      (friendlyName != null && friendlyName!.trim().isNotEmpty)
          ? friendlyName!
          : hostname;
}

class ManagedChatMessage {
  final String id;
  final String senderDeviceId;
  final String body;
  final String sentAt;
  final bool isRead;
  // Only meaningful for a message this device sent: was the recipient
  // connected to receive it live? Always true for a received message
  // (trivially - it's already here). See managed_chat_store.rs's
  // `delivered` column and _MessageBubble's coloring of it.
  final bool delivered;

  ManagedChatMessage({
    required this.id,
    required this.senderDeviceId,
    required this.body,
    required this.sentAt,
    required this.isRead,
    this.delivered = true,
  });

  factory ManagedChatMessage.fromJson(Map<String, dynamic> json) {
    return ManagedChatMessage(
      id: json['id'] as String? ?? '',
      senderDeviceId: json['sender_device_id'] as String? ?? '',
      body: json['body'] as String? ?? '',
      sentAt: json['sent_at'] as String? ?? '',
      isRead: json['is_read'] as bool? ?? true,
      delivered: json['delivered'] as bool? ?? true,
    );
  }
}

class ManagedChatConversation {
  final String id;
  final String conversationType;
  final String? name;
  final String createdAt;
  final List<ManagedChatParticipant> participants;
  final int retentionDays;
  final ManagedChatMessage? lastMessage;
  final int unreadCount;

  ManagedChatConversation({
    required this.id,
    required this.conversationType,
    required this.name,
    required this.createdAt,
    required this.participants,
    required this.retentionDays,
    required this.lastMessage,
    required this.unreadCount,
  });

  factory ManagedChatConversation.fromJson(Map<String, dynamic> json) {
    return ManagedChatConversation(
      id: json['id'] as String? ?? '',
      conversationType: json['conversation_type'] as String? ?? 'direct',
      name: json['name'] as String?,
      createdAt: json['created_at'] as String? ?? '',
      participants: ((json['participants'] as List<dynamic>?) ?? [])
          .map((e) =>
              ManagedChatParticipant.fromJson(e as Map<String, dynamic>))
          .toList(),
      // Server-provided conversations (start/sync) have no opinion on
      // retention - default to forever until the local store says
      // otherwise via ManagedChatModel._applyConversations.
      retentionDays: (json['retention_days'] as num?)?.toInt() ??
          kManagedChatRetentionForever,
      lastMessage: json['last_message'] == null
          ? null
          : ManagedChatMessage.fromJson(
              json['last_message'] as Map<String, dynamic>),
      unreadCount: (json['unread_count'] as num?)?.toInt() ?? 0,
    );
  }

  /// The display name for a direct (1:1) conversation's *other* party.
  /// Falls back to the conversation's own name (relevant once groups
  /// exist), or null if neither is known - callers (which have access to
  /// translate()) supply their own final fallback text in that case.
  String? otherPartyName(String? selfDeviceId) {
    final other = selfDeviceId == null
        ? null
        : participants.firstWhereOrNull((p) => p.deviceId != selfDeviceId);
    if (other != null && other.displayName.isNotEmpty) return other.displayName;
    if (name != null && name!.isNotEmpty) return name;
    return null;
  }
}

// Retention, in days, offered per-conversation. Enforced entirely on this
// device (managed_chat_store.rs) - the server has no say in it.
const int kManagedChatRetentionForever = -1;
const int kManagedChatRetentionOff = 0;
const List<int> kManagedChatRetentionPresets = [
  kManagedChatRetentionForever,
  90,
  30,
  7,
  kManagedChatRetentionOff,
];

class ManagedChatModel {
  final WeakReference<FFI> parent;

  final RxList<ManagedChatConversation> conversations =
      RxList<ManagedChatConversation>.empty(growable: true);
  final RxMap<String, RxList<ManagedChatMessage>> _messagesByConversation =
      RxMap<String, RxList<ManagedChatMessage>>();

  String? _selfDeviceId;

  ManagedChatModel(this.parent);

  RxList<ManagedChatMessage> messagesFor(String conversationId) {
    return _messagesByConversation.putIfAbsent(
        conversationId, () => RxList<ManagedChatMessage>.empty(growable: true));
  }

  /// Finds the 1:1 conversation with a peer by hostname - used by the
  /// Directory tab's unread-mail badge, which only has the peer's
  /// RustDesk id/hostname to go on, not a conversation id.
  ManagedChatConversation? conversationForPeerHostname(String hostname) {
    return conversations
        .firstWhereOrNull((c) => c.participants.any((p) => p.hostname == hostname));
  }

  Future<String?> selfDeviceId() async {
    if (_selfDeviceId != null) return _selfDeviceId;
    try {
      final raw = await bind.managedChatSelfDeviceId();
      final decoded = jsonDecode(raw);
      if (decoded is Map && decoded['device_id'] != null) {
        _selfDeviceId = decoded['device_id'] as String;
      }
    } catch (_) {}
    return _selfDeviceId;
  }

  void _applyConversations(List<dynamic> rawList) {
    conversations.assignAll(rawList
        .whereType<Map<String, dynamic>>()
        .map((e) => ManagedChatConversation.fromJson(e)));
  }

  void _applyMessages(String conversationId, List<dynamic> rawList) {
    messagesFor(conversationId).assignAll(rawList
        .whereType<Map<String, dynamic>>()
        .map((e) => ManagedChatMessage.fromJson(e)));
  }

  /// Instant, offline-friendly population from this device's own store.
  Future<void> loadLocalConversations() async {
    final decoded = jsonDecode(await bind.managedChatGetLocalConversations());
    if (decoded is List) _applyConversations(decoded);
  }

  /// Pulls the current conversation list from the server (picking up any
  /// conversation someone else started with this device while it was
  /// offline) and merges it into the local store, then returns the
  /// merged local view. Falls back to the local-only view if offline.
  Future<void> syncConversations() async {
    try {
      await bind.managedChatSyncConversations();
    } catch (_) {}
    await loadLocalConversations();
  }

  Future<void> loadLocalMessages(String conversationId) async {
    final decoded = jsonDecode(
        await bind.managedChatGetLocalMessages(conversationId: conversationId));
    if (decoded is List) _applyMessages(conversationId, decoded);
  }

  /// Drains whatever the server mailbox is still holding for this
  /// conversation and merges it into local history.
  Future<void> syncMessages(String conversationId) async {
    try {
      await bind.managedChatSyncMessages(conversationId: conversationId);
    } catch (_) {}
    await loadLocalMessages(conversationId);
  }

  Future<ManagedChatConversation?> startConversation(
      String peerRustdeskId) async {
    final raw = await bind.managedChatStartConversation(
        peerRustdeskId: peerRustdeskId);
    final decoded = jsonDecode(raw);
    if (decoded is Map<String, dynamic> && decoded['error'] == null) {
      final conversation = ManagedChatConversation.fromJson(decoded);
      final index = conversations.indexWhere((c) => c.id == conversation.id);
      if (index >= 0) {
        conversations[index] = conversation;
      } else {
        conversations.add(conversation);
      }
      return conversation;
    }
    return null;
  }

  Future<bool> sendMessage(String conversationId, String body) async {
    final raw = await bind.managedChatSendMessage(
        conversationId: conversationId, body: body);
    final decoded = jsonDecode(raw);
    if (decoded is Map<String, dynamic> && decoded['error'] == null) {
      // Persisted on the Rust side (managed_chat_store.rs's `delivered`
      // column) from this same send response's delivered_to field before
      // this reload - see _MessageBubble for how it's rendered.
      await loadLocalMessages(conversationId);
      await loadLocalConversations();
      return true;
    }
    return false;
  }

  Future<void> markRead(String conversationId) async {
    await bind.managedChatMarkRead(conversationId: conversationId);
    await loadLocalMessages(conversationId);
    await loadLocalConversations();
  }

  /// "No retention" means visible only while the chat window is open -
  /// call this from the window's own close handler, not on every
  /// send/read (that raced a just-sent message's own read flag and made
  /// it disappear immediately). No-op for any other retention setting.
  Future<void> purgeConversationIfNoRetention(String conversationId) async {
    final retention = await getRetention(conversationId);
    if (retention != kManagedChatRetentionOff) return;
    await bind.managedChatPurgeConversation(conversationId: conversationId);
    await loadLocalMessages(conversationId);
  }

  Future<int> getRetention(String conversationId) async {
    final decoded = jsonDecode(
        await bind.managedChatGetRetention(conversationId: conversationId));
    return (decoded['retention_days'] as num?)?.toInt() ??
        kManagedChatRetentionForever;
  }

  Future<void> setRetention(String conversationId, int retentionDays) async {
    await bind.managedChatSetRetention(
        conversationId: conversationId, retentionDays: retentionDays);
    await loadLocalConversations();
    await loadLocalMessages(conversationId);
  }
}
