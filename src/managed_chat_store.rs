// Local, per-device persistence for managed chat. The server is a
// delivery mailbox only (see hbbs_http::managed_chat's module comment) -
// once a message is purged there, this is the only remaining copy. Each
// conversation has its own retention policy, set and enforced entirely
// on this machine; deleting local history here never touches the server
// or any other participant's copy.

use crate::hbbs_http::managed_chat::{ChatConversation, ChatMessage, ChatParticipant};
use hbb_common::{config, lazy_static, ResultType};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;

// Retention, in days. FOREVER never prunes by age; OFF ("no retention")
// keeps messages only for as long as the conversation's chat window
// stays open - see purge_conversation(), called from the window's close
// handler, not from insert/read (that raced and deleted messages before
// the UI ever showed them).
pub const RETENTION_FOREVER: i64 = -1;
pub const RETENTION_OFF: i64 = 0;
const DEFAULT_RETENTION_DAYS: i64 = RETENTION_FOREVER;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalMessage {
    pub id: String,
    pub sender_device_id: String,
    pub body: String,
    pub sent_at: String,
    pub is_read: bool,
    pub delivered: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalConversation {
    pub id: String,
    pub conversation_type: String,
    pub name: Option<String>,
    pub created_at: String,
    pub participants: Vec<ChatParticipant>,
    pub retention_days: i64,
    pub last_message: Option<LocalMessage>,
    pub unread_count: i64,
}

lazy_static::lazy_static! {
    static ref DB: Mutex<Connection> = Mutex::new(open_db().expect("failed to open managed chat store"));
}

// Must be a machine-wide path, not a per-user-profile one: this database
// is written from both the GUI process (the interactive user's own
// token) and, on Windows, --server (a duplicated SYSTEM token - see
// ipc::Data::ManagedChatIpcRequest's doc comment). Config::path(...)
// resolves relative to whichever profile the *current process's* token
// belongs to, so on Windows the two processes would silently read and
// write two entirely different files if this used that - exactly what
// happened before this fix (server.rs's --server-hosted websocket task
// could insert a message, but the GUI's own local read never found it).
// Deliberately NOT placed inside the same C:\ProgramData\RustDeskManaged
// directory the enrollment credential lives in either: that directory's
// own DACL is hardened to SYSTEM+Administrators only (see
// create_machine_secret_directory), which the GUI's filtered,
// non-elevated token can't reach even as a local admin - the very
// problem this whole IPC-relay architecture exists to work around.
#[cfg(windows)]
fn managed_chat_db_path() -> ResultType<PathBuf> {
    Ok(crate::platform::get_program_data_dir()?
        .join("RustDeskManagedChat")
        .join("managed_chat.sqlite3"))
}

#[cfg(not(windows))]
fn managed_chat_db_path() -> ResultType<PathBuf> {
    Ok(config::Config::path("managed_chat.sqlite3"))
}

fn open_db() -> ResultType<Connection> {
    let path = managed_chat_db_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
        // Only --server (a duplicated SYSTEM token) can grant this ACE:
        // modifying a directory's DACL requires WRITE_DAC, which the GUI's
        // filtered token doesn't have on an object it doesn't already own
        // (its Administrators group membership is present but "deny only"
        // under UAC, so it can't take ownership or reassert the DACL
        // either) - attempting it from the GUI just fails with the same
        // ACCESS_DENIED this whole IPC-relay architecture exists to work
        // around. --server, running as SYSTEM, always has this right,
        // whether it created the directory itself or is repairing one a
        // previous build left owned by the interactive user. This is a
        // merge-mode ACE add (see set_path_permission), so it never
        // narrows access already granted, and is safe to repeat on every
        // open.
        #[cfg(windows)]
        if crate::platform::is_root() {
            if let Err(error) = crate::platform::set_path_permission(
                parent,
                windows::Win32::Storage::FileSystem::FILE_GENERIC_READ.0
                    | windows::Win32::Storage::FileSystem::FILE_GENERIC_WRITE.0,
            ) {
                hbb_common::log::warn!(
                    "managed chat: failed to set shared permission on {:?}: {}",
                    parent,
                    error
                );
            }
        }
    }
    let conn = Connection::open(path)?;
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS conversations (
            id TEXT PRIMARY KEY,
            conversation_type TEXT NOT NULL,
            name TEXT,
            created_at TEXT NOT NULL,
            participants_json TEXT NOT NULL,
            retention_days INTEGER NOT NULL DEFAULT -1
        );
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            conversation_id TEXT NOT NULL,
            sender_device_id TEXT NOT NULL,
            body TEXT NOT NULL,
            sent_at TEXT NOT NULL,
            is_read INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS messages_conversation_idx ON messages(conversation_id, sent_at);
        "#,
    )?;
    // `delivered` was added after messages already shipped without it -
    // ALTER TABLE ADD COLUMN has no "IF NOT EXISTS" in SQLite, so just
    // attempt it and ignore the one specific error that means it's
    // already there (a fresh CREATE TABLE above already includes it via
    // this same migration running once against an empty db).
    match conn.execute(
        "ALTER TABLE messages ADD COLUMN delivered INTEGER NOT NULL DEFAULT 1",
        [],
    ) {
        Ok(_) => {}
        Err(rusqlite::Error::SqliteFailure(_, Some(msg)))
            if msg.contains("duplicate column name") => {}
        Err(error) => return Err(error.into()),
    }
    Ok(conn)
}

/// Records (or refreshes the metadata of) a conversation this device knows
/// about. Deliberately never overwrites an existing row's retention_days -
/// that's a local choice the server has no say in and a re-sync must not
/// clobber.
pub fn upsert_conversation(conversation: &ChatConversation) -> ResultType<()> {
    let db = DB.lock().unwrap();
    let participants_json = serde_json::to_string(&conversation.participants)?;
    db.execute(
        "INSERT INTO conversations (id, conversation_type, name, created_at, participants_json, retention_days)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(id) DO UPDATE SET
             conversation_type = excluded.conversation_type,
             name = excluded.name,
             participants_json = excluded.participants_json",
        params![
            conversation.id,
            conversation.conversation_type,
            conversation.name,
            conversation.created_at,
            participants_json,
            DEFAULT_RETENTION_DAYS,
        ],
    )?;
    Ok(())
}

/// Stores a message that was just sent or just received. `is_from_self`
/// marks the sender's own copy as already read, since a device never
/// needs an unread badge for something it wrote itself. `delivered` only
/// carries real meaning for a message this device just sent (was the
/// recipient connected to receive it live, per the send response's
/// delivered_to) - a message this device just received is trivially
/// "delivered" (it's already here), so callers should always pass true
/// for those.
pub fn insert_message(
    conversation_id: &str,
    message: &ChatMessage,
    is_from_self: bool,
    delivered: bool,
) -> ResultType<()> {
    {
        let db = DB.lock().unwrap();
        db.execute(
            "INSERT OR IGNORE INTO messages (id, conversation_id, sender_device_id, body, sent_at, is_read, delivered)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                message.id,
                conversation_id,
                message.sender_device_id,
                message.body,
                message.sent_at,
                is_from_self as i64,
                delivered as i64,
            ],
        )?;
    }
    prune_conversation(conversation_id)
}

/// Marks one message (identified by id, not conversation) delivered - the
/// server has just confirmed the recipient actually received it, in
/// response to a "delivered" push. Only ever fires for a message this
/// device sent, but doesn't need to check that: an incoming/self-sent
/// message that was already delivered=1 just gets set to the same value
/// again, harmlessly.
pub fn mark_delivered(message_id: &str) -> ResultType<()> {
    let db = DB.lock().unwrap();
    db.execute(
        "UPDATE messages SET delivered = 1 WHERE id = ?1",
        params![message_id],
    )?;
    Ok(())
}

pub fn mark_read(conversation_id: &str) -> ResultType<()> {
    {
        let db = DB.lock().unwrap();
        db.execute(
            "UPDATE messages SET is_read = 1 WHERE conversation_id = ?1 AND is_read = 0",
            params![conversation_id],
        )?;
    }
    prune_conversation(conversation_id)
}

pub fn set_retention(conversation_id: &str, retention_days: i64) -> ResultType<()> {
    {
        let db = DB.lock().unwrap();
        db.execute(
            "UPDATE conversations SET retention_days = ?1 WHERE id = ?2",
            params![retention_days, conversation_id],
        )?;
    }
    prune_conversation(conversation_id)
}

pub fn get_retention(conversation_id: &str) -> i64 {
    let db = DB.lock().unwrap();
    retention_days_for(&db, conversation_id)
}

fn retention_days_for(db: &Connection, conversation_id: &str) -> i64 {
    db.query_row(
        "SELECT retention_days FROM conversations WHERE id = ?1",
        params![conversation_id],
        |row| row.get(0),
    )
    .unwrap_or(DEFAULT_RETENTION_DAYS)
}

// RETENTION_OFF ("no retention") is deliberately NOT handled here: it
// means "visible only while the chat window is open," not "delete on
// arrival" - immediately deleting on every insert/read (the previous
// behavior) raced a just-sent message's own is_read=1 flag and made it
// vanish before the UI ever displayed it. Purging for that mode instead
// happens once, unconditionally, via purge_conversation() below, called
// from the chat window's own close handler.
fn prune_conversation(conversation_id: &str) -> ResultType<()> {
    let db = DB.lock().unwrap();
    let retention_days = retention_days_for(&db, conversation_id);
    if retention_days != RETENTION_FOREVER && retention_days != RETENTION_OFF {
        db.execute(
            "DELETE FROM messages WHERE conversation_id = ?1 AND sent_at < datetime('now', ?2)",
            params![conversation_id, format!("-{} days", retention_days)],
        )?;
    }
    Ok(())
}

/// Deletes every local message in a conversation, regardless of read
/// state. Used only for the RETENTION_OFF ("no retention") mode, when the
/// chat window that was showing it closes.
pub fn purge_conversation(conversation_id: &str) -> ResultType<()> {
    let db = DB.lock().unwrap();
    db.execute(
        "DELETE FROM messages WHERE conversation_id = ?1",
        params![conversation_id],
    )?;
    Ok(())
}

pub fn list_messages(conversation_id: &str) -> ResultType<Vec<LocalMessage>> {
    let db = DB.lock().unwrap();
    let mut stmt = db.prepare(
        "SELECT id, sender_device_id, body, sent_at, is_read, delivered FROM messages
         WHERE conversation_id = ?1 ORDER BY sent_at ASC",
    )?;
    let rows = stmt.query_map(params![conversation_id], row_to_local_message)?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

fn row_to_local_message(row: &rusqlite::Row<'_>) -> rusqlite::Result<LocalMessage> {
    Ok(LocalMessage {
        id: row.get(0)?,
        sender_device_id: row.get(1)?,
        body: row.get(2)?,
        sent_at: row.get(3)?,
        is_read: row.get::<_, i64>(4)? != 0,
        delivered: row.get::<_, i64>(5)? != 0,
    })
}

pub fn list_conversations() -> ResultType<Vec<LocalConversation>> {
    let db = DB.lock().unwrap();
    let mut stmt = db.prepare(
        "SELECT id, conversation_type, name, created_at, participants_json, retention_days
         FROM conversations",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, i64>(5)?,
        ))
    })?;

    let mut conversations = Vec::new();
    for row in rows {
        let (id, conversation_type, name, created_at, participants_json, retention_days) = row?;
        let participants: Vec<ChatParticipant> =
            serde_json::from_str(&participants_json).unwrap_or_default();

        let last_message = db
            .query_row(
                "SELECT id, sender_device_id, body, sent_at, is_read, delivered FROM messages
                 WHERE conversation_id = ?1 ORDER BY sent_at DESC LIMIT 1",
                params![id],
                row_to_local_message,
            )
            .optional()?;

        let unread_count: i64 = db.query_row(
            "SELECT COUNT(*) FROM messages WHERE conversation_id = ?1 AND is_read = 0",
            params![id],
            |row| row.get(0),
        )?;

        conversations.push(LocalConversation {
            id,
            conversation_type,
            name,
            created_at,
            participants,
            retention_days,
            last_message,
            unread_count,
        });
    }

    conversations.sort_by(|a, b| {
        let a_key = a
            .last_message
            .as_ref()
            .map(|m| m.sent_at.as_str())
            .unwrap_or(&a.created_at);
        let b_key = b
            .last_message
            .as_ref()
            .map(|m| m.sent_at.as_str())
            .unwrap_or(&b.created_at);
        b_key.cmp(a_key)
    });

    Ok(conversations)
}
