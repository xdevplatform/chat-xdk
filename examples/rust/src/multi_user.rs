//! Many signed-in users in one process.
//!
//! A chat holds one user's private keys and signs as that user. A process
//! that serves several signed-in users keeps one chat per user, for all of
//! that user's conversations, and never one per conversation: the chat keeps
//! its conversation keys by conversation and the public keys it has met by
//! user id.
//!
//! Other users' public keys are the same whichever chat asks, so the chats
//! share one cache of them:
//!
//! - [`SharedPublicKeys`] -> a public-key hook over one cache of
//!   `GET /2/users/{id}/public_keys` answers
//! - [`UserChats`]        -> one [`ChatCore`] per signed-in user, each with
//!   that hook

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use chat_xdk_core::error::SdkError;
use chat_xdk_core::{PublicKeyRecord, ResolvePublicKeys};

use crate::chat_core::ChatCore;

/// How long a fetched answer is served before it is fetched again.
pub const PUBLIC_KEYS_TTL: Duration = Duration::from_secs(5 * 60);

/// Fetches one user's records, as `GET /2/users/{id}/public_keys` returns
/// them, or says why it could not.
type Fetch = Box<dyn Fn(&str) -> Result<Vec<PublicKeyRecord>, String> + Send + Sync>;

/// The clock: the time since a fixed start.
type Clock = Box<dyn Fn() -> Duration + Send + Sync>;

/// One lookup of a user's public keys, under way or answered.
struct Lookup {
    /// The time on the clock from which the answer is no longer served.
    expires: Duration,
    /// The user's records, set by the one caller that runs the fetch while
    /// the others wait for it; `None` when the fetch failed.
    records: OnceLock<Option<Vec<PublicKeyRecord>>>,
}

/// Lock a map of this module. A thread that panicked while it held the lock
/// left the map as it was before or after its change, so the lock is taken
/// all the same.
fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A cache of `GET /2/users/{id}/public_keys` answers for every chat in the
/// process, by user id, in front of a function that fetches one user's
/// records.
///
/// [`SharedPublicKeys::resolve`] has the shape of the SDK's public-key hook,
/// and [`SharedPublicKeys::hook`] returns it as one, so the chats of two
/// signed-in users who meet the same user cost one request:
///
/// - Calls that ask for a user whose lookup is under way wait for that
///   lookup, whichever thread they run on.
/// - A lookup that fails is logged and dropped, and the user is left out of
///   the answer: the next call fetches again.
/// - An answer is served for a time, [`PUBLIC_KEYS_TTL`] unless
///   [`SharedPublicKeys::with_ttl`] sets another, then fetched again, so a
///   key a user registers later is picked up.
pub struct SharedPublicKeys {
    fetch: Fetch,
    ttl: Duration,
    now: Clock,
    /// Each user's lookup, by user id. The lock is held to find or replace
    /// an entry and never while a fetch runs, so lookups of different users
    /// do not wait for each other.
    lookups: Mutex<HashMap<String, Arc<Lookup>>>,
}

impl SharedPublicKeys {
    /// A cache in front of `fetch`, which returns one user's records from
    /// `GET /2/users/{id}/public_keys`: the function
    /// [`ChatCore::fetch_public_keys_with`] takes.
    pub fn new<F>(fetch: F) -> Self
    where
        F: Fn(&str) -> Result<Vec<PublicKeyRecord>, String> + Send + Sync + 'static,
    {
        let start = Instant::now();
        Self {
            fetch: Box::new(fetch),
            ttl: PUBLIC_KEYS_TTL,
            now: Box::new(move || start.elapsed()),
            lookups: Mutex::new(HashMap::new()),
        }
    }

    /// Serve each answer for `ttl` before it is fetched again.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Read the time from `now`, which returns the time since a fixed start,
    /// rather than from the system's clock.
    pub fn with_clock<C>(mut self, now: C) -> Self
    where
        C: Fn() -> Duration + Send + Sync + 'static,
    {
        self.now = Box::new(now);
        self
    }

    /// What the SDK's public-key hook returns for `user_ids`: each user's
    /// records, by user id. A user whose lookup failed is left out.
    pub fn resolve(&self, user_ids: &[String]) -> HashMap<String, Vec<PublicKeyRecord>> {
        let mut records = HashMap::new();
        for user_id in user_ids {
            if let Some(found) = self.look_up(user_id) {
                records.insert(user_id.clone(), found);
            }
        }
        records
    }

    /// [`SharedPublicKeys::resolve`] as the hook to set on a chat with
    /// [`ChatCore::resolve_public_keys_with`].
    pub fn hook(self: &Arc<Self>) -> ResolvePublicKeys {
        let shared = Arc::clone(self);
        Arc::new(move |user_ids: &[String]| shared.resolve(user_ids))
    }

    /// One user's records, from the cache or fetched; `None` when the fetch
    /// failed.
    fn look_up(&self, user_id: &str) -> Option<Vec<PublicKeyRecord>> {
        let lookup = self.lookup_for(user_id);
        // The first caller to get here runs the fetch; the others wait for
        // its answer.
        lookup
            .records
            .get_or_init(|| match (self.fetch)(user_id) {
                Ok(records) => Some(records),
                Err(err) => {
                    eprintln!("public_keys_fetch_failed user={user_id} err={err}");
                    self.forget(user_id, &lookup);
                    None
                }
            })
            .clone()
    }

    /// The lookup to read `user_id`'s records from: the one in the cache
    /// while its time lasts, or one this call starts.
    fn lookup_for(&self, user_id: &str) -> Arc<Lookup> {
        let at = (self.now)();
        let mut lookups = locked(&self.lookups);
        if let Some(lookup) = lookups.get(user_id).filter(|lookup| lookup.expires > at) {
            return Arc::clone(lookup);
        }
        // Answers past their time go here, so the cache holds no more than
        // the users looked up within one TTL.
        lookups.retain(|_, lookup| lookup.expires > at);
        let lookup = Arc::new(Lookup {
            expires: at.saturating_add(self.ttl),
            records: OnceLock::new(),
        });
        lookups.insert(user_id.to_string(), Arc::clone(&lookup));
        lookup
    }

    /// Drop `lookup` from the cache, unless a later lookup of `user_id` has
    /// taken its place.
    fn forget(&self, user_id: &str, lookup: &Arc<Lookup>) {
        let mut lookups = locked(&self.lookups);
        if lookups
            .get(user_id)
            .is_some_and(|current| Arc::ptr_eq(current, lookup))
        {
            lookups.remove(user_id);
        }
    }
}

/// One chat per signed-in user, all fetching public keys through one
/// [`SharedPublicKeys`].
pub struct UserChats {
    public_keys: Arc<SharedPublicKeys>,
    /// Each signed-in user's chat, by user id.
    chats: Mutex<HashMap<String, Arc<ChatCore>>>,
}

impl UserChats {
    /// `public_keys` is the cache every chat fetches public keys through.
    pub fn new(public_keys: Arc<SharedPublicKeys>) -> Self {
        Self {
            public_keys,
            chats: Mutex::new(HashMap::new()),
        }
    }

    /// The chat of the signed-in user `user_id`, created on first use from
    /// the user's private-key blob and the `public_key_version` it was
    /// registered under. Calls for one user get one chat, whichever thread
    /// they come from, and that chat serves every conversation of the user.
    /// A chat that could not be created is not kept: the next call tries
    /// again.
    pub fn chat_for(
        &self,
        user_id: &str,
        private_keys_b64: &str,
        signing_key_version: &str,
    ) -> Result<Arc<ChatCore>, SdkError> {
        // The lock is held while the chat is created, which makes no
        // request, so a second call for the user waits and gets that chat.
        let mut chats = locked(&self.chats);
        if let Some(chat) = chats.get(user_id) {
            return Ok(Arc::clone(chat));
        }
        let mut core = ChatCore::new();
        core.load_keys(private_keys_b64, signing_key_version)?;
        core.set_identity(user_id)?;
        core.resolve_public_keys_with(self.public_keys.hook());
        let chat = Arc::new(core);
        chats.insert(user_id.to_string(), Arc::clone(&chat));
        Ok(chat)
    }

    /// Sign `user_id` out: forget the user's chat. Its keys are cleared
    /// from memory once every holder of the chat has dropped it.
    pub fn close(&self, user_id: &str) {
        locked(&self.chats).remove(user_id);
    }
}
