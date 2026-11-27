//! The compiled policy and its decision (ADR-0022).
//!
//! Every identifier is mapped once to a dense index; memberships and the
//! rules of each account and of each group of accounts are kept as sorted
//! arrays (one offset table and one data table per relation). A decision
//! reads the rules of the account and of its groups only, checks the
//! subject by a binary search in the groups of the user, and allocates
//! nothing.

use std::collections::HashMap;
use std::hash::Hash;

use crate::decision::{Allowed, Decision, Denied, Request};
use crate::error::{Code, PolicyError};
use crate::model::{
    AccountGroupId, AccountId, Effect, Functions, Protocols, Rule, RuleId, Snapshot, Subject,
    Target, UserGroupId, UserId,
};

/// Longest validity of an allowing rule: 366 days, as a right (ADR-0014).
pub const MAX_ALLOW_SECS: u64 = 366 * 86_400;
/// Shortest session an allowing rule may set, seconds.
pub const MIN_SESSION_SECS: u32 = 60;
/// Longest session an allowing rule may set: 12 h.
pub const MAX_SESSION_SECS: u32 = 12 * 3_600;
/// Bound of each list of a snapshot (rules, memberships of users, of
/// accounts): the indexes are 32 bits wide, and the bound keeps a hostile
/// or broken database from taking the memory of the core.
pub const MAX_ITEMS: usize = 1 << 24;

/// A relation from dense indexes to sorted dense indexes.
#[derive(Debug, Default)]
struct Relation {
    /// `offsets[i]..offsets[i + 1]` is the slice of `data` of key `i`.
    offsets: Box<[u32]>,
    data: Box<[u32]>,
}

impl Relation {
    /// Builds the relation of `keys` keys from `pairs` (sorted and deduplicated
    /// here). Every key and value fits in `u32` ([`MAX_ITEMS`]).
    fn build(keys: usize, mut pairs: Vec<(u32, u32)>) -> Self {
        pairs.sort_unstable();
        pairs.dedup();
        let mut offsets = vec![0u32; keys + 1];
        for &(k, _) in &pairs {
            offsets[k as usize + 1] += 1;
        }
        for i in 0..keys {
            offsets[i + 1] += offsets[i];
        }
        Self {
            offsets: offsets.into_boxed_slice(),
            data: pairs.into_iter().map(|(_, v)| v).collect(),
        }
    }

    fn get(&self, key: u32) -> &[u32] {
        let k = key as usize;
        match (self.offsets.get(k), self.offsets.get(k + 1)) {
            (Some(&start), Some(&end)) => {
                self.data.get(start as usize..end as usize).unwrap_or(&[])
            }
            _ => &[],
        }
    }
}

/// Dense indexes of one kind of identifier.
struct Interner<K> {
    map: HashMap<K, u32>,
}

impl<K: Copy + Eq + Hash> Interner<K> {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    /// The index of `key`, given now if new. Never more than [`MAX_ITEMS`]
    /// times three keys of a kind, which fits in `u32`.
    fn intern(&mut self, key: K) -> u32 {
        let next = u32::try_from(self.map.len()).unwrap_or(u32::MAX);
        *self.map.entry(key).or_insert(next)
    }

    fn finish(mut self) -> HashMap<K, u32> {
        self.map.shrink_to_fit();
        self.map
    }
}

#[derive(Debug, Clone, Copy)]
enum CompiledSubject {
    User(u32),
    Group(u32),
}

#[derive(Debug, Clone, Copy)]
struct CompiledRule {
    id: RuleId,
    subject: CompiledSubject,
    protocols: Protocols,
    effect: Effect,
    valid_from: u64,
    valid_until: u64,
}

/// What a compiled policy holds, for the logs and the audit record of its
/// installation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// Rules.
    pub rules: usize,
    /// Users named by a membership or a rule.
    pub users: usize,
    /// Groups of users.
    pub user_groups: usize,
    /// Accounts named by a membership or a rule.
    pub accounts: usize,
    /// Groups of accounts.
    pub account_groups: usize,
}

/// One version of the policy, compiled; immutable. [`crate::Pdp`] holds the
/// current one.
pub struct CompiledPolicy {
    version: u64,
    users: HashMap<UserId, u32>,
    accounts: HashMap<AccountId, u32>,
    user_group_count: usize,
    account_group_count: usize,
    /// Sorted by identifier: the index order is the identifier order.
    rules: Box<[CompiledRule]>,
    /// User → its groups.
    groups_of_user: Relation,
    /// Account → its groups.
    groups_of_account: Relation,
    /// Account → the rules that name it.
    rules_of_account: Relation,
    /// Group of accounts → the rules that name it.
    rules_of_account_group: Relation,
}

impl std::fmt::Debug for CompiledPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledPolicy")
            .field("version", &self.version)
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

fn bounded(what: &'static str, count: usize) -> Result<(), PolicyError> {
    if count > MAX_ITEMS {
        return Err(PolicyError::TooMany {
            what,
            count,
            max: MAX_ITEMS,
        });
    }
    Ok(())
}

fn validate(rule: &Rule) -> Result<(), PolicyError> {
    if rule.protocols.is_empty() {
        return Err(PolicyError::NoProtocol(rule.id));
    }
    if rule.valid_until <= rule.valid_from {
        return Err(PolicyError::Window(rule.id));
    }
    match rule.effect {
        Effect::Allow {
            max_session_secs, ..
        } => {
            if rule.valid_until - rule.valid_from > MAX_ALLOW_SECS {
                return Err(PolicyError::AllowTooLong(rule.id));
            }
            if !(MIN_SESSION_SECS..=MAX_SESSION_SECS).contains(&max_session_secs) {
                return Err(PolicyError::SessionLength(rule.id));
            }
        }
        Effect::DenyFunctions(functions) if functions.is_empty() => {
            return Err(PolicyError::NoFunction(rule.id));
        }
        Effect::Deny | Effect::DenyFunctions(_) => {}
    }
    Ok(())
}

impl CompiledPolicy {
    /// Compiles `snapshot`.
    ///
    /// # Errors
    ///
    /// [`PolicyError`] (`POL-E004`): a rule in double, without protocol,
    /// with an empty window, an allowing rule longer than 366 days or with
    /// a session out of `[60 s, 12 h]`, a refusal of no function, or a list
    /// longer than [`MAX_ITEMS`]. Nothing is partly compiled.
    pub fn compile(snapshot: &Snapshot) -> Result<Self, PolicyError> {
        bounded("règles", snapshot.rules.len())?;
        bounded(
            "membres des groupes d'utilisateurs",
            snapshot.user_groups.len(),
        )?;
        bounded(
            "membres des groupes de comptes",
            snapshot.account_groups.len(),
        )?;

        let mut rules: Vec<&Rule> = snapshot.rules.iter().collect();
        rules.sort_unstable_by_key(|r| r.id);
        for pair in rules.windows(2) {
            if pair[0].id == pair[1].id {
                return Err(PolicyError::DuplicateRule(pair[0].id));
            }
        }
        for rule in &rules {
            validate(rule)?;
        }

        let mut users = Interner::<UserId>::new();
        let mut user_groups = Interner::<UserGroupId>::new();
        let mut accounts = Interner::<AccountId>::new();
        let mut account_groups = Interner::<AccountGroupId>::new();

        let user_pairs: Vec<(u32, u32)> = snapshot
            .user_groups
            .iter()
            .map(|&(g, u)| (users.intern(u), user_groups.intern(g)))
            .collect();
        let account_pairs: Vec<(u32, u32)> = snapshot
            .account_groups
            .iter()
            .map(|&(g, a)| (accounts.intern(a), account_groups.intern(g)))
            .collect();

        let mut by_account = Vec::new();
        let mut by_account_group = Vec::new();
        let mut compiled = Vec::with_capacity(rules.len());
        for (index, rule) in rules.iter().enumerate() {
            // At most MAX_ITEMS rules: the index fits.
            let index = u32::try_from(index).unwrap_or(u32::MAX);
            let subject = match rule.subject {
                Subject::User(u) => CompiledSubject::User(users.intern(u)),
                Subject::Group(g) => CompiledSubject::Group(user_groups.intern(g)),
            };
            match rule.target {
                Target::Account(a) => by_account.push((accounts.intern(a), index)),
                Target::AccountGroup(g) => {
                    by_account_group.push((account_groups.intern(g), index));
                }
            }
            compiled.push(CompiledRule {
                id: rule.id,
                subject,
                protocols: rule.protocols,
                effect: rule.effect,
                valid_from: rule.valid_from,
                valid_until: rule.valid_until,
            });
        }

        let users = users.finish();
        let accounts = accounts.finish();
        let user_group_count = user_groups.finish().len();
        let account_group_count = account_groups.finish().len();
        Ok(Self {
            version: snapshot.version,
            groups_of_user: Relation::build(users.len(), user_pairs),
            groups_of_account: Relation::build(accounts.len(), account_pairs),
            rules_of_account: Relation::build(accounts.len(), by_account),
            rules_of_account_group: Relation::build(account_group_count, by_account_group),
            users,
            accounts,
            user_group_count,
            account_group_count,
            rules: compiled.into_boxed_slice(),
        })
    }

    /// Its version.
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// What it holds.
    pub fn stats(&self) -> Stats {
        Stats {
            rules: self.rules.len(),
            users: self.users.len(),
            user_groups: self.user_group_count,
            accounts: self.accounts.len(),
            account_groups: self.account_group_count,
        }
    }

    fn denied(&self, code: Code, rule: Option<RuleId>) -> Decision {
        Decision::Deny(Denied {
            version: Some(self.version),
            code,
            rule,
        })
    }

    /// Decides `request`. Refused by default; a valid refusing rule wins
    /// over any allowing rule. Among the allowing rules, the one that has
    /// every function wanted (for the protocol) comes first, then the one
    /// that ends last, then the longest session, then the smallest
    /// identifier: the functions of several rules never add up. The
    /// refused functions are then taken away. Does not allocate.
    pub fn decide(&self, request: &Request) -> Decision {
        let (Some(&user), Some(&account)) = (
            self.users.get(&request.user),
            self.accounts.get(&request.account),
        ) else {
            return self.denied(Code::NoRule, None);
        };
        let groups = self.groups_of_user.get(user);
        let wanted = request.wanted.for_protocol(request.protocol);

        let mut deny: Option<RuleId> = None;
        let mut taken = Functions::NONE;
        let mut restricted_by: Option<RuleId> = None;
        let mut best: Option<(&CompiledRule, Functions, u32)> = None;

        let direct = self.rules_of_account.get(account);
        let via_groups = self
            .groups_of_account
            .get(account)
            .iter()
            .flat_map(|&g| self.rules_of_account_group.get(g));
        for &index in direct.iter().chain(via_groups) {
            let Some(rule) = self.rules.get(index as usize) else {
                continue;
            };
            if !rule.protocols.contains(request.protocol)
                || request.now < rule.valid_from
                || request.now >= rule.valid_until
            {
                continue;
            }
            let applies = match rule.subject {
                CompiledSubject::User(u) => u == user,
                CompiledSubject::Group(g) => groups.binary_search(&g).is_ok(),
            };
            if !applies {
                continue;
            }
            match rule.effect {
                Effect::Deny => {
                    if deny.is_none_or(|d| rule.id < d) {
                        deny = Some(rule.id);
                    }
                }
                Effect::DenyFunctions(functions) => {
                    taken = taken.union(functions);
                    if restricted_by.is_none_or(|r| rule.id < r) {
                        restricted_by = Some(rule.id);
                    }
                }
                Effect::Allow {
                    functions,
                    max_session_secs,
                } => {
                    let functions = functions.for_protocol(request.protocol);
                    if best.is_none_or(|b| better(rule, functions, max_session_secs, b, wanted)) {
                        best = Some((rule, functions, max_session_secs));
                    }
                }
            }
        }

        if deny.is_some() {
            return self.denied(Code::DeniedByRule, deny);
        }
        let Some((rule, functions, max_session_secs)) = best else {
            return self.denied(Code::NoRule, None);
        };
        // Taking functions away may leave a one-way SSH transfer: dropped too.
        let granted = functions.difference(taken).for_protocol(request.protocol);
        let remaining = rule.valid_until - request.now;
        Decision::Allow(Allowed {
            version: self.version,
            rule: rule.id,
            functions: granted,
            missing: wanted.difference(granted),
            restricted_by: if granted == functions {
                None
            } else {
                restricted_by
            },
            max_session_secs: u32::try_from(remaining)
                .map_or(max_session_secs, |r| r.min(max_session_secs)),
            valid_until: rule.valid_until,
        })
    }
}

/// Whether `rule` beats the current best allowing rule.
fn better(
    rule: &CompiledRule,
    functions: Functions,
    max_session_secs: u32,
    (best, best_functions, best_session): (&CompiledRule, Functions, u32),
    wanted: Functions,
) -> bool {
    let key = (
        functions.contains(wanted),
        rule.valid_until,
        max_session_secs,
        std::cmp::Reverse(rule.id),
    );
    let best_key = (
        best_functions.contains(wanted),
        best.valid_until,
        best_session,
        std::cmp::Reverse(best.id),
    );
    key > best_key
}
