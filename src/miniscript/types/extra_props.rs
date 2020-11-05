//! Other miscellaneous type properties which are not related to
//! correctness or malleability.

use super::{Error, ErrorKind, Property, ScriptContext};
use script_num_size;
use std::cmp;
use std::iter::once;
use MiniscriptKey;
use Terminal;

/// Maximum operations per script
// https://github.com/bitcoin/bitcoin/blob/875e1ccc9fe01e026e564dfd39a64d9a4b332a89/src/script/script.h#L26
pub const MAX_OPS_PER_SCRIPT: usize = 201;
/// Maximum p2wsh initial stack items
// https://github.com/bitcoin/bitcoin/blob/875e1ccc9fe01e026e564dfd39a64d9a4b332a89/src/policy/policy.h#L40
pub const MAX_STANDARD_P2WSH_STACK_ITEMS: usize = 100;
/// Maximum script size allowed by standardness rules
// https://github.com/bitcoin/bitcoin/blob/283a73d7eaea2907a6f7f800f529a0d6db53d7a6/src/policy/policy.h#L44
pub const MAX_STANDARD_P2WSH_SCRIPT_SIZE: usize = 3600;
/// The Threshold for deciding whether `nLockTime` is interpreted as
/// time or height.
// https://github.com/bitcoin/bitcoin/blob/9ccaee1d5e2e4b79b0a7c29aadb41b97e4741332/src/script/script.h#L39
pub const HEIGHT_TIME_THRESHOLD: u32 = 500_000_000;

/// Bit flag for deciding whether sequence number is
/// interpreted as height or time
/* If nSequence encodes a relative lock-time and this flag
 * is set, the relative lock-time has units of 512 seconds,
 * otherwise it specifies blocks with a granularity of 1. */
// https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki
pub const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;

/// Disable flag for sequence locktime
/* Below flags apply in the context of BIP 68*/
/* If this flag set, nSequence is NOT interpreted as a
 * relative lock-time. For future soft-fork compatibility*/
// https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki
pub const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;

/// Helper struct Whether any satisfaction of this fragment contains any timelocks
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct TimeLockInfo {
    /// csv with heights
    pub csv_with_height: bool,
    /// csv with times
    pub csv_with_time: bool,
    /// cltv with heights
    pub cltv_with_height: bool,
    /// cltv with times
    pub cltv_with_time: bool,
    /// combination of any heightlocks and timelocks
    pub contains_combination: bool,
}

impl Default for TimeLockInfo {
    fn default() -> Self {
        Self {
            csv_with_height: false,
            csv_with_time: false,
            cltv_with_height: false,
            cltv_with_time: false,
            contains_combination: false,
        }
    }
}

impl TimeLockInfo {
    /// Whether the current contains any possible unspendable
    /// path
    pub fn contains_unspendable_path(self) -> bool {
        self.contains_combination
    }

    // handy function for combining `and` timelocks
    // This can be operator overloaded in future
    pub(crate) fn comb_and_timelocks(a: Self, b: Self) -> Self {
        Self::combine_thresh_timelocks(2, once(a).chain(once(b)))
    }

    // handy function for combining `or` timelocks
    // This can be operator overloaded in future
    pub(crate) fn comb_or_timelocks(a: Self, b: Self) -> Self {
        Self::combine_thresh_timelocks(1, once(a).chain(once(b)))
    }

    pub(crate) fn combine_thresh_timelocks<I>(k: usize, sub_timelocks: I) -> TimeLockInfo
    where
        I: IntoIterator<Item = TimeLockInfo>,
    {
        // timelocks calculation
        // Propagate all fields of `TimelockInfo` from each of the node's children to the node
        // itself (by taking the logical-or of all of them). In case `k == 1` (this is a disjunction)
        // this is all we need to do: the node may behave like any of its children, for purposes
        // of timelock accounting.
        //
        // If `k > 1` we have the additional consideration that if any two children have conflicting
        // timelock requirements, this represents an inaccessible spending branch.
        sub_timelocks.into_iter().fold(
            TimeLockInfo::default(),
            |mut timelock_info, sub_timelock| {
                // If more than one branch may be taken, and some other branch has a requirement
                // that conflicts with this one, set `contains_combination`
                if k >= 2 {
                    timelock_info.contains_combination |= (timelock_info.csv_with_height
                        && sub_timelock.csv_with_time)
                        || (timelock_info.csv_with_time && sub_timelock.csv_with_height)
                        || (timelock_info.cltv_with_time && sub_timelock.cltv_with_height)
                        || (timelock_info.cltv_with_height && sub_timelock.cltv_with_time);
                }
                timelock_info.csv_with_height |= sub_timelock.csv_with_height;
                timelock_info.csv_with_time |= sub_timelock.csv_with_time;
                timelock_info.cltv_with_height |= sub_timelock.cltv_with_height;
                timelock_info.cltv_with_time |= sub_timelock.cltv_with_time;
                timelock_info.contains_combination |= sub_timelock.contains_combination;
                timelock_info
            },
        )
    }
}

/// Structure representing the extra type properties of a fragment. If a fragment
/// is used in pre-segwit transactions it will only be malleable but still is
/// correct and sound.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct ExtData {
    /// The number of bytes needed to encode its scriptpubkey
    pub pk_cost: usize,
    /// Whether this fragment can be verify-wrapped for free
    pub has_free_verify: bool,
    /// The worst case static(unexecuted) ops-count for this Miniscript fragment.
    pub ops_count_static: usize,
    /// The worst case ops-count for satisfying this Miniscript fragment.
    pub ops_count_sat: Option<usize>,
    /// The worst case ops-count for dissatisfying this Miniscript fragment.
    pub ops_count_nsat: Option<usize>,
    /// The timelock info about heightlocks and timelocks
    pub timelock_info: TimeLockInfo,
}

impl Property for ExtData {
    fn sanity_checks(&self) {
        //No sanity checks
    }

    fn from_true() -> Self {
        ExtData {
            pk_cost: 1,
            has_free_verify: false,
            ops_count_static: 0,
            ops_count_sat: Some(0),
            ops_count_nsat: None,
            timelock_info: TimeLockInfo::default(),
        }
    }

    fn from_false() -> Self {
        ExtData {
            pk_cost: 1,
            has_free_verify: false,
            ops_count_static: 0,
            ops_count_sat: None,
            ops_count_nsat: Some(0),
            timelock_info: TimeLockInfo::default(),
        }
    }

    fn from_pk_k() -> Self {
        ExtData {
            pk_cost: 34,
            has_free_verify: false,
            ops_count_static: 0,
            ops_count_sat: Some(0),
            ops_count_nsat: Some(0),
            timelock_info: TimeLockInfo::default(),
        }
    }

    fn from_pk_h() -> Self {
        ExtData {
            pk_cost: 24,
            has_free_verify: false,
            ops_count_static: 3,
            ops_count_sat: Some(3),
            ops_count_nsat: Some(3),
            timelock_info: TimeLockInfo::default(),
        }
    }

    fn from_multi(k: usize, n: usize) -> Self {
        let num_cost = match (k > 16, n > 16) {
            (true, true) => 4,
            (false, true) => 3,
            (true, false) => 3,
            (false, false) => 2,
        };
        ExtData {
            pk_cost: num_cost + 34 * n + 1,
            has_free_verify: true,
            ops_count_static: 1,
            ops_count_sat: Some(n + 1),
            ops_count_nsat: Some(n + 1),
            timelock_info: TimeLockInfo::default(),
        }
    }

    fn from_hash() -> Self {
        //never called directly
        unreachable!()
    }

    fn from_sha256() -> Self {
        ExtData {
            pk_cost: 33 + 6,
            has_free_verify: true,
            ops_count_static: 4,
            ops_count_sat: Some(4),
            ops_count_nsat: None,
            timelock_info: TimeLockInfo::default(),
        }
    }

    fn from_hash256() -> Self {
        ExtData {
            pk_cost: 33 + 6,
            has_free_verify: true,
            ops_count_static: 4,
            ops_count_sat: Some(4),
            ops_count_nsat: None,
            timelock_info: TimeLockInfo::default(),
        }
    }

    fn from_ripemd160() -> Self {
        ExtData {
            pk_cost: 21 + 6,
            has_free_verify: true,
            ops_count_static: 4,
            ops_count_sat: Some(4),
            ops_count_nsat: None,
            timelock_info: TimeLockInfo::default(),
        }
    }

    fn from_hash160() -> Self {
        ExtData {
            pk_cost: 21 + 6,
            has_free_verify: true,
            ops_count_static: 4,
            ops_count_sat: Some(4),
            ops_count_nsat: None,
            timelock_info: TimeLockInfo::default(),
        }
    }

    fn from_time(_t: u32) -> Self {
        unreachable!()
    }

    fn from_after(t: u32) -> Self {
        ExtData {
            pk_cost: script_num_size(t as usize) + 1,
            has_free_verify: false,
            ops_count_static: 1,
            ops_count_sat: Some(1),
            ops_count_nsat: None,
            timelock_info: TimeLockInfo {
                csv_with_height: false,
                csv_with_time: false,
                cltv_with_height: t < HEIGHT_TIME_THRESHOLD,
                cltv_with_time: t >= HEIGHT_TIME_THRESHOLD,
                contains_combination: false,
            },
        }
    }

    fn from_older(t: u32) -> Self {
        ExtData {
            pk_cost: script_num_size(t as usize) + 1,
            has_free_verify: false,
            ops_count_static: 1,
            ops_count_sat: Some(1),
            ops_count_nsat: None,
            timelock_info: TimeLockInfo {
                csv_with_height: (t & SEQUENCE_LOCKTIME_TYPE_FLAG) == 0,
                csv_with_time: (t & SEQUENCE_LOCKTIME_TYPE_FLAG) != 0,
                cltv_with_height: false,
                cltv_with_time: false,
                contains_combination: false,
            },
        }
    }

    fn cast_alt(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            pk_cost: self.pk_cost + 2,
            has_free_verify: false,
            ops_count_static: self.ops_count_static + 2,
            ops_count_sat: self.ops_count_sat.map(|x| x + 2),
            ops_count_nsat: self.ops_count_nsat.map(|x| x + 2),
            timelock_info: self.timelock_info,
        })
    }

    fn cast_swap(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            pk_cost: self.pk_cost + 1,
            has_free_verify: self.has_free_verify,
            ops_count_static: self.ops_count_static + 1,
            ops_count_sat: self.ops_count_sat.map(|x| x + 1),
            ops_count_nsat: self.ops_count_nsat.map(|x| x + 1),
            timelock_info: self.timelock_info,
        })
    }

    fn cast_check(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            pk_cost: self.pk_cost + 1,
            has_free_verify: true,
            ops_count_static: self.ops_count_static + 1,
            ops_count_sat: self.ops_count_sat.map(|x| x + 1),
            ops_count_nsat: self.ops_count_nsat.map(|x| x + 1),
            timelock_info: self.timelock_info,
        })
    }

    fn cast_dupif(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            pk_cost: self.pk_cost + 3,
            has_free_verify: false,
            ops_count_static: self.ops_count_static + 3,
            ops_count_sat: self.ops_count_sat.map(|x| x + 3),
            ops_count_nsat: Some(self.ops_count_static + 3),
            timelock_info: self.timelock_info,
        })
    }

    fn cast_verify(self) -> Result<Self, ErrorKind> {
        let verify_cost = if self.has_free_verify { 0 } else { 1 };
        Ok(ExtData {
            pk_cost: self.pk_cost + if self.has_free_verify { 0 } else { 1 },
            has_free_verify: false,
            ops_count_static: self.ops_count_static + verify_cost,
            ops_count_sat: self.ops_count_sat.map(|x| x + verify_cost),
            ops_count_nsat: None,
            timelock_info: self.timelock_info,
        })
    }

    fn cast_nonzero(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            pk_cost: self.pk_cost + 4,
            has_free_verify: false,
            ops_count_static: self.ops_count_static + 4,
            ops_count_sat: self.ops_count_sat.map(|x| x + 4),
            ops_count_nsat: Some(self.ops_count_static + 4),
            timelock_info: self.timelock_info,
        })
    }

    fn cast_zeronotequal(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            pk_cost: self.pk_cost + 1,
            has_free_verify: false,
            ops_count_static: self.ops_count_static + 1,
            ops_count_sat: self.ops_count_sat.map(|x| x + 1),
            ops_count_nsat: self.ops_count_nsat.map(|x| x + 1),
            timelock_info: self.timelock_info,
        })
    }

    fn cast_true(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            pk_cost: self.pk_cost + 1,
            has_free_verify: false,
            ops_count_static: self.ops_count_static,
            ops_count_sat: self.ops_count_sat,
            ops_count_nsat: None,
            timelock_info: self.timelock_info,
        })
    }

    fn cast_or_i_false(self) -> Result<Self, ErrorKind> {
        // never called directly
        unreachable!()
    }

    fn cast_unlikely(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            pk_cost: self.pk_cost + 4,
            has_free_verify: false,
            ops_count_static: self.ops_count_static + 3,
            ops_count_sat: self.ops_count_sat.map(|x| x + 3),
            ops_count_nsat: Some(self.ops_count_static + 3),
            timelock_info: self.timelock_info,
        })
    }

    fn cast_likely(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            pk_cost: self.pk_cost + 4,
            has_free_verify: false,
            ops_count_static: self.ops_count_static + 3,
            ops_count_sat: self.ops_count_sat.map(|x| x + 3),
            ops_count_nsat: Some(self.ops_count_static + 3),
            timelock_info: self.timelock_info,
        })
    }

    fn and_b(l: Self, r: Self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            pk_cost: l.pk_cost + r.pk_cost + 1,
            has_free_verify: false,
            ops_count_static: l.ops_count_static + r.ops_count_static + 1,
            ops_count_sat: l
                .ops_count_sat
                .and_then(|x| r.ops_count_sat.map(|y| x + y + 1)),
            ops_count_nsat: l
                .ops_count_nsat
                .and_then(|x| r.ops_count_nsat.map(|y| x + y + 1)),
            timelock_info: TimeLockInfo::comb_and_timelocks(l.timelock_info, r.timelock_info),
        })
    }

    fn and_v(l: Self, r: Self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            pk_cost: l.pk_cost + r.pk_cost,
            has_free_verify: r.has_free_verify,
            ops_count_static: l.ops_count_static + r.ops_count_static,
            ops_count_sat: l.ops_count_sat.and_then(|x| r.ops_count_sat.map(|y| x + y)),
            ops_count_nsat: None,
            timelock_info: TimeLockInfo::comb_and_timelocks(l.timelock_info, r.timelock_info),
        })
    }

    fn or_b(l: Self, r: Self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            pk_cost: l.pk_cost + r.pk_cost + 1,
            has_free_verify: false,
            ops_count_static: l.ops_count_static + r.ops_count_static + 1,
            ops_count_sat: cmp::max(
                l.ops_count_sat
                    .and_then(|x| r.ops_count_nsat.map(|y| y + x + 1)),
                r.ops_count_sat
                    .and_then(|x| l.ops_count_nsat.map(|y| y + x + 1)),
            ),
            ops_count_nsat: l
                .ops_count_nsat
                .and_then(|x| r.ops_count_nsat.map(|y| x + y + 1)),
            timelock_info: TimeLockInfo::comb_or_timelocks(l.timelock_info, r.timelock_info),
        })
    }

    fn or_d(l: Self, r: Self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            pk_cost: l.pk_cost + r.pk_cost + 3,
            has_free_verify: false,
            ops_count_static: l.ops_count_static + r.ops_count_static + 1,
            ops_count_sat: cmp::max(
                l.ops_count_sat.map(|x| x + 3 + r.ops_count_static),
                r.ops_count_sat
                    .and_then(|x| l.ops_count_nsat.map(|y| y + x + 3)),
            ),
            ops_count_nsat: l
                .ops_count_nsat
                .and_then(|x| r.ops_count_nsat.map(|y| x + y + 3)),
            timelock_info: TimeLockInfo::comb_or_timelocks(l.timelock_info, r.timelock_info),
        })
    }

    fn or_c(l: Self, r: Self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            pk_cost: l.pk_cost + r.pk_cost + 2,
            has_free_verify: false,
            ops_count_static: l.ops_count_static + r.ops_count_static + 2,
            ops_count_sat: cmp::max(
                l.ops_count_sat.map(|x| x + 2 + r.ops_count_static),
                r.ops_count_sat
                    .and_then(|x| l.ops_count_nsat.map(|y| y + x + 2)),
            ),
            ops_count_nsat: None,
            timelock_info: TimeLockInfo::comb_or_timelocks(l.timelock_info, r.timelock_info),
        })
    }

    fn or_i(l: Self, r: Self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            pk_cost: l.pk_cost + r.pk_cost + 3,
            has_free_verify: false,
            ops_count_static: l.ops_count_static + r.ops_count_static + 3,
            ops_count_sat: cmp::max(
                l.ops_count_sat.map(|x| x + 3 + r.ops_count_static),
                r.ops_count_sat.map(|x| x + 3 + l.ops_count_static),
            ),
            ops_count_nsat: match (l.ops_count_nsat, r.ops_count_nsat) {
                (Some(a), Some(b)) => Some(cmp::max(a, b) + 3),
                (_, Some(x)) | (Some(x), _) => Some(x + 3),
                (None, None) => None,
            },
            timelock_info: TimeLockInfo::comb_or_timelocks(l.timelock_info, r.timelock_info),
        })
    }

    fn and_or(a: Self, b: Self, c: Self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            pk_cost: a.pk_cost + b.pk_cost + c.pk_cost + 3,
            has_free_verify: false,
            ops_count_static: a.ops_count_static + b.ops_count_static + c.ops_count_static + 3,
            ops_count_sat: cmp::max(
                a.ops_count_sat
                    .and_then(|x| b.ops_count_sat.map(|y| x + y + c.ops_count_static + 3)),
                c.ops_count_sat
                    .and_then(|z| a.ops_count_nsat.map(|y| y + z + b.ops_count_static + 3)),
            ),
            ops_count_nsat: c
                .ops_count_nsat
                .and_then(|z| a.ops_count_nsat.map(|x| x + b.ops_count_static + z + 3)),
            timelock_info: TimeLockInfo::comb_or_timelocks(
                TimeLockInfo::comb_and_timelocks(a.timelock_info, b.timelock_info),
                c.timelock_info,
            ),
        })
    }

    fn threshold<S>(k: usize, n: usize, mut sub_ck: S) -> Result<Self, ErrorKind>
    where
        S: FnMut(usize) -> Result<Self, ErrorKind>,
    {
        let mut pk_cost = 1 + script_num_size(k); //Equal and k
        let mut ops_count_static = 0 as usize;
        let mut ops_count_sat_vec = Vec::with_capacity(n);
        let mut ops_count_nsat_sum = 0 as usize;
        let mut ops_count_nsat = Some(0);
        let mut ops_count_sat = Some(0);
        let mut sat_count = 0;
        let mut timelocks = Vec::with_capacity(n);
        for i in 0..n {
            let sub = sub_ck(i)?;

            pk_cost += sub.pk_cost;
            ops_count_static += sub.ops_count_static;
            timelocks.push(sub.timelock_info);
            match (sub.ops_count_sat, sub.ops_count_nsat) {
                (Some(x), Some(y)) => {
                    ops_count_sat_vec.push(Some(x as i32 - y as i32));
                    ops_count_nsat = ops_count_nsat.map(|v| y + v);
                    ops_count_nsat_sum = ops_count_nsat_sum + y;
                }
                (Some(x), None) => {
                    sat_count = sat_count + 1;
                    ops_count_sat = ops_count_sat.map(|y| x + y);
                    ops_count_nsat = None;
                }
                _ => {}
            }
        }
        let remaining_sat = k - sat_count;
        let mut sum: i32 = 0;
        if k < sat_count || ops_count_sat_vec.len() < remaining_sat {
            ops_count_sat = None;
        } else {
            ops_count_sat_vec.sort();
            ops_count_sat_vec.reverse();
            sum = ops_count_sat_vec
                .split_off(remaining_sat)
                .iter()
                .map(|z| z.unwrap())
                .sum();
        }
        Ok(ExtData {
            pk_cost: pk_cost + n - 1, //all pk cost + (n-1)*ADD
            has_free_verify: true,
            ops_count_static: ops_count_static + (n - 1) + 1, //adds and equal
            ops_count_sat: ops_count_sat
                .map(|x: usize| (x + (n - 1) + 1 + (sum + ops_count_nsat_sum as i32) as usize)), //adds and equal
            ops_count_nsat: ops_count_nsat.map(|x| x + (n - 1) + 1), //adds and equal
            timelock_info: TimeLockInfo::combine_thresh_timelocks(k, timelocks),
        })
    }

    /// Compute the type of a fragment assuming all the children of
    /// Miniscript have been computed already.
    fn type_check<Pk, Ctx, C>(
        fragment: &Terminal<Pk, Ctx>,
        _child: C,
    ) -> Result<Self, Error<Pk, Ctx>>
    where
        C: FnMut(usize) -> Option<Self>,
        Ctx: ScriptContext,
        Pk: MiniscriptKey,
    {
        let wrap_err = |result: Result<Self, ErrorKind>| {
            result.map_err(|kind| Error {
                fragment: fragment.clone(),
                error: kind,
            })
        };

        let ret = match *fragment {
            Terminal::True => Ok(Self::from_true()),
            Terminal::False => Ok(Self::from_false()),
            Terminal::PkK(..) => Ok(Self::from_pk_k()),
            Terminal::PkH(..) => Ok(Self::from_pk_h()),
            Terminal::Multi(k, ref pks) => {
                if k == 0 {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::ZeroThreshold,
                    });
                }
                if k > pks.len() {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::OverThreshold(k, pks.len()),
                    });
                }
                Ok(Self::from_multi(k, pks.len()))
            }
            Terminal::After(t) => {
                // FIXME check if t > 2^31 - 1
                if t == 0 {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::ZeroTime,
                    });
                }
                Ok(Self::from_after(t))
            }
            Terminal::Older(t) => {
                if t == 0 {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::ZeroTime,
                    });
                }
                Ok(Self::from_older(t))
            }
            Terminal::Sha256(..) => Ok(Self::from_sha256()),
            Terminal::Hash256(..) => Ok(Self::from_hash256()),
            Terminal::Ripemd160(..) => Ok(Self::from_ripemd160()),
            Terminal::Hash160(..) => Ok(Self::from_hash160()),
            Terminal::Alt(ref sub) => wrap_err(Self::cast_alt(sub.ext.clone())),
            Terminal::Swap(ref sub) => wrap_err(Self::cast_swap(sub.ext.clone())),
            Terminal::Check(ref sub) => wrap_err(Self::cast_check(sub.ext.clone())),
            Terminal::DupIf(ref sub) => wrap_err(Self::cast_dupif(sub.ext.clone())),
            Terminal::Verify(ref sub) => wrap_err(Self::cast_verify(sub.ext.clone())),
            Terminal::NonZero(ref sub) => wrap_err(Self::cast_nonzero(sub.ext.clone())),
            Terminal::ZeroNotEqual(ref sub) => wrap_err(Self::cast_zeronotequal(sub.ext.clone())),
            Terminal::AndB(ref l, ref r) => {
                let ltype = l.ext.clone();
                let rtype = r.ext.clone();
                wrap_err(Self::and_b(ltype, rtype))
            }
            Terminal::AndV(ref l, ref r) => {
                let ltype = l.ext.clone();
                let rtype = r.ext.clone();
                wrap_err(Self::and_v(ltype, rtype))
            }
            Terminal::OrB(ref l, ref r) => {
                let ltype = l.ext.clone();
                let rtype = r.ext.clone();
                wrap_err(Self::or_b(ltype, rtype))
            }
            Terminal::OrD(ref l, ref r) => {
                let ltype = l.ext.clone();
                let rtype = r.ext.clone();
                wrap_err(Self::or_d(ltype, rtype))
            }
            Terminal::OrC(ref l, ref r) => {
                let ltype = l.ext.clone();
                let rtype = r.ext.clone();
                wrap_err(Self::or_c(ltype, rtype))
            }
            Terminal::OrI(ref l, ref r) => {
                let ltype = l.ext.clone();
                let rtype = r.ext.clone();
                wrap_err(Self::or_i(ltype, rtype))
            }
            Terminal::AndOr(ref a, ref b, ref c) => {
                let atype = a.ext.clone();
                let btype = b.ext.clone();
                let ctype = c.ext.clone();
                wrap_err(Self::and_or(atype, btype, ctype))
            }
            Terminal::Thresh(k, ref subs) => {
                if k == 0 {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::ZeroThreshold,
                    });
                }
                if k > subs.len() {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::OverThreshold(k, subs.len()),
                    });
                }

                let res = Self::threshold(k, subs.len(), |n| Ok(subs[n].ext.clone()));

                res.map_err(|kind| Error {
                    fragment: fragment.clone(),
                    error: kind,
                })
            }
        };
        if let Ok(ref ret) = ret {
            ret.sanity_checks()
        }
        ret
    }
}
