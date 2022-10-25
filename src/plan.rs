// Miniscript
// Written in 2022 by rust-miniscript developers
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//! A spending plan or *plan* for short is a representation of a particular spending path on a
//! descriptor. This allows us to analayze a choice of spending path without producing any
//! signatures or other witness data for it.
//!
//! To make a plan you provide the descriptor with "assets" like which keys you are able to use, hash
//! pre-images you have access to, absolute/relative timelock constraints etc.
//!
//! Once you've got a plan it can tell you its expected satisfaction weight which can be useful for
//! doing coin selection. Furthermore it provides which subset of those keys and hash pre-images you
//! will actually need as well as what locktime or sequence number you need to set.
//!
//! Once you've obstained signatures, hash pre-images etc required by the plan, it can create a
//! witness/script_sig for the input.

use core::cmp::Ordering;
use core::iter::FromIterator;

use bitcoin::hashes::{hash160, ripemd160, sha256};
use bitcoin::util::address::WitnessVersion;
use bitcoin::util::taproot::TapLeafHash;
use bitcoin::{LockTime, Sequence};

use crate::descriptor::{DescriptorType, KeyMap};
use crate::miniscript::context::SigType;
use crate::miniscript::hash256;
use crate::miniscript::satisfy::{Placeholder, Satisfier, WitnessTemplate};
use crate::prelude::*;
use crate::util::witness_size;
use crate::{
    DefiniteDescriptorKey, DescriptorPublicKey, MiniscriptKey, ScriptContext, ToPublicKey,
};

/// Trait describing a present/missing lookup table for constructing witness templates
///
/// This trait mirrors the [`Satisfier`] trait with the difference that instad of returning the
/// item if it's present, it only returns a boolean to indicate its presence.
///
/// This trait is automatically implemented for every type that is also a satisfier, and simply
/// proxies the queries to the satisfier and returns whether an item is available or not.
///
/// All the methods have a default implementation that returns `false`.
pub trait AssetProvider<Pk: MiniscriptKey> {
    /// Given a public key, look up an ECDSA signature with that key
    fn lookup_ecdsa_sig(&self, _: &Pk) -> bool {
        false
    }

    /// Lookup the tap key spend sig
    fn lookup_tap_key_spend_sig(&self, _: &Pk) -> bool {
        false
    }

    /// Given a public key and a associated leaf hash, look up an schnorr signature with that key
    fn lookup_tap_leaf_script_sig(&self, _: &Pk, _: &TapLeafHash) -> bool {
        false
    }

    /// Given a raw `Pkh`, lookup corresponding `Pk`. If present, return its lenght.
    fn lookup_raw_pkh_pk<Ctx: ScriptContext>(&self, _: &hash160::Hash) -> Option<usize> {
        None
    }

    /// Given a raw `Pkh`, lookup corresponding [`bitcoin::XOnlyPublicKey`].
    fn lookup_raw_pkh_x_only_pk(&self, _: &hash160::Hash) -> bool {
        false
    }

    /// Given a keyhash, look up the EC signature and the associated key. If present,
    /// return the key lenght.
    /// Even if signatures for public key Hashes are not available, the users
    /// can use this map to provide pkh -> pk mapping which can be useful
    /// for dissatisfying pkh.
    fn lookup_raw_pkh_ecdsa_sig<Ctx: ScriptContext>(&self, _: &hash160::Hash) -> Option<usize> {
        None
    }

    /// Given a keyhash, look up the schnorr signature and the associated key
    /// Even if signatures for public key Hashes are not available, the users
    /// can use this map to provide pkh -> pk mapping which can be useful
    /// for dissatisfying pkh.
    fn lookup_raw_pkh_tap_leaf_script_sig(&self, _: &(hash160::Hash, TapLeafHash)) -> bool {
        false
    }

    /// Given a SHA256 hash, look up its preimage
    fn lookup_sha256(&self, _: &Pk::Sha256) -> bool {
        false
    }

    /// Given a HASH256 hash, look up its preimage
    fn lookup_hash256(&self, _: &Pk::Hash256) -> bool {
        false
    }

    /// Given a RIPEMD160 hash, look up its preimage
    fn lookup_ripemd160(&self, _: &Pk::Ripemd160) -> bool {
        false
    }

    /// Given a HASH160 hash, look up its preimage
    fn lookup_hash160(&self, _: &Pk::Hash160) -> bool {
        false
    }

    /// Assert whether a relative locktime is satisfied
    fn check_older(&self, _: Sequence) -> bool {
        false
    }

    /// Assert whether an absolute locktime is satisfied
    fn check_after(&self, _: LockTime) -> bool {
        false
    }
}

/// Wrapper around [`Assets`] that logs every query and value returned
#[cfg(feature = "std")]
pub struct LoggerAssetProvider(Assets);

#[cfg(feature = "std")]
macro_rules! impl_log_method {
    ( $name:ident, $( <$ctx:ident: ScriptContext > )? $( $arg:ident : $ty:ty, )* -> $ret_ty:ty ) => {
        fn $name $( <$ctx: ScriptContext> )? ( &self, $( $arg:$ty ),* ) -> $ret_ty {
            let ret = (self.0).$name $( ::<$ctx> )*( $( $arg ),* );
            dbg!(stringify!( $name ), ( $( $arg ),* ), &ret);

            ret
        }
    }
}

#[cfg(feature = "std")]
impl AssetProvider<DefiniteDescriptorKey> for LoggerAssetProvider {
    impl_log_method!(lookup_ecdsa_sig, pk: &DefiniteDescriptorKey, -> bool);
    impl_log_method!(lookup_tap_key_spend_sig, pk: &DefiniteDescriptorKey, -> bool);
    impl_log_method!(lookup_tap_leaf_script_sig, pk: &DefiniteDescriptorKey, leaf_hash: &TapLeafHash, -> bool);
    impl_log_method!(lookup_raw_pkh_pk, <Ctx: ScriptContext> hash: &hash160::Hash, -> Option<usize>);
    impl_log_method!(lookup_raw_pkh_x_only_pk, hash: &hash160::Hash, -> bool);
    impl_log_method!(lookup_raw_pkh_ecdsa_sig, <Ctx: ScriptContext> hash: &hash160::Hash, -> Option<usize>);
    impl_log_method!(lookup_raw_pkh_tap_leaf_script_sig, hash: &(hash160::Hash, TapLeafHash), -> bool);
    impl_log_method!(lookup_sha256, hash: &sha256::Hash, -> bool);
    impl_log_method!(lookup_hash256, hash: &hash256::Hash, -> bool);
    impl_log_method!(lookup_ripemd160, hash: &ripemd160::Hash, -> bool);
    impl_log_method!(lookup_hash160, hash: &hash160::Hash, -> bool);
    impl_log_method!(check_older, s: Sequence, -> bool);
    impl_log_method!(check_after, t: LockTime, -> bool);
}

impl<T, Pk> AssetProvider<Pk> for T
where
    T: Satisfier<Pk>,
    Pk: MiniscriptKey + ToPublicKey,
{
    fn lookup_ecdsa_sig(&self, pk: &Pk) -> bool {
        Satisfier::lookup_ecdsa_sig(self, pk).is_some()
    }

    fn lookup_tap_key_spend_sig(&self, _: &Pk) -> bool {
        Satisfier::lookup_tap_key_spend_sig(self).is_some()
    }

    fn lookup_tap_leaf_script_sig(&self, pk: &Pk, leaf_hash: &TapLeafHash) -> bool {
        Satisfier::lookup_tap_leaf_script_sig(self, pk, leaf_hash).is_some()
    }

    fn lookup_raw_pkh_pk<Ctx: ScriptContext>(&self, hash: &hash160::Hash) -> Option<usize> {
        Satisfier::lookup_raw_pkh_pk(self, hash).map(|p| Ctx::pk_len(&p))
    }

    fn lookup_raw_pkh_x_only_pk(&self, hash: &hash160::Hash) -> bool {
        Satisfier::lookup_raw_pkh_x_only_pk(self, hash).is_some()
    }

    fn lookup_raw_pkh_ecdsa_sig<Ctx: ScriptContext>(&self, hash: &hash160::Hash) -> Option<usize> {
        Satisfier::lookup_raw_pkh_ecdsa_sig(self, hash).map(|(p, _)| Ctx::pk_len(&p))
    }

    fn lookup_raw_pkh_tap_leaf_script_sig(&self, hash: &(hash160::Hash, TapLeafHash)) -> bool {
        Satisfier::lookup_raw_pkh_tap_leaf_script_sig(self, hash).is_some()
    }

    fn lookup_sha256(&self, hash: &Pk::Sha256) -> bool {
        Satisfier::lookup_sha256(self, hash).is_some()
    }

    fn lookup_hash256(&self, hash: &Pk::Hash256) -> bool {
        Satisfier::lookup_hash256(self, hash).is_some()
    }

    fn lookup_ripemd160(&self, hash: &Pk::Ripemd160) -> bool {
        Satisfier::lookup_ripemd160(self, hash).is_some()
    }

    fn lookup_hash160(&self, hash: &Pk::Hash160) -> bool {
        Satisfier::lookup_hash160(self, hash).is_some()
    }

    fn check_older(&self, s: Sequence) -> bool {
        Satisfier::check_older(self, s)
    }

    fn check_after(&self, l: LockTime) -> bool {
        Satisfier::check_after(self, l)
    }
}

/// Representation of a particular spending path on a descriptor. Contains the witness template
/// and the timelocks needed for satisfying the plan.
/// Calling `get_plan` on a Descriptor will return this structure,
/// containing the cheapest spending path possible (considering the `Assets` given)
#[derive(Debug, Clone)]
pub struct Plan {
    /// This plan's witness template
    pub template: WitnessTemplate<Placeholder<DefiniteDescriptorKey>>,
    /// The absolute timelock this plan uses
    pub absolute_timelock: Option<LockTime>,
    /// The relative timelock this plan uses
    pub relative_timelock: Option<Sequence>,

    pub(crate) desc_type: DescriptorType,
}

impl Plan {
    /// Returns the witness version
    pub fn witness_version(&self) -> Option<WitnessVersion> {
        self.desc_type.segwit_version()
    }

    /// The weight, in witness units, needed for satisfying this plan (includes both
    /// the script sig weight and the witness weight)
    pub fn satisfaction_weight(&self) -> usize {
        self.witness_size() + self.scriptsig_size() * 4
    }

    /// The size in bytes of the script sig that satisfies this plan
    pub fn scriptsig_size(&self) -> usize {
        match (self.desc_type.segwit_version(), self.desc_type) {
            // Entire witness goes in the script_sig
            (None, _) => witness_size(self.template.as_ref()),
            // Taproot doesn't have a "wrapped" version (scriptSig len (1))
            (Some(WitnessVersion::V1), _) => 1,
            // scriptSig len (1) + OP_0 (1) + OP_PUSHBYTES_20 (1) + <pk hash> (20)
            (_, DescriptorType::ShWpkh) => 1 + 1 + 1 + 20,
            // scriptSig len (1) + OP_0 (1) + OP_PUSHBYTES_32 (1) + <script hash> (32)
            (_, DescriptorType::ShWsh) | (_, DescriptorType::ShWshSortedMulti) => 1 + 1 + 1 + 32,
            // Native Segwit v0 (scriptSig len (1))
            __ => 1,
        }
    }

    /// The size in bytes of the witness that satisfies this plan
    pub fn witness_size(&self) -> usize {
        if let Some(_) = self.desc_type.segwit_version() {
            witness_size(self.template.as_ref())
        } else {
            0 // should be 1 if there's at least one segwit input in the tx, but that's out of
              // scope as we can't possibly know that just by looking at the descriptor
        }
    }
}

/// The Assets we can use to satisfy a particular spending path
#[derive(Debug, Default)]
pub struct Assets {
    keys: HashMap<hash160::Hash, DescriptorPublicKey>,
    tap_key_spend_sig: Option<bitcoin::SchnorrSig>,
    ecdsa_signatures: HashMap<DescriptorPublicKey, (bitcoin::EcdsaSig, usize)>,
    schnorr_signatures: HashMap<(DescriptorPublicKey, TapLeafHash), (bitcoin::SchnorrSig, usize)>,
    sha256_preimages: HashSet<sha256::Hash>,
    hash256_preimages: HashSet<hash256::Hash>,
    ripemd160_preimages: HashSet<ripemd160::Hash>,
    hash160_preimages: HashSet<hash160::Hash>,
    absolute_timelock: Option<LockTime>,
    relative_timelock: Option<Sequence>,
}

impl Assets {
    pub(crate) fn has_key(&self, pk: &DefiniteDescriptorKey) -> bool {
        self.keys.values().any(|k| k.is_parent(pk).is_some())
    }

    pub(crate) fn has_ecdsa_sig(&self, pk: &DefiniteDescriptorKey) -> bool {
        self.ecdsa_signatures
            .keys()
            .any(|k| k.is_parent(pk).is_some())
    }

    pub(crate) fn has_schnorr_sig(
        &self,
        pk: &DefiniteDescriptorKey,
        tap_leaf_hash: &TapLeafHash,
    ) -> bool {
        self.schnorr_signatures
            .keys()
            .any(|(k, lh)| tap_leaf_hash == lh && k.is_parent(pk).is_some())
    }
}

impl AssetProvider<DefiniteDescriptorKey> for Assets {
    fn lookup_ecdsa_sig(&self, pk: &DefiniteDescriptorKey) -> bool {
        // Either we have the key to produce the signature, or we already have the signature itself
        self.has_key(pk) || self.has_ecdsa_sig(pk)
    }

    fn lookup_tap_key_spend_sig(&self, pk: &DefiniteDescriptorKey) -> bool {
        // Either we have the key to produce the signature, or we already have the signature itself
        self.has_key(pk) || self.tap_key_spend_sig.is_some()
    }

    fn lookup_tap_leaf_script_sig(
        &self,
        pk: &DefiniteDescriptorKey,
        tap_leaf_hash: &TapLeafHash,
    ) -> bool {
        // Either we have the key to produce the signature, or we already have the signature itself
        self.has_key(pk) || self.has_schnorr_sig(pk, tap_leaf_hash)
    }

    fn lookup_raw_pkh_pk<Ctx: ScriptContext>(&self, hash: &hash160::Hash) -> Option<usize> {
        self.keys.get(hash).map(|p| Ctx::pk_len(p))
    }

    fn lookup_raw_pkh_ecdsa_sig<Ctx: ScriptContext>(&self, hash: &hash160::Hash) -> Option<usize> {
        self.keys.get(hash).map(|p| Ctx::pk_len(p))
    }

    fn lookup_raw_pkh_tap_leaf_script_sig(&self, hash: &(hash160::Hash, TapLeafHash)) -> bool {
        self.keys.get(&hash.0).is_some()
    }

    fn lookup_sha256(&self, hash: &sha256::Hash) -> bool {
        self.sha256_preimages.contains(hash)
    }

    fn lookup_hash256(&self, hash: &hash256::Hash) -> bool {
        self.hash256_preimages.contains(hash)
    }

    fn lookup_ripemd160(&self, hash: &ripemd160::Hash) -> bool {
        self.ripemd160_preimages.contains(hash)
    }

    fn lookup_hash160(&self, hash: &hash160::Hash) -> bool {
        self.hash160_preimages.contains(hash)
    }

    fn check_older(&self, s: Sequence) -> bool {
        if let Some(rt) = &self.relative_timelock {
            return rt.is_relative_lock_time()
                && rt.is_height_locked() == s.is_height_locked()
                && s <= *rt;
        }

        false
    }

    fn check_after(&self, l: LockTime) -> bool {
        if let Some(at) = &self.absolute_timelock {
            let cmp = l.partial_cmp(at);
            return cmp == Some(Ordering::Less) || cmp == Some(Ordering::Equal);
        }

        false
    }
}

impl FromIterator<DescriptorPublicKey> for Assets {
    fn from_iter<I: IntoIterator<Item = DescriptorPublicKey>>(iter: I) -> Self {
        Assets {
            keys: iter
                .into_iter()
                .map(|pk| {
                    (
                        pk.clone()
                            .at_derivation_index(0)
                            .to_pubkeyhash(SigType::Ecdsa),
                        pk,
                    )
                })
                .collect(),
            ..Default::default()
        }
    }
}

/// Conversion into a `Assets`
pub trait IntoAssets {
    /// Convert `self` into a `Assets` struct
    fn into_assets(self) -> Assets;
}

impl IntoAssets for KeyMap {
    fn into_assets(mut self) -> Assets {
        Assets::from_iter(self.drain().map(|(k, _)| k))
    }
}

impl IntoAssets for DescriptorPublicKey {
    fn into_assets(self) -> Assets {
        vec![self].into_assets()
    }
}

impl IntoAssets for Vec<DescriptorPublicKey> {
    fn into_assets(self) -> Assets {
        Assets::from_iter(self.into_iter())
    }
}

impl IntoAssets for sha256::Hash {
    fn into_assets(self) -> Assets {
        Assets {
            sha256_preimages: vec![self].into_iter().collect(),
            ..Default::default()
        }
    }
}

impl IntoAssets for hash256::Hash {
    fn into_assets(self) -> Assets {
        Assets {
            hash256_preimages: vec![self].into_iter().collect(),
            ..Default::default()
        }
    }
}

impl IntoAssets for ripemd160::Hash {
    fn into_assets(self) -> Assets {
        Assets {
            ripemd160_preimages: vec![self].into_iter().collect(),
            ..Default::default()
        }
    }
}

impl IntoAssets for hash160::Hash {
    fn into_assets(self) -> Assets {
        Assets {
            hash160_preimages: vec![self].into_iter().collect(),
            ..Default::default()
        }
    }
}

impl IntoAssets for Assets {
    fn into_assets(self) -> Assets {
        self
    }
}

impl Assets {
    /// Contruct an empty instance
    pub fn new() -> Self {
        Self::default()
    }

    /// Add some assets
    pub fn add<A: IntoAssets>(mut self, asset: A) -> Self {
        self.append(asset.into_assets());
        self
    }

    /// Set the maximum relative timelock allowed
    pub fn older(mut self, seq: Sequence) -> Self {
        self.relative_timelock = Some(seq);
        self
    }

    /// Set the maximum absolute timelock allowed
    pub fn after(mut self, lt: LockTime) -> Self {
        self.absolute_timelock = Some(lt);
        self
    }

    fn append(&mut self, b: Self) {
        self.keys.extend(b.keys.into_iter());
        self.ecdsa_signatures.extend(b.ecdsa_signatures.into_iter());
        self.schnorr_signatures
            .extend(b.schnorr_signatures.into_iter());
        self.sha256_preimages.extend(b.sha256_preimages.into_iter());
        self.hash256_preimages
            .extend(b.hash256_preimages.into_iter());
        self.ripemd160_preimages
            .extend(b.ripemd160_preimages.into_iter());
        self.hash160_preimages
            .extend(b.hash160_preimages.into_iter());

        self.tap_key_spend_sig = b.tap_key_spend_sig.or(self.tap_key_spend_sig);
        self.relative_timelock = b.relative_timelock.or(self.relative_timelock);
        self.absolute_timelock = b.absolute_timelock.or(self.absolute_timelock);
    }
}
