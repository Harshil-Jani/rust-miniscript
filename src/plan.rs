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
use bitcoin::util::taproot::{ControlBlock, LeafVersion, TapLeafHash};
use bitcoin::util::{bip32, psbt};
use bitcoin::{LockTime, Script, Sequence, XOnlyPublicKey};

use crate::descriptor::{self, Descriptor, DescriptorType, KeyMap};
use crate::miniscript::context::SigType;
use crate::miniscript::hash256;
use crate::miniscript::satisfy::{Placeholder, Satisfier, SchnorrSigType};
use crate::prelude::*;
use crate::util::witness_size;
use crate::{
    DefiniteDescriptorKey, DescriptorPublicKey, Error, MiniscriptKey, ScriptContext, ToPublicKey,
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

    /// Lookup the tap key spend sig and return its size
    fn lookup_tap_key_spend_sig(&self, _: &Pk) -> Option<usize> {
        None
    }

    /// Given a public key and a associated leaf hash, look up an schnorr signature with that key
    /// and return its size
    fn lookup_tap_leaf_script_sig(&self, _: &Pk, _: &TapLeafHash) -> Option<usize> {
        None
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
    ///
    /// Returns the signature size if present
    fn lookup_raw_pkh_tap_leaf_script_sig(
        &self,
        _: &(hash160::Hash, TapLeafHash),
    ) -> Option<usize> {
        None
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
    impl_log_method!(lookup_tap_key_spend_sig, pk: &DefiniteDescriptorKey, -> Option<usize>);
    impl_log_method!(lookup_tap_leaf_script_sig, pk: &DefiniteDescriptorKey, leaf_hash: &TapLeafHash, -> Option<usize>);
    impl_log_method!(lookup_raw_pkh_pk, <Ctx: ScriptContext> hash: &hash160::Hash, -> Option<usize>);
    impl_log_method!(lookup_raw_pkh_x_only_pk, hash: &hash160::Hash, -> bool);
    impl_log_method!(lookup_raw_pkh_ecdsa_sig, <Ctx: ScriptContext> hash: &hash160::Hash, -> Option<usize>);
    impl_log_method!(lookup_raw_pkh_tap_leaf_script_sig, hash: &(hash160::Hash, TapLeafHash), -> Option<usize>);
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

    fn lookup_tap_key_spend_sig(&self, _: &Pk) -> Option<usize> {
        Satisfier::lookup_tap_key_spend_sig(self).map(|s| s.to_vec().len())
    }

    fn lookup_tap_leaf_script_sig(&self, pk: &Pk, leaf_hash: &TapLeafHash) -> Option<usize> {
        Satisfier::lookup_tap_leaf_script_sig(self, pk, leaf_hash).map(|s| s.to_vec().len())
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

    fn lookup_raw_pkh_tap_leaf_script_sig(
        &self,
        hash: &(hash160::Hash, TapLeafHash),
    ) -> Option<usize> {
        Satisfier::lookup_raw_pkh_tap_leaf_script_sig(self, hash).map(|(_, s)| s.to_vec().len())
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

/// Enum defining the type of signature required
#[derive(Debug, Clone)]
pub enum RequiredSig<'pk, Pk: MiniscriptKey> {
    /// ECDSA (legacy or Segwit-v0) signature
    Ecdsa(&'pk Pk),
    /// Schnorr key-spend signature (BIP-341)
    SchnorrTapKey(&'pk Pk),
    /// Schnorr script-spend signature (BIP-341)
    SchnorrTapScript(&'pk Pk, &'pk TapLeafHash),
}

/// Enum defining the type of preimage required
#[derive(Debug, Clone)]
pub enum RequiredPreimage<'h, Pk: MiniscriptKey> {
    /// HASH160 preimage
    Hash160(&'h <Pk as MiniscriptKey>::Hash160),
    /// RIPEMD160 preimage
    Ripemd160(&'h <Pk as MiniscriptKey>::Ripemd160),
    /// HASH256 preimage
    Hash256(&'h <Pk as MiniscriptKey>::Hash256),
    /// SHA256 preimage
    Sha256(&'h <Pk as MiniscriptKey>::Sha256),
}

/// Representation of a particular spending path on a descriptor. Contains the witness template
/// and the timelocks needed for satisfying the plan.
/// Calling `get_plan` on a Descriptor will return this structure,
/// containing the cheapest spending path possible (considering the `Assets` given)
#[derive(Debug, Clone)]
pub struct Plan<'d> {
    /// This plan's witness template
    pub template: Vec<Placeholder<DefiniteDescriptorKey>>,
    /// The absolute timelock this plan uses
    pub absolute_timelock: Option<LockTime>,
    /// The relative timelock this plan uses
    pub relative_timelock: Option<Sequence>,

    pub(crate) descriptor: &'d Descriptor<DefiniteDescriptorKey>,
}

impl<'d> Plan<'d> {
    /// Returns the witness version
    pub fn witness_version(&self) -> Option<WitnessVersion> {
        self.descriptor.desc_type().segwit_version()
    }

    /// The weight, in witness units, needed for satisfying this plan (includes both
    /// the script sig weight and the witness weight)
    pub fn satisfaction_weight(&self) -> usize {
        self.witness_size() + self.scriptsig_size() * 4
    }

    /// The size in bytes of the script sig that satisfies this plan
    pub fn scriptsig_size(&self) -> usize {
        match (
            self.descriptor.desc_type().segwit_version(),
            self.descriptor.desc_type(),
        ) {
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
        if let Some(_) = self.descriptor.desc_type().segwit_version() {
            witness_size(self.template.as_ref())
        } else {
            0 // should be 1 if there's at least one segwit input in the tx, but that's out of
              // scope as we can't possibly know that just by looking at the descriptor
        }
    }

    /// Try creating the final script_sig and witness using a [`Satisfier`]
    pub fn satisfy<Sat: Satisfier<DefiniteDescriptorKey>>(
        &self,
        stfr: &Sat,
    ) -> Result<(Vec<Vec<u8>>, Script), Error> {
        use bitcoin::blockdata::script::Builder;

        let stack = self
            .template
            .iter()
            .map(|placeholder| placeholder.satisfy_self(stfr))
            .collect::<Option<Vec<Vec<u8>>>>()
            .ok_or(Error::CouldNotSatisfy)?;

        Ok(match self.descriptor.desc_type() {
            DescriptorType::Bare
            | DescriptorType::Sh
            | DescriptorType::Pkh
            | DescriptorType::ShSortedMulti => (
                vec![],
                stack
                    .iter()
                    .fold(Builder::new(), |builder, item| builder.push_slice(item))
                    .into_script(),
            ),
            DescriptorType::Wpkh
            | DescriptorType::Wsh
            | DescriptorType::WshSortedMulti
            | DescriptorType::Tr => (stack, Script::new()),
            DescriptorType::ShWsh | DescriptorType::ShWshSortedMulti | DescriptorType::ShWpkh => {
                (stack, self.descriptor.unsigned_script_sig())
            }
        })
    }

    /// Update a PSBT input with the metadata required to complete this plan
    ///
    /// This will only add the metadata for items required to complete this plan. For example, if
    /// there are multiple keys present in the descriptor, only the few used by this plan will be
    /// added to the PSBT.
    pub fn update_psbt_input(&self, input: &mut psbt::Input) {
        if let Descriptor::Tr(tr) = &self.descriptor {
            #[derive(Default)]
            struct TrDescriptorData {
                tap_script: Option<Script>,
                control_block: Option<ControlBlock>,
                internal_key: Option<XOnlyPublicKey>,
                key_origins: BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, bip32::KeySource)>,
            }

            let spend_info = tr.spend_info();
            input.tap_merkle_root = spend_info.merkle_root();

            let data = self
                .template
                .iter()
                .fold(TrDescriptorData::default(), |mut data, item| {
                    match item {
                        Placeholder::TapScript(script) => data.tap_script = Some(script.clone()),
                        Placeholder::TapControlBlock(cb) => data.control_block = Some(cb.clone()),
                        Placeholder::SchnorrSig(pk, sig_type, _) => {
                            let raw_pk = pk.to_x_only_pubkey();

                            let leaf_hash = match sig_type {
                                SchnorrSigType::KeySpend { .. } => {
                                    data.internal_key = Some(raw_pk);
                                    None
                                }
                                SchnorrSigType::ScriptSpend { leaf_hash } => Some(leaf_hash),
                            };

                            data.key_origins
                                .entry(raw_pk)
                                .and_modify(|(tapleaf_hashes, _)| {
                                    if let Some(leaf_hash) = leaf_hash {
                                        tapleaf_hashes.push(*leaf_hash);
                                    }
                                })
                                .or_insert_with(|| {
                                    (
                                        if let Some(lh) = leaf_hash {
                                            vec![*lh]
                                        } else {
                                            vec![]
                                        },
                                        (pk.master_fingerprint(), pk.full_derivation_path()),
                                    )
                                });
                        }
                        _ => {}
                    }

                    data
                });

            // TODO: TapTree. we need to re-traverse the tree to build it, sigh

            input.tap_internal_key = data.internal_key;
            input.tap_key_origins.extend(data.key_origins.into_iter());
            if let (Some(tap_script), Some(control_block)) = (data.tap_script, data.control_block) {
                input
                    .tap_scripts
                    .insert(control_block, (tap_script, LeafVersion::TapScript));
            }

            // Ensure there are no duplicated leaf hashes. This can happen if some of them were
            // already present in the map when this function is called, since this only appends new
            // data to the psbt without checking what's already present.
            for (tapleaf_hashes, _) in input.tap_key_origins.values_mut() {
                tapleaf_hashes.sort();
                tapleaf_hashes.dedup();
            }
        } else {
            input
                .bip32_derivation
                .extend(self.template.iter().filter_map(|item| match item {
                    Placeholder::EcdsaSigPk(pk) => Some((
                        pk.to_public_key().inner,
                        (pk.master_fingerprint(), pk.full_derivation_path()),
                    )),
                    _ => None,
                }));

            match &self.descriptor {
                Descriptor::Bare(_) | Descriptor::Pkh(_) | Descriptor::Wpkh(_) => {}
                Descriptor::Sh(sh) => match sh.as_inner() {
                    descriptor::ShInner::Wsh(wsh) => {
                        input.witness_script = Some(wsh.inner_script());
                        input.redeem_script = Some(wsh.inner_script().to_v0_p2wsh());
                    }
                    descriptor::ShInner::Wpkh(..) => input.redeem_script = Some(sh.inner_script()),
                    descriptor::ShInner::SortedMulti(_) | descriptor::ShInner::Ms(_) => {
                        input.redeem_script = Some(sh.inner_script())
                    }
                },
                Descriptor::Wsh(wsh) => input.witness_script = Some(wsh.inner_script()),
                Descriptor::Tr(_) => unreachable!("Tr is dealt with separately"),
            }
        }
    }
}

#[derive(Debug)]
/// Signatures which a key can produce
///
/// Defaults to `ecdsa=true` and `taproot=TaprootCanSign::default()`
pub struct CanSign {
    /// Whether the key can produce ECDSA signatures
    ecdsa: bool,
    /// Whether the key can produce taproot (Schnorr) signatures
    taproot: TaprootCanSign,
}

impl Default for CanSign {
    fn default() -> Self {
        CanSign {
            ecdsa: true,
            taproot: TaprootCanSign::default(),
        }
    }
}

#[derive(Debug)]
/// Signatures which a taproot key can produce
///
/// Defaults to `key_spend=true`, `script_spend=Any` and `sighash_default=true`
pub struct TaprootCanSign {
    /// Can produce key spend signatures
    key_spend: bool,
    /// Can produce script spend signatures
    script_spend: TaprootAvailableLeaves,
    /// Whether `SIGHASH_DEFAULT` will be used to sign
    sighash_default: bool,
}

impl TaprootCanSign {
    fn sig_len(&self) -> usize {
        match self.sighash_default {
            true => 64,
            false => 65,
        }
    }
}

impl Default for TaprootCanSign {
    fn default() -> Self {
        TaprootCanSign {
            key_spend: true,
            script_spend: TaprootAvailableLeaves::Any,
            sighash_default: true,
        }
    }
}

#[derive(Debug)]
/// Which taproot leaves the key can sign for
pub enum TaprootAvailableLeaves {
    /// Cannot sign for any leaf
    None,
    /// Can sign for any leaf
    Any,
    /// Can sign only for a specific leaf
    Single(TapLeafHash),
    /// Can sign for multiple leaves
    Many(HashSet<TapLeafHash>),
}

impl TaprootAvailableLeaves {
    fn is_available(&self, lh: &TapLeafHash) -> bool {
        use TaprootAvailableLeaves::*;

        match self {
            None => false,
            Any => true,
            Single(v) => v == lh,
            Many(set) => set.contains(lh),
        }
    }
}

/// The Assets we can use to satisfy a particular spending path
#[derive(Debug, Default)]
pub struct Assets {
    keys: HashMap<hash160::Hash, (DescriptorPublicKey, CanSign)>,
    sha256_preimages: HashSet<sha256::Hash>,
    hash256_preimages: HashSet<hash256::Hash>,
    ripemd160_preimages: HashSet<ripemd160::Hash>,
    hash160_preimages: HashSet<hash160::Hash>,
    absolute_timelock: Option<LockTime>,
    relative_timelock: Option<Sequence>,
}

impl Assets {
    pub(crate) fn has_ecdsa_key(&self, pk: &DefiniteDescriptorKey) -> bool {
        self.keys
            .values()
            .any(|(key, can_sign)| can_sign.ecdsa && key.is_parent(pk).is_some())
    }

    pub(crate) fn has_taproot_internal_key(&self, pk: &DefiniteDescriptorKey) -> Option<usize> {
        self.keys.values().find_map(|(key, can_sign)| {
            if !can_sign.taproot.key_spend || !key.is_parent(pk).is_some() {
                None
            } else {
                Some(can_sign.taproot.sig_len())
            }
        })
    }

    pub(crate) fn has_taproot_script_key(
        &self,
        pk: &DefiniteDescriptorKey,
        tap_leaf_hash: &TapLeafHash,
    ) -> Option<usize> {
        self.keys.values().find_map(|(key, can_sign)| {
            if !can_sign.taproot.script_spend.is_available(tap_leaf_hash)
                || !key.is_parent(pk).is_some()
            {
                None
            } else {
                Some(can_sign.taproot.sig_len())
            }
        })
    }

    pub(crate) fn has_taproot_script_key_hash(
        &self,
        key: &hash160::Hash,
        tap_leaf_hash: &TapLeafHash,
    ) -> Option<usize> {
        self.keys.get(key).and_then(|(_, can_sign)| {
            if !can_sign.taproot.script_spend.is_available(tap_leaf_hash) {
                None
            } else {
                Some(can_sign.taproot.sig_len())
            }
        })
    }
}

impl AssetProvider<DefiniteDescriptorKey> for Assets {
    fn lookup_ecdsa_sig(&self, pk: &DefiniteDescriptorKey) -> bool {
        self.has_ecdsa_key(pk)
    }

    fn lookup_tap_key_spend_sig(&self, pk: &DefiniteDescriptorKey) -> Option<usize> {
        self.has_taproot_internal_key(pk)
    }

    fn lookup_tap_leaf_script_sig(
        &self,
        pk: &DefiniteDescriptorKey,
        tap_leaf_hash: &TapLeafHash,
    ) -> Option<usize> {
        self.has_taproot_script_key(pk, tap_leaf_hash)
    }

    fn lookup_raw_pkh_pk<Ctx: ScriptContext>(&self, hash: &hash160::Hash) -> Option<usize> {
        self.keys.get(hash).map(|(pk, _)| Ctx::pk_len(pk))
    }

    fn lookup_raw_pkh_ecdsa_sig<Ctx: ScriptContext>(&self, hash: &hash160::Hash) -> Option<usize> {
        self.keys.get(hash).map(|(pk, _)| Ctx::pk_len(pk))
    }

    fn lookup_raw_pkh_tap_leaf_script_sig(
        &self,
        (key, lh): &(hash160::Hash, TapLeafHash),
    ) -> Option<usize> {
        self.has_taproot_script_key_hash(key, lh)
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
                        (pk, CanSign::default()),
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
        self.sha256_preimages.extend(b.sha256_preimages.into_iter());
        self.hash256_preimages
            .extend(b.hash256_preimages.into_iter());
        self.ripemd160_preimages
            .extend(b.ripemd160_preimages.into_iter());
        self.hash160_preimages
            .extend(b.hash160_preimages.into_iter());

        self.relative_timelock = b.relative_timelock.or(self.relative_timelock);
        self.absolute_timelock = b.absolute_timelock.or(self.absolute_timelock);
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use bitcoin::util::bip32::ExtendedPubKey;
    use bitcoin::{LockTime, Sequence};

    use super::*;
    use crate::*;

    fn test_inner(
        desc: &str,
        keys: Vec<DescriptorPublicKey>,
        hashes: Vec<hash160::Hash>,
        // [ (key_indexes, hash_indexes, older, after, expected) ]
        tests: Vec<(
            Vec<usize>,
            Vec<usize>,
            Option<Sequence>,
            Option<LockTime>,
            Option<usize>,
        )>,
    ) {
        let desc = Descriptor::<DefiniteDescriptorKey>::from_str(&desc).unwrap();

        for (key_indexes, hash_indexes, older, after, expected) in tests {
            let mut assets = Assets::new();
            if let Some(seq) = older {
                assets = assets.older(seq);
            }
            if let Some(locktime) = after {
                assets = assets.after(locktime);
            }
            for ki in key_indexes {
                assets = assets.add(keys[ki].clone());
            }
            for hi in hash_indexes {
                assets = assets.add(hashes[hi].clone());
            }

            let result = desc.get_plan(&assets);
            assert_eq!(
                result.as_ref().map(|plan| plan.satisfaction_weight()),
                expected,
                "{:#?}",
                result
            );
        }
    }

    #[test]
    fn test_or() {
        let keys = vec![
            DescriptorPublicKey::from_str(
                "02c2fd50ceae468857bb7eb32ae9cd4083e6c7e42fbbec179d81134b3e3830586c",
            )
            .unwrap(),
            DescriptorPublicKey::from_str(
                "0257f4a2816338436cccabc43aa724cf6e69e43e84c3c8a305212761389dd73a8a",
            )
            .unwrap(),
        ];
        let hashes = vec![];
        let desc = format!("wsh(t:or_c(pk({}),v:pkh({})))", keys[0], keys[1]);

        // expected weight: 4 (scriptSig len) + 1 (witness len) + 73 (sig)
        let tests = vec![
            (vec![], vec![], None, None, None),
            (vec![0], vec![], None, None, Some(4 + 1 + 73)),
            (vec![0, 1], vec![], None, None, Some(4 + 1 + 73)),
        ];

        test_inner(&desc, keys, hashes, tests);
    }

    #[test]
    fn test_and() {
        let keys = vec![
            DescriptorPublicKey::from_str(
                "02c2fd50ceae468857bb7eb32ae9cd4083e6c7e42fbbec179d81134b3e3830586c",
            )
            .unwrap(),
            DescriptorPublicKey::from_str(
                "0257f4a2816338436cccabc43aa724cf6e69e43e84c3c8a305212761389dd73a8a",
            )
            .unwrap(),
        ];
        let hashes = vec![];
        let desc = format!("wsh(and_v(v:pk({}),pk({})))", keys[0], keys[1]);

        // expected weight: 4 (scriptSig len) + 1 (witness len) + 73 (sig) * 2
        let tests = vec![
            (vec![], vec![], None, None, None),
            (vec![0], vec![], None, None, None),
            (vec![0, 1], vec![], None, None, Some(4 + 1 + 73 * 2)),
        ];

        test_inner(&desc, keys, hashes, tests);
    }

    #[test]
    fn test_multi() {
        let keys = vec![
            DescriptorPublicKey::from_str(
                "02c2fd50ceae468857bb7eb32ae9cd4083e6c7e42fbbec179d81134b3e3830586c",
            )
            .unwrap(),
            DescriptorPublicKey::from_str(
                "0257f4a2816338436cccabc43aa724cf6e69e43e84c3c8a305212761389dd73a8a",
            )
            .unwrap(),
            DescriptorPublicKey::from_str(
                "03500a2b48b0f66c8183cc0d6645ab21cc19c7fad8a33ff04d41c3ece54b0bc1c5",
            )
            .unwrap(),
            DescriptorPublicKey::from_str(
                "033ad2d191da4f39512adbaac320cae1f12f298386a4e9d43fd98dec7cf5db2ac9",
            )
            .unwrap(),
        ];
        let hashes = vec![];
        let desc = format!(
            "wsh(multi(3,{},{},{},{}))",
            keys[0], keys[1], keys[2], keys[3]
        );

        let tests = vec![
            (vec![], vec![], None, None, None),
            (vec![0, 1], vec![], None, None, None),
            // expected weight: 4 (scriptSig len) + 1 (witness len) + 73 (sig) * 3 + 1 (dummy push)
            (vec![0, 1, 3], vec![], None, None, Some(4 + 1 + 73 * 3 + 1)),
        ];

        test_inner(&desc, keys, hashes, tests);
    }

    #[test]
    fn test_thresh() {
        let keys = vec![
            DescriptorPublicKey::from_str(
                "02c2fd50ceae468857bb7eb32ae9cd4083e6c7e42fbbec179d81134b3e3830586c",
            )
            .unwrap(),
            DescriptorPublicKey::from_str(
                "0257f4a2816338436cccabc43aa724cf6e69e43e84c3c8a305212761389dd73a8a",
            )
            .unwrap(),
        ];
        let hashes = vec![];
        let desc = format!(
            "wsh(thresh(2,pk({}),s:pk({}),snl:older(144)))",
            keys[0], keys[1]
        );

        let tests = vec![
            (vec![], vec![], None, None, None),
            (vec![], vec![], Some(Sequence(1000)), None, None),
            (vec![0], vec![], None, None, None),
            // expected weight: 4 (scriptSig len) + 1 (witness len) + 73 (sig) + 1 (OP_0) + 1 (OP_ZERO)
            (vec![0], vec![], Some(Sequence(1000)), None, Some(80)),
            // expected weight: 4 (scriptSig len) + 1 (witness len) + 73 (sig) * 2 + 2 (OP_PUSHBYTE_1 0x01)
            (vec![0, 1], vec![], None, None, Some(153)),
            // expected weight: 4 (scriptSig len) + 1 (witness len) + 73 (sig) + 1 (OP_0) + 1 (OP_ZERO)
            (vec![0, 1], vec![], Some(Sequence(1000)), None, Some(80)),
            // expected weight: 4 (scriptSig len) + 1 (witness len) + 73 (sig) * 2 + 2 (OP_PUSHBYTE_1 0x01)
            (
                vec![0, 1],
                vec![],
                Some(Sequence::from_512_second_intervals(10)),
                None,
                Some(153),
            ), // incompatible timelock
        ];

        test_inner(&desc, keys.clone(), hashes.clone(), tests);

        let desc = format!(
            "wsh(thresh(2,pk({}),s:pk({}),snl:after(144)))",
            keys[0], keys[1]
        );

        let tests = vec![
            // expected weight: 4 (scriptSig len) + 1 (witness len) + 73 (sig) + 1 (OP_0) + 1 (OP_ZERO)
            (
                vec![0],
                vec![],
                None,
                Some(LockTime::from_height(1000).unwrap()),
                Some(80),
            ),
            // expected weight: 4 (scriptSig len) + 1 (witness len) + 73 (sig) * 2 + 2 (OP_PUSHBYTE_1 0x01)
            (
                vec![0, 1],
                vec![],
                None,
                Some(LockTime::from_time(500_001_000).unwrap()),
                Some(153),
            ), // incompatible timelock
        ];

        test_inner(&desc, keys, hashes, tests);
    }

    #[test]
    fn test_taproot() {
        let keys = vec![
            DescriptorPublicKey::from_str(
                "02c2fd50ceae468857bb7eb32ae9cd4083e6c7e42fbbec179d81134b3e3830586c",
            )
            .unwrap(),
            DescriptorPublicKey::from_str(
                "0257f4a2816338436cccabc43aa724cf6e69e43e84c3c8a305212761389dd73a8a",
            )
            .unwrap(),
            DescriptorPublicKey::from_str(
                "03500a2b48b0f66c8183cc0d6645ab21cc19c7fad8a33ff04d41c3ece54b0bc1c5",
            )
            .unwrap(),
            DescriptorPublicKey::from_str(
                "033ad2d191da4f39512adbaac320cae1f12f298386a4e9d43fd98dec7cf5db2ac9",
            )
            .unwrap(),
            DescriptorPublicKey::from_str(
                "023fc33527afab09fa97135f2180bcd22ce637b1d2fbcb2db748b1f2c33f45b2b4",
            )
            .unwrap(),
        ];
        let hashes = vec![];
        //    .
        //   / \
        //  .   .
        //  A  / \
        //    .   .
        //    B   C
        //  where A = pk(key1)
        //        B = multi(1, key2, key3)
        //        C = and(key4, after(10))
        let desc = format!(
            "tr({},{{pk({}),{{multi_a(1,{},{}),and_v(v:pk({}),after(10))}}}})",
            keys[0], keys[1], keys[2], keys[3], keys[4]
        );

        // expected weight: 4 (scriptSig len) + 1 (witness len) + 1 (OP_PUSH) + 64 (sig)
        let internal_key_sat_weight = Some(70);
        // expected weight: 4 (scriptSig len) + 1 (witness len) + 1 (OP_PUSH) + 64 (sig)
        // + 34 [script: 1 (OP_PUSHBYTES_32) + 32 (key) + 1 (OP_CHECKSIG)]
        // + 65 [control block: 1 (control byte) + 32 (internal key) + 32 (hash BC)]
        let first_leaf_sat_weight = Some(169);
        // expected weight: 4 (scriptSig len) + 1 (witness len) + 1 (OP_PUSH) + 64 (sig)
        // + 1 (OP_ZERO)
        // + 70 [script: 1 (OP_PUSHBYTES_32) + 32 (key) + 1 (OP_CHECKSIG)
        //       + 1 (OP_PUSHBYTES_32) + 32 (key) + 1 (OP_CHECKSIGADD)
        //       + 1 (OP_PUSHNUM1) + 1 (OP_NUMEQUAL)]
        // + 97 [control block: 1 (control byte) + 32 (internal key) + 32 (hash C) + 32 (hash
        //       A)]
        let second_leaf_sat_weight = Some(238);
        // expected weight: 4 (scriptSig len) + 1 (witness len) + 1 (OP_PUSH) + 64 (sig)
        // + 36 [script: 1 (OP_PUSHBYTES_32) + 32 (key) + 1 (OP_CHECKSIGVERIFY)
        //       + 1 (OP_PUSHNUM_10) + 1 (OP_CLTV)]
        // + 97 [control block: 1 (control byte) + 32 (internal key) + 32 (hash B) + 32 (hash
        //       A)]
        let third_leaf_sat_weight = Some(203);

        let tests = vec![
            // Don't give assets
            (vec![], vec![], None, None, None),
            // Spend with internal key
            (vec![0], vec![], None, None, internal_key_sat_weight),
            // Spend with first leaf (single pk)
            (vec![1], vec![], None, None, first_leaf_sat_weight),
            // Spend with second leaf (1of2)
            (vec![2], vec![], None, None, second_leaf_sat_weight),
            // Spend with second leaf (1of2)
            (vec![2, 3], vec![], None, None, second_leaf_sat_weight),
            // Spend with third leaf (key + timelock)
            (
                vec![4],
                vec![],
                None,
                Some(LockTime::from_height(10).unwrap()),
                third_leaf_sat_weight,
            ),
            // Spend with third leaf (key + timelock),
            // but timelock is too low (=impossible)
            (
                vec![4],
                vec![],
                None,
                Some(LockTime::from_height(9).unwrap()),
                None,
            ),
            // Spend with third leaf (key + timelock),
            // but timelock is in the wrong unit (=impossible)
            (
                vec![4],
                vec![],
                None,
                Some(LockTime::from_time(1296000000).unwrap()),
                None,
            ),
            // Spend with third leaf (key + timelock),
            // but don't give the timelock (=impossible)
            (vec![4], vec![], None, None, None),
            // Give all the keys (internal key will be used, as it's cheaper)
            (
                vec![0, 1, 2, 3, 4],
                vec![],
                None,
                None,
                internal_key_sat_weight,
            ),
            // Give all the leaf keys (uses 1st leaf)
            (vec![1, 2, 3, 4], vec![], None, None, first_leaf_sat_weight),
            // Give 2nd+3rd leaf without timelock (uses 2nd leaf)
            (vec![2, 3, 4], vec![], None, None, second_leaf_sat_weight),
            // Give 2nd+3rd leaf with timelock (uses 3rd leaf)
            (
                vec![2, 3, 4],
                vec![],
                None,
                Some(LockTime::from_consensus(11)),
                third_leaf_sat_weight,
            ),
        ];

        test_inner(&desc, keys, hashes, tests);
    }

    #[test]
    fn test_hash() {
        let keys = vec![DescriptorPublicKey::from_str(
            "02c2fd50ceae468857bb7eb32ae9cd4083e6c7e42fbbec179d81134b3e3830586c",
        )
        .unwrap()];
        let hashes = vec![hash160::Hash::from_slice(&vec![0; 20]).unwrap()];
        let desc = format!("wsh(and_v(v:pk({}),hash160({})))", keys[0], hashes[0]);

        let tests = vec![
            // No assets, impossible
            (vec![], vec![], None, None, None),
            // Only key, impossible
            (vec![0], vec![], None, None, None),
            // Only hash, impossible
            (vec![], vec![0], None, None, None),
            // Key + hash
            // expected weight: 4 (scriptSig len) + 1 (witness len) + 73 (sig) + 1 (OP_PUSH) + 32 (preimage)
            (vec![0], vec![0], None, None, Some(111)),
        ];

        test_inner(&desc, keys, hashes, tests);
    }

    #[test]
    fn test_plan_update_psbt_tr() {
        // keys taken from: https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki#Specifications
        let root_xpub = ExtendedPubKey::from_str("xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8").unwrap();
        let fingerprint = root_xpub.fingerprint();
        let xpub = format!("[{}/86'/0'/0']xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ", fingerprint);
        let desc = format!(
            "tr({}/0/0,{{pkh({}/0/1),multi_a(2,{}/1/0,{}/1/1)}})",
            xpub, xpub, xpub, xpub
        );

        let desc = Descriptor::from_str(&desc).unwrap();

        let internal_key = DescriptorPublicKey::from_str(&format!("{}/0/0", xpub)).unwrap();
        let first_branch = DescriptorPublicKey::from_str(&format!("{}/0/1", xpub)).unwrap();
        let second_branch = DescriptorPublicKey::from_str(&format!("{}/1/*", xpub)).unwrap(); // Note this is a wildcard key, so it can sign for the whole multi_a

        let mut psbt_input = bitcoin::util::psbt::Input::default();
        let assets = Assets::new().add(internal_key);
        desc.get_plan(&assets)
            .unwrap()
            .update_psbt_input(&mut psbt_input);
        assert!(
            psbt_input.tap_internal_key.is_some(),
            "Internal key is missing"
        );
        assert!(
            psbt_input.tap_merkle_root.is_some(),
            "Merkle root is missing"
        );
        assert_eq!(
            psbt_input.tap_key_origins.len(),
            1,
            "Unexpected number of tap_key_origins"
        );
        assert_eq!(
            psbt_input.tap_scripts.len(),
            0,
            "Unexpected number of tap_scripts"
        );

        let mut psbt_input = bitcoin::util::psbt::Input::default();
        let assets = Assets::new().add(first_branch);
        desc.get_plan(&assets)
            .unwrap()
            .update_psbt_input(&mut psbt_input);
        assert!(
            psbt_input.tap_internal_key.is_none(),
            "Internal key is present"
        );
        assert!(
            psbt_input.tap_merkle_root.is_some(),
            "Merkle root is missing"
        );
        assert_eq!(
            psbt_input.tap_key_origins.len(),
            1,
            "Unexpected number of tap_key_origins"
        );
        assert_eq!(
            psbt_input.tap_scripts.len(),
            1,
            "Unexpected number of tap_scripts"
        );

        let mut psbt_input = bitcoin::util::psbt::Input::default();
        let assets = Assets::new().add(second_branch);
        desc.get_plan(&assets)
            .unwrap()
            .update_psbt_input(&mut psbt_input);
        assert!(
            psbt_input.tap_internal_key.is_none(),
            "Internal key is present"
        );
        assert!(
            psbt_input.tap_merkle_root.is_some(),
            "Merkle root is missing"
        );
        assert_eq!(
            psbt_input.tap_key_origins.len(),
            2,
            "Unexpected number of tap_key_origins"
        );
        assert_eq!(
            psbt_input.tap_scripts.len(),
            1,
            "Unexpected number of tap_scripts"
        );
    }

    #[test]
    fn test_plan_update_psbt_segwit() {
        // keys taken from: https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki#Specifications
        let root_xpub = ExtendedPubKey::from_str("xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8").unwrap();
        let fingerprint = root_xpub.fingerprint();
        let xpub = format!("[{}/86'/0'/0']xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ", fingerprint);
        let desc = format!("wsh(multi(2,{}/1/0,{}/1/1))", xpub, xpub);

        let desc = Descriptor::from_str(&desc).unwrap();

        let asset_key = DescriptorPublicKey::from_str(&format!("{}/1/*", xpub)).unwrap(); // Note this is a wildcard key, so it can sign for the whole multi

        let mut psbt_input = bitcoin::util::psbt::Input::default();
        let assets = Assets::new().add(asset_key);
        desc.get_plan(&assets)
            .unwrap()
            .update_psbt_input(&mut psbt_input);
        assert!(
            psbt_input.witness_script.is_some(),
            "Witness script missing"
        );
        assert!(psbt_input.redeem_script.is_none(), "Redeem script present");
        assert_eq!(
            psbt_input.bip32_derivation.len(),
            2,
            "Unexpected number of bip32_derivation"
        );
    }
}
