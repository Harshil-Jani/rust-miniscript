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

use bitcoin::absolute::LockTime;
use bitcoin::address::WitnessVersion;
use bitcoin::hashes::{hash160, ripemd160, sha256};
use bitcoin::key::XOnlyPublicKey;
use bitcoin::script::PushBytesBuf;
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash};
use bitcoin::{bip32, psbt, ScriptBuf, Sequence};

use crate::descriptor::{self, Descriptor, DescriptorType, KeyMap};
use crate::miniscript::hash256;
use crate::miniscript::satisfy::{Placeholder, Satisfier, SchnorrSigType};
use crate::prelude::*;
use crate::util::witness_size;
use crate::{DefiniteDescriptorKey, DescriptorPublicKey, Error, MiniscriptKey, ToPublicKey};

/// Trait describing a present/missing lookup table for constructing witness templates
///
/// This trait mirrors the [`Satisfier`] trait with the difference that instead of returning the
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
    pub template: Vec<Placeholder<DefiniteDescriptorKey>>,
    /// The absolute timelock this plan uses
    pub absolute_timelock: Option<LockTime>,
    /// The relative timelock this plan uses
    pub relative_timelock: Option<Sequence>,

    pub(crate) descriptor: Descriptor<DefiniteDescriptorKey>,
}

impl Plan {
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
    ) -> Result<(Vec<Vec<u8>>, ScriptBuf), Error> {
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
                    .into_iter()
                    .fold(Builder::new(), |builder, item| {
                        use core::convert::TryFrom;
                        let bytes = PushBytesBuf::try_from(item)
                            .expect("All the possible placeholders can be made into PushBytesBuf");
                        builder.push_slice(bytes)
                    })
                    .into_script(),
            ),
            DescriptorType::Wpkh
            | DescriptorType::Wsh
            | DescriptorType::WshSortedMulti
            | DescriptorType::Tr => (stack, ScriptBuf::new()),
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
            enum SpendType {
                KeySpend { internal_key: XOnlyPublicKey },
                ScriptSpend { leaf_hash: TapLeafHash },
            }

            #[derive(Default)]
            struct TrDescriptorData {
                tap_script: Option<ScriptBuf>,
                control_block: Option<ControlBlock>,
                spend_type: Option<SpendType>,
                key_origins: BTreeMap<XOnlyPublicKey, bip32::KeySource>,
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

                            match (&data.spend_type, sig_type) {
                                // First encountered schnorr sig, update the `TrDescriptorData` accordingly
                                (None, SchnorrSigType::KeySpend { .. }) => data.spend_type = Some(SpendType::KeySpend { internal_key: raw_pk }),
                                (None, SchnorrSigType::ScriptSpend { leaf_hash }) => data.spend_type = Some(SpendType::ScriptSpend { leaf_hash: *leaf_hash }),

                                // Inconsistent placeholders (should be unreachable with the
                                // current implementation)
                                (Some(SpendType::KeySpend {..}), SchnorrSigType::ScriptSpend { .. }) | (Some(SpendType::ScriptSpend {..}), SchnorrSigType::KeySpend{..}) => unreachable!("Mixed taproot key-spend and script-spend placeholders in the same plan"),

                                _ => {},
                            }

                            for path in pk.full_derivation_paths() {
                                data.key_origins.insert(raw_pk, (pk.master_fingerprint(), path));
                            }
                        }
                        _ => {}
                    }

                    data
                });

            // TODO: TapTree. we need to re-traverse the tree to build it, sigh

            let leaf_hash = match data.spend_type {
                Some(SpendType::KeySpend { internal_key }) => {
                    input.tap_internal_key = Some(internal_key);
                    None
                }
                Some(SpendType::ScriptSpend { leaf_hash }) => Some(leaf_hash),
                _ => None,
            };
            for (pk, key_source) in data.key_origins {
                input
                    .tap_key_origins
                    .entry(pk)
                    .and_modify(|(leaf_hashes, _)| {
                        if let Some(lh) = leaf_hash {
                            if leaf_hashes.iter().find(|&&i| i == lh).is_none() {
                                leaf_hashes.push(lh);
                            }
                        }
                    })
                    .or_insert_with(|| (vec![], key_source));
            }
            if let (Some(tap_script), Some(control_block)) = (data.tap_script, data.control_block) {
                input
                    .tap_scripts
                    .insert(control_block, (tap_script, LeafVersion::TapScript));
            }
        } else {
            for item in &self.template {
                match item {
                    Placeholder::EcdsaSigPk(pk) => {
                        let public_key = pk.to_public_key().inner;
                        let master_fingerprint = pk.master_fingerprint();
                        for derivation_path in pk.full_derivation_paths() {
                            input
                                .bip32_derivation
                                .insert(public_key, (master_fingerprint, derivation_path));
                        }
                    }
                    _ => {}
                }
            }

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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
/// Signatures which a key can produce
///
/// Defaults to `ecdsa=true` and `taproot=TaprootCanSign::default()`
pub struct CanSign {
    /// Whether the key can produce ECDSA signatures
    pub ecdsa: bool,
    /// Whether the key can produce taproot (Schnorr) signatures
    pub taproot: TaprootCanSign,
}

impl Default for CanSign {
    fn default() -> Self {
        CanSign {
            ecdsa: true,
            taproot: TaprootCanSign::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
/// Signatures which a taproot key can produce
///
/// Defaults to `key_spend=true`, `script_spend=Any` and `sighash_default=true`
pub struct TaprootCanSign {
    /// Can produce key spend signatures
    pub key_spend: bool,
    /// Can produce script spend signatures
    pub script_spend: TaprootAvailableLeaves,
    /// Whether `SIGHASH_DEFAULT` will be used to sign
    pub sighash_default: bool,
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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
/// Which taproot leaves the key can sign for
pub enum TaprootAvailableLeaves {
    /// Cannot sign for any leaf
    None,
    /// Can sign for any leaf
    Any,
    /// Can sign only for a specific leaf
    Single(TapLeafHash),
    /// Can sign for multiple leaves
    Many(Vec<TapLeafHash>),
}

impl TaprootAvailableLeaves {
    fn is_available(&self, lh: &TapLeafHash) -> bool {
        use TaprootAvailableLeaves::*;

        match self {
            None => false,
            Any => true,
            Single(v) => v == lh,
            Many(list) => list.contains(lh),
        }
    }
}

/// The Assets we can use to satisfy a particular spending path
#[derive(Debug, Default)]
pub struct Assets {
    /// Keys the user can sign for, and how
    pub keys: HashSet<(DescriptorPublicKey, CanSign)>,
    /// Set of available sha256 preimages
    pub sha256_preimages: HashSet<sha256::Hash>,
    /// Set of available hash256 preimages
    pub hash256_preimages: HashSet<hash256::Hash>,
    /// Set of available ripemd160 preimages
    pub ripemd160_preimages: HashSet<ripemd160::Hash>,
    /// Set of available hash160 preimages
    pub hash160_preimages: HashSet<hash160::Hash>,
    /// Maximum absolute timelock allowed
    pub absolute_timelock: Option<LockTime>,
    /// Maximum relative timelock allowed
    pub relative_timelock: Option<Sequence>,
}

impl Assets {
    pub(crate) fn has_ecdsa_key(&self, pk: &DefiniteDescriptorKey) -> bool {
        self.keys
            .iter()
            .any(|(key, can_sign)| can_sign.ecdsa && key.is_parent(pk).is_some())
    }

    pub(crate) fn has_taproot_internal_key(&self, pk: &DefiniteDescriptorKey) -> Option<usize> {
        self.keys.iter().find_map(|(key, can_sign)| {
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
        self.keys.iter().find_map(|(key, can_sign)| {
            if !can_sign.taproot.script_spend.is_available(tap_leaf_hash)
                || !key.is_parent(pk).is_some()
            {
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
                .map(|pk| (pk, CanSign::default()))
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
