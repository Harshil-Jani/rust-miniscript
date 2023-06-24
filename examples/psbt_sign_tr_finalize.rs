use std::collections::BTreeMap;
use std::str::FromStr;

use actual_base64 as base64;
use bitcoin::absolute::Height;
use bitcoin::blockdata::locktime::absolute;
use bitcoin::key::TapTweak;
use bitcoin::psbt::{self, Psbt};
use bitcoin::sighash::{SighashCache};
use bitcoin::{taproot, PrivateKey, ScriptBuf};
use miniscript::bitcoin::consensus::encode::deserialize;
use miniscript::bitcoin::hashes::hex::FromHex;
use miniscript::bitcoin::{
    self, secp256k1, Address, Network, OutPoint, Sequence, Transaction, TxIn, TxOut,
};
use miniscript::psbt::{PsbtExt, PsbtInputExt};
use miniscript::Descriptor;
use secp256k1::{Secp256k1};
fn main() {
    // Defining the descriptor keys required.
    let secp256k1 = secp256k1::Secp256k1::new();
    let keys = vec![
        "036a7ae441409bd40af1b8efba7dbd34b822b9a72566eff10b889b8de13659e343",
        "03b6c8a1a901edf3c5f1cb0e3ffe1f20393435a5d467f435e2858c9ab43d3ca78c",
        "03500a2b48b0f66c8183cc0d6645ab21cc19c7fad8a33ff04d41c3ece54b0bc1c5",
        "033ad2d191da4f39512adbaac320cae1f12f298386a4e9d43fd98dec7cf5db2ac9",
        "023fc33527afab09fa97135f2180bcd22ce637b1d2fbcb2db748b1f2c33f45b2b4",
    ];

    // Defining the taproot descriptor
    let s = format!(
        "tr({},{{pkh({}),{{multi_a(1,{},{}),and_v(v:pk({}),after(10))}}}})",
        keys[0], keys[1], keys[2], keys[3], keys[4]
    );

    let bridge_descriptor = Descriptor::from_str(&s).expect("parse descriptor string");
    assert!(bridge_descriptor.sanity_check().is_ok());

    println!(
        "Bridge pubkey script: {}",
        bridge_descriptor.script_pubkey()
    );
    println!(
        "Bridge address: {}",
        bridge_descriptor.address(Network::Regtest).unwrap()
    );

    // Doing the max satisfaction (i.e Worst Case) analysis for determining the weight of transaction
    println!(
        "Weight for witness satisfaction cost {}",
        bridge_descriptor.max_weight_to_satisfy().unwrap()
    );

    let master_private_key_str = "KxQqtbUnMugSEbKHG3saknvVYux1cgFjFqWzMfwnFhLm8QrGq26v";
    let master_private_key =
        PrivateKey::from_str(master_private_key_str).expect("Can't create private key");
    println!(
        "Master public key: {}",
        master_private_key.public_key(&secp256k1)
    );

    let backup1_private_key_str = "Kwb9oFfPNt6D3Fa9DCF5emRvLyJ3UUvCHnVxp4xf7bWDxWmeVdeH";
    let backup1_private =
        PrivateKey::from_str(backup1_private_key_str).expect("Can't create private key");

    println!(
        "Backup1 public key: {}",
        backup1_private.public_key(&secp256k1)
    );

    let backup2_private_key_str = "cPJFWUKk8sdL7pcDKrmNiWUyqgovimmhaaZ8WwsByDaJ45qLREkh";
    let backup2_private =
        PrivateKey::from_str(backup2_private_key_str).expect("Can't create private key");

    println!(
        "Backup2 public key: {}",
        backup2_private.public_key(&secp256k1)
    );

    let backup3_private_key_str = "cT5cH9UVm81W5QAf5KABXb23RKNSMbMzMx85y6R2mF42L94YwKX6";
    let _backup3_private =
        PrivateKey::from_str(backup3_private_key_str).expect("Can't create private key");

    println!(
        "Backup3 public key: {}",
        _backup3_private.public_key(&secp256k1)
    );

    // Create a spending transaction
    let spend_tx = Transaction {
        version: 2,
        lock_time: absolute::LockTime::Blocks(Height::ZERO),
        input: vec![],
        output: vec![],
    };

    // Creating a PSBT Object
    let mut psbt = Psbt {
        unsigned_tx: spend_tx,
        unknown: BTreeMap::new(),
        proprietary: BTreeMap::new(),
        xpub: BTreeMap::new(),
        version: 0,
        inputs: vec![],
        outputs: vec![],
    };

    let hex_tx = "020000000001018ff27041f3d738f5f84fd5ee62f1c5b36afebfb15f6da0c9d1382ddd0eaaa23c0000000000feffffff02b3884703010000001600142ca3b4e53f17991582d47b15a053b3201891df5200e1f5050000000022512056993be33d12c7df8eead247807e459cdf387f7b6df5784fe16fde157f382dc70247304402207b820860a9d425833f729775880b0ed59dd12b64b9a3d1ab677e27e4d6b370700220576003163f8420fe0b9dc8df726cff22cbc191104a2d4ae4f9dfedb087fcec72012103817e1da42a7701df4db94db8576f0e3605f3ab3701608b7e56f92321e4d8999100000000";
    let mut depo_tx: Transaction = deserialize(&Vec::<u8>::from_hex(hex_tx).unwrap()).unwrap();
    depo_tx.output[1].script_pubkey = bridge_descriptor.script_pubkey();
    let receiver = Address::from_str("bcrt1qsdks5za4t6sevaph6tz9ddfjzvhkdkxe9tfrcy").unwrap();

    let amount = 100000000;

    let (outpoint, witness_utxo) = get_vout(&depo_tx, bridge_descriptor.script_pubkey());

    // Defining the Transaction Input
    let mut txin = TxIn::default();
    txin.previous_output = outpoint;
    txin.sequence = Sequence::from_height(26); //Sequence::MAX; //
    psbt.unsigned_tx.input.push(txin);

    // Defining the Transaction Output
    psbt.unsigned_tx.output.push(TxOut {
        script_pubkey: receiver.payload.script_pubkey(),
        value: amount / 5 - 500,
    });

    psbt.unsigned_tx.output.push(TxOut {
        script_pubkey: bridge_descriptor.script_pubkey(),
        value: amount * 4 / 5,
    });

    bridge_descriptor.max_weight_to_satisfy().unwrap();

    // Creating PSBT Input
    let mut input = psbt::Input::default();
    input
        .update_with_descriptor_unchecked(&bridge_descriptor)
        .unwrap();
    input.witness_utxo = Some(witness_utxo.clone());

    // Push the PSBT Input and declare an PSBT Output Structure
    psbt.inputs.push(input);
    psbt.outputs.push(psbt::Output::default());

    // Use private keys to sign
    let sk1 = master_private_key.inner;
    let sk2 = backup1_private.inner;

    // In the following example we have signed the descriptor with master key
    // which will allow the transaction to be key spend type. 
    // Any other key apart from master key is part of script policies and it
    // will sign for script spend type.
    sign_taproot_psbt(&sk1, &mut psbt, &secp256k1); // Key Spend
    sign_taproot_psbt(&sk2, &mut psbt, &secp256k1); // Script Spend
    
    // Serializing and finalizing the PSBT Transaction
    let serialized = psbt.serialize();
    println!("{}", base64::encode(&serialized));
    psbt.finalize_mut(&secp256k1).unwrap();

    let tx = psbt.extract_tx();
    println!("{}", bitcoin::consensus::encode::serialize_hex(&tx));
}

// Siging the Taproot PSBT Transaction
fn sign_taproot_psbt (
    secret_key: &secp256k1::SecretKey,
    psbt: &mut psbt::Psbt,
    secp256k1: &Secp256k1<secp256k1::All>,
){
    // Creating signing entitites required
    let hash_ty = bitcoin::sighash::TapSighashType::Default;
    let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);
    
    // Defining Keypair for given private key
    let keypair = secp256k1::KeyPair::from_seckey_slice(&secp256k1, secret_key.as_ref()).unwrap();
    
    // Checking if leaf hash exist or not.
    // For Key Spend -> Leaf Hash is None
    // For Script Spend -> Leaf Hash is Some(_)
    let (leaf_hashes, (_, _)) = &psbt.inputs[0].tap_key_origins[&keypair.x_only_public_key().0];
    let leaf_hash = if !leaf_hashes.is_empty() {
        Some(leaf_hashes[0])
    } else {
        None
    };

    let keypair = match leaf_hash {
        None => keypair
            .tap_tweak(&secp256k1, psbt.inputs[0].tap_merkle_root)
            .to_inner(), // tweak for key spend
        Some(_) => keypair, // no tweak for script spend
    };

    // Construct the message to input for schnorr signature
    let msg = psbt
        .sighash_msg(0, &mut sighash_cache, leaf_hash)
        .unwrap()
        .to_secp_msg();
    let sig = secp256k1.sign_schnorr(&msg, &keypair);
    let (pk, _parity) = keypair.x_only_public_key();
    assert!(secp256k1.verify_schnorr(&sig, &msg, &pk).is_ok());

    // Create final signature with corresponding hash type
    let final_signature1 = taproot::Signature {
        hash_ty,
        sig,
    };

    if let Some(lh) = leaf_hash {
        // Script Spend
        psbt.inputs[0]
            .tap_script_sigs
            .insert((pk, lh), final_signature1);
    } else {
        // Key Spend
        psbt.inputs[0].tap_key_sig = Some(final_signature1);
        println!("{:#?}", psbt);
    }
     
}

// Find the Outpoint by spk
fn get_vout(tx: &Transaction, spk: ScriptBuf) -> (OutPoint, TxOut) {
    for (i, txout) in tx.clone().output.into_iter().enumerate() {
        if spk == txout.script_pubkey {
            return (OutPoint::new(tx.txid(), i as u32), txout);
        }
    }
    panic!("Only call get vout on functions which have the expected outpoint");
}