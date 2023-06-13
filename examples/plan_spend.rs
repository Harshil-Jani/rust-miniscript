use std::collections::BTreeMap;
use std::str::FromStr;

use actual_base64 as base64;
use bitcoin::consensus::serialize;
use bitcoin::schnorr::TapTweak;
use bitcoin::util::sighash::SighashCache;
use bitcoin::{schnorr, PackedLockTime, PrivateKey};
use miniscript::bitcoin::consensus::encode::deserialize;
use miniscript::bitcoin::hashes::hex::FromHex;
use miniscript::bitcoin::util::psbt;
use miniscript::bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
use miniscript::bitcoin::{
    self, secp256k1, Address, Network, OutPoint, Script, Sequence, Transaction, TxIn, TxOut,
};
use miniscript::plan::Assets;
use miniscript::psbt::PsbtExt;
use miniscript::Descriptor;
use miniscript::DescriptorPublicKey;
fn main() {
    let secp256k1 = secp256k1::Secp256k1::new();
    let keys = vec![
        "028013b54d87221128265e819f484790f64a4bf85852d3a3a2e331c287b97c8fed",
        "0257f4a2816338436cccabc43aa724cf6e69e43e84c3c8a305212761389dd73a8a",
        "03500a2b48b0f66c8183cc0d6645ab21cc19c7fad8a33ff04d41c3ece54b0bc1c5",
        "033ad2d191da4f39512adbaac320cae1f12f298386a4e9d43fd98dec7cf5db2ac9",
        "023fc33527afab09fa97135f2180bcd22ce637b1d2fbcb2db748b1f2c33f45b2b4",
    ];
    // defining the taproot descriptor
    let s = format!(
        "tr({},{{pk({}),{{multi_a(1,{},{}),and_v(v:pk({}),after(10))}}}})",
        keys[0], keys[1], keys[2], keys[3], keys[4]
    );

    let bridge_descriptor = Descriptor::from_str(&s).unwrap();
    assert!(bridge_descriptor.sanity_check().is_ok());
    println!(
        "Bridge pubkey script: {}",
        bridge_descriptor.script_pubkey()
    );
    println!(
        "Bridge address: {}",
        bridge_descriptor.address(Network::Regtest).unwrap()
    );
    println!(
        "Weight for witness satisfaction cost {}",
        bridge_descriptor.max_weight_to_satisfy().unwrap()
    );

    let master_private_key_str = "L3PQBktmrjb15mcVwunS1WY1eUdgRC2Y6HjbaZ5FkNRmm9hq1C1d";
    let master_private_key =
        PrivateKey::from_str(master_private_key_str).expect("Can't create private key");
    println!(
        "Master public key: {}",
        master_private_key.public_key(&secp256k1)
    );

    let backup1_private_key_str = "cWA34TkfWyHa3d4Vb2jNQvsWJGAHdCTNH73Rht7kAz6vQJcassky";
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

    // create a spending transaction
    let spend_tx = Transaction {
        version: 2,
        lock_time: PackedLockTime(5000),
        input: vec![],
        output: vec![],
    };

    // Spend one input and spend one output for simplicity.
    let mut psbt = Psbt {
        unsigned_tx: spend_tx,
        unknown: BTreeMap::new(),
        proprietary: BTreeMap::new(),
        xpub: BTreeMap::new(),
        version: 0,
        inputs: vec![],
        outputs: vec![],
    };

    let hex_tx = "020000000001018ff27041f3d738f5f84fd5ee62f1c5b36afebfb15f6da0c9d1382ddd0eaaa23c0000000000feffffff02b3884703010000001600142ca3b4e53f17991582d47b15a053b3201891df5200e1f50500000000225120ea173203dcad18962ae22cc44db73ff7f7546f60ec5a9afa7e4facdbd96fb3360247304402207b820860a9d425833f729775880b0ed59dd12b64b9a3d1ab677e27e4d6b370700220576003163f8420fe0b9dc8df726cff22cbc191104a2d4ae4f9dfedb087fcec72012103817e1da42a7701df4db94db8576f0e3605f3ab3701608b7e56f92321e4d8999100000000";
    let mut depo_tx: Transaction = deserialize(&Vec::<u8>::from_hex(hex_tx).unwrap()).unwrap();
    depo_tx.output[1].script_pubkey = bridge_descriptor.script_pubkey();
    let receiver = Address::from_str("bcrt1qsdks5za4t6sevaph6tz9ddfjzvhkdkxe9tfrcy").unwrap();

    let amount = 100000000;

    let (outpoint, witness_utxo) = get_vout(&depo_tx, bridge_descriptor.script_pubkey());

    let mut txin = TxIn::default();
    txin.previous_output = outpoint;

    txin.sequence = Sequence::from_height(26); //Sequence::MAX; //
    psbt.unsigned_tx.input.push(txin);

    psbt.unsigned_tx.output.push(TxOut {
        script_pubkey: receiver.script_pubkey(),
        value: amount / 5 - 500,
    });

    psbt.unsigned_tx.output.push(TxOut {
        script_pubkey: bridge_descriptor.script_pubkey(),
        value: amount * 4 / 5,
    });

    // Planning the Assets based on availability of keys.
    let mut assets = Assets::new();
    assets = assets.add(
        DescriptorPublicKey::from_str(
            "028013b54d87221128265e819f484790f64a4bf85852d3a3a2e331c287b97c8fed",
        )
        .unwrap(),
    );

    // Get the Plan and update the PSBT Input with the obtained meta-data.
    let result = bridge_descriptor.clone().get_plan(&assets);
    let mut input = psbt::Input::default();
    result.unwrap().update_psbt_input(&mut input);

    // Generating signatures & witness data
    input.witness_utxo = Some(witness_utxo.clone());
    psbt.inputs.push(input);
    psbt.outputs.push(psbt::Output::default());

    let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);

    let msg = dbg!(psbt.sighash_msg(0, &mut sighash_cache, None).unwrap()).to_secp_msg();

    // Fixme: Take a parameter
    let hash_ty = bitcoin::SchnorrSighashType::Default;

    let sk1 = master_private_key.inner;
    let sk2 = backup2_private.inner;

    let keypair1 = secp256k1::KeyPair::from_seckey_slice(&secp256k1, sk1.as_ref()).unwrap();
    let keypair2 = secp256k1::KeyPair::from_seckey_slice(&secp256k1, sk2.as_ref()).unwrap();

    // Tweak only if leaf_hash is None i.e Key Spend
    let keypair1 = keypair1
        .tap_tweak(&secp256k1, psbt.inputs[0].tap_merkle_root)
        .to_inner();
    let keypair2 = keypair2
        .tap_tweak(&secp256k1, psbt.inputs[0].tap_merkle_root)
        .to_inner();

    // Finally construct the signature and add to psbt
    let sig1 = secp256k1.sign_schnorr(&msg, &keypair1);
    let sig2 = secp256k1.sign_schnorr(&msg, &keypair2);

    let (pk1, _parity) = keypair1.x_only_public_key();
    let (pk2, _parity) = keypair2.x_only_public_key();

    assert!(secp256k1.verify_schnorr(&sig1, &msg, &pk1).is_ok());
    assert!(secp256k1.verify_schnorr(&sig2, &msg, &pk2).is_ok());

    // Generate the final signature
    let final_signature = schnorr::SchnorrSig {
        hash_ty: hash_ty,
        sig: sig1,
    };

    // tap key sign for the key spend path since  lf is `None`.
    psbt.inputs[0].tap_key_sig = Some(final_signature);

    // If leaf_hash is not none.
    // psbt.inputs[0].tap_script_sigs.insert((pk1, lh), final_signature);

    println!("{:#?}", psbt.inputs[0]);

    let serialized = serialize(&psbt);
    println!("{}", base64::encode(&serialized));
    psbt.finalize_mut(&secp256k1).unwrap();

    let tx = psbt.extract_tx();
    println!("{}", bitcoin::consensus::encode::serialize_hex(&tx));
}

// Find the Outpoint by spk
fn get_vout(tx: &Transaction, spk: Script) -> (OutPoint, TxOut) {
    for (i, txout) in tx.clone().output.into_iter().enumerate() {
        if spk == txout.script_pubkey {
            return (OutPoint::new(tx.txid(), i as u32), txout);
        }
    }
    panic!("Only call get vout on functions which have the expected outpoint");
}
