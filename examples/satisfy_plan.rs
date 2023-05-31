// Miniscript
// Written in 2023 by
//     Harshil Jani <harshiljani2002@gmail.comt>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Example: Planning a spending path using planner API.
//!
use bitcoin::{LockTime, Sequence};
use miniscript::plan::Assets;
use miniscript::{DefiniteDescriptorKey, Descriptor, DescriptorPublicKey};
use std::str::FromStr;

fn main() {
    // Defining the descriptor with the following public keys
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
    let desc = Descriptor::<DefiniteDescriptorKey>::from_str(&format!(
        "wsh(thresh(2,pk({}),s:pk({}),snl:older(144)))",
        keys[0], keys[1]
    ))
    .unwrap();

    // Available Keys for planning first Asset
    // Here it has only one of the two expected keys available.
    let available_keys_1 = vec![DescriptorPublicKey::from_str(
        "02c2fd50ceae468857bb7eb32ae9cd4083e6c7e42fbbec179d81134b3e3830586c",
    )
    .unwrap()];

    // Available Keys for planning second Asset
    // Here it has both the expected keys available
    let available_keys_2 = vec![
        DescriptorPublicKey::from_str(
            "02c2fd50ceae468857bb7eb32ae9cd4083e6c7e42fbbec179d81134b3e3830586c",
        )
        .unwrap(),
        DescriptorPublicKey::from_str(
            "0257f4a2816338436cccabc43aa724cf6e69e43e84c3c8a305212761389dd73a8a",
        )
        .unwrap(),
    ];

    // Available Hashes for planning first Asset
    let hashes_1 = vec![];
    // Available Hashes for planning second Asset
    let hashes_2 = vec![];

    // Constructing the first asset with available signatures and hashes
    let mut assets_1 = Assets::new();
    // We have the relative timelock present
    assets_1 = assets_1.older(Sequence(1000));
    // We also have 1 Key available
    assets_1 = assets_1.add(available_keys_1);
    assets_1 = assets_1.add(hashes_1);
    // Getting the plan for the first asset
    let result_1 = desc.clone().get_plan(&assets_1);
    // Finally getting the satisfaction weight
    // Expected weight : 4 + 1 + 73*1 + 2 = 80
    let weight_1 = result_1.as_ref().map(|plan| plan.satisfaction_weight());

    // Constructing the second asset with available signatures and hashes
    let mut assets_2 = Assets::new();
    // We have 2 Keys available
    assets_2 = assets_2.add(available_keys_2);
    assets_2 = assets_2.add(hashes_2);
    // Getting the plan for the second asset
    let result_2 = desc.clone().get_plan(&assets_2);
    // Finally getting the satisfaction weight
    // Expected weight : 4 + 1 + 73*2 + 1 + 1 = 153
    let weight_2 = result_2.as_ref().map(|plan| plan.satisfaction_weight());
    assert_eq!(weight_1, Some(80));
    assert_eq!(weight_2, Some(153));
}
