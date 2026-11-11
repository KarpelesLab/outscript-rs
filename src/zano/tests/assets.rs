//! Building, verifying and scanning a transfer of several assets, with a
//! transparent input and payment ids: outputs made as a sender makes them
//! are scanned, spent with this module's signer, and the result is checked
//! with its verifier and scanned again. (The verifier is checked against
//! the main network in `mainnet.rs`; no key of a wallet that received
//! another asset than ZANO there is known, so the amounts and asset ids of
//! such outputs are only checked this way.)

use super::super::crypto::OutputSecrets;
use super::super::*;
use super::chain::ggx_ring;
use super::stream;
use crate::cryptonote::{EdwardsPoint, Scalar, point_from_hash, scalar_from_u64};
use crate::prelude::*;

/// An output of `amount` of `asset_id` to `wallet`, as the sender with the
/// transaction key `tx_secret` builds it at `index`.
pub(super) fn pay(
    wallet: &Wallet,
    tx_secret: &Scalar,
    index: u64,
    asset_id: &[u8; 32],
    amount: u64,
) -> TxOutZarcanum {
    let view = EdwardsPoint::decompress(wallet.view_public_key()).unwrap();
    let spend = EdwardsPoint::decompress(wallet.spend_public_key()).unwrap();
    let derivation = view.mul(tx_secret).mul_by_cofactor().compress();
    let secrets = OutputSecrets::derive(&derivation, index);
    let inv8 = scalar_1div8();
    let blinded = EdwardsPoint::decompress(asset_id)
        .unwrap()
        .add(&generator_x().mul(&secrets.asset_blinding_mask));
    let commitment = blinded
        .mul(&scalar_from_u64(amount))
        .add(&EdwardsPoint::mul_base(&secrets.amount_blinding_mask));
    TxOutZarcanum {
        stealth_address: EdwardsPoint::mul_base(&secrets.h).add(&spend).compress(),
        concealing_point: view.mul(&secrets.concealing).compress(),
        amount_commitment: commitment.mul(&inv8).compress(),
        blinded_asset_id: blinded.mul(&inv8).compress(),
        encrypted_amount: amount ^ secrets.amount_mask,
        mix_attr: 0,
    }
}

/// A ring around `real` at global index `real_index`: decoys that are
/// points and nothing more.
pub(super) fn ring_around(real: RingMember, size: u64) -> Vec<RingMember> {
    (0..size)
        .map(|i| {
            if i == real.global_index % size {
                return real;
            }
            let point = |n: u8| point_from_hash(&[n, i as u8, real.stealth_address[0]]).compress();
            RingMember {
                global_index: real.global_index - real.global_index % size + i,
                stealth_address: point(0),
                concealing_point: point(1),
                amount_commitment: point(2),
                blinded_asset_id: point(3),
            }
        })
        .collect()
}

#[test]
fn multi_asset_transfer() {
    let wallet = super::wallet();
    let recipient = Wallet::generate(&mut stream(31), 0).unwrap();
    // An asset: the id a descriptor registers.
    let asset = AssetDescriptorBase {
        ticker: b"TEST".to_vec(),
        full_name: b"Test asset".to_vec(),
        total_max_supply: 1_000_000,
        decimal_point: 2,
        owner: *wallet.spend_public_key(),
        ..Default::default()
    }
    .asset_id(None);
    assert_ne!(asset, NATIVE_COIN_ASSET_ID);

    // The wallet received 500 of the asset and 3 coins, in one transaction.
    let tx_secret = scalar_from_u64(0x1234_5678);
    let tx_pub = EdwardsPoint::mul_base(&tx_secret).compress();
    let derivation = wallet.key_derivation(&tx_pub).unwrap();
    let outs = [
        pay(&wallet, &tx_secret, 0, &asset, 500),
        pay(
            &wallet,
            &tx_secret,
            1,
            &NATIVE_COIN_ASSET_ID,
            3_000_000_000_000,
        ),
    ];
    let received: Vec<ReceivedOutput> = outs
        .iter()
        .enumerate()
        .map(|(i, out)| {
            wallet
                .scan_output(&derivation, i as u64, out)
                .unwrap()
                .unwrap()
        })
        .collect();
    assert_eq!(
        (
            received[0].amount,
            received[0].asset_id,
            received[0].is_native
        ),
        (500, asset, false)
    );
    assert_eq!(
        (received[1].amount, received[1].is_native),
        (3_000_000_000_000, true)
    );
    // Not the recipient's.
    let other = recipient.key_derivation(&tx_pub).unwrap();
    assert_eq!(recipient.scan_output(&other, 0, &outs[0]).unwrap(), None);

    // And one transparent coin, from before hard fork 4.
    let bare_secret = scalar_from_u64(0x9999);
    let bare_pub = EdwardsPoint::mul_base(&bare_secret).compress();
    let bare_derivation = wallet.key_derivation(&bare_pub).unwrap();
    let bare_key =
        crate::cryptonote::derive_public_key(&bare_derivation, 0, wallet.spend_public_key())
            .unwrap();
    let bare = wallet
        .scan_bare_output(&bare_derivation, 0, 1_000_000_000_000, &bare_key)
        .unwrap()
        .unwrap();
    assert!(bare.is_native && bare.amount_blinding_mask == [0u8; 32]);

    let mut inputs: Vec<TransferInput> = received
        .iter()
        .zip(&outs)
        .enumerate()
        .map(|(n, (found, out))| TransferInput {
            amount: found.amount,
            asset_id: found.asset_id,
            amount_blinding_mask: found.amount_blinding_mask,
            asset_id_blinding_mask: found.asset_id_blinding_mask,
            real_out_tx_key: tx_pub,
            real_out_index: found.output_index,
            real_global_index: 1000 + 7 * n as u64,
            ring: ring_around(
                RingMember {
                    global_index: 1000 + 7 * n as u64,
                    stealth_address: out.stealth_address,
                    concealing_point: out.concealing_point,
                    amount_commitment: out.amount_commitment,
                    blinded_asset_id: out.blinded_asset_id,
                },
                5,
            ),
        })
        .collect();
    let zero = [0u8; 32];
    inputs.push(TransferInput {
        amount: bare.amount,
        asset_id: NATIVE_COIN_ASSET_ID,
        amount_blinding_mask: zero,
        asset_id_blinding_mask: zero,
        real_out_tx_key: bare_pub,
        real_out_index: 0,
        real_global_index: 42,
        ring: (40..44)
            .map(|i| RingMember {
                global_index: i,
                stealth_address: if i == 42 {
                    bare_key
                } else {
                    point_from_hash(&[i as u8]).compress()
                },
                concealing_point: zero,
                amount_commitment: zero,
                blinded_asset_id: zero,
            })
            .collect(),
    });

    // 300 of the asset to an integrated address, the rest back.
    let mut integrated = recipient.address();
    integrated.set_payment_id(&[0xaa, 0xbb, 0xcc]).unwrap();
    let fee = 10_000_000_000;
    let dests = [
        TransferDest {
            address: integrated,
            asset_id: asset,
            amount: 300,
        },
        TransferDest {
            address: wallet.address(),
            asset_id: asset,
            amount: 200,
        },
        TransferDest {
            address: wallet.address(),
            asset_id: NATIVE_COIN_ASSET_ID,
            amount: 4_000_000_000_000 - fee,
        },
    ];

    for height in [3_000_000u64, 3_900_000] {
        let signed = wallet
            .build_transfer_at_height(&mut stream(height), &inputs, &dests, height)
            .unwrap();
        let tx = &signed.tx;
        let hf6 = height > 3_833_000;
        assert_eq!(tx.version, if hf6 { 4 } else { 2 });
        assert_eq!(tx.fee(), Some(fee));
        let kinds: Vec<&str> = tx.vin.iter().map(Variant::name).collect();
        assert_eq!(kinds, ["key", "txin_zc_input", "txin_zc_input"]);
        assert_eq!(signed.tx_id, tx.prefix_hash());
        // Three outputs: a range proof of four values; and surjection
        // rings of three members: two pseudo-outputs and the native coin.
        let Some(Variant::AssetSurjectionProof(surjection)) = tx.proofs.first() else {
            panic!()
        };
        assert_eq!(surjection.bge_proofs.len(), 3);
        assert_eq!(Transaction::from_bytes(&tx.to_bytes()).unwrap(), *tx);

        // Each input verifies over the ring it was built from, sorted.
        let rings: Vec<Vec<ClsagGgxInput>> = tx
            .vin
            .iter()
            .map(|vin| {
                let image = vin.key_image().unwrap();
                let input = inputs
                    .iter()
                    .find(|input| {
                        let mut ring = input.ring.clone();
                        ring.sort_by_key(|m| m.global_index);
                        tx.verify_input(
                            tx.vin
                                .iter()
                                .position(|v| v.key_image() == Some(image))
                                .unwrap(),
                            &ggx_ring(&ring),
                        )
                    })
                    .expect("a ring for the input");
                let mut ring = input.ring.clone();
                ring.sort_by_key(|m| m.global_index);
                ggx_ring(&ring)
            })
            .collect();
        let refs: Vec<&[ClsagGgxInput]> = rings.iter().map(Vec::as_slice).collect();
        assert_eq!(tx.verify(&VerifyContext::new(&refs)), Ok(()), "{height}");
        // A fee that is not the one declared does not balance.
        let mut bad = tx.clone();
        for entry in &mut bad.extra {
            if let Variant::ZarcanumTxDataV1 { fee } = entry {
                *fee += 1;
            }
        }
        assert!(!bad.verify_proofs());

        // The recipient finds 300 of the asset, with the payment id from
        // version 4 on; the sender its change of both assets.
        let found = recipient.scan_tx(tx).unwrap();
        assert_eq!(found.outputs.len(), 1);
        assert_eq!(
            (found.outputs[0].amount, found.outputs[0].asset_id),
            (300, asset)
        );
        if hf6 {
            let id = u64::from_le_bytes([0, 0, 0, 0, 0, 0xaa, 0xbb, 0xcc]);
            assert_eq!(found.output_payment_ids, [id]);
            assert_eq!(found.payment_id, Some(id.to_le_bytes().to_vec()));
        } else {
            assert_eq!(found.payment_id, None);
        }
        let change = wallet.scan_tx(tx).unwrap();
        let mut amounts: Vec<(u64, bool)> = change
            .outputs
            .iter()
            .map(|o| (o.amount, o.is_native))
            .collect();
        amounts.sort_unstable();
        assert_eq!(amounts, [(200, false), (4_000_000_000_000 - fee, true)]);
        assert_eq!(change.output_payment_ids, [0, 0]);
        // The key images of the change go back with the signed blob.
        assert_eq!(signed.outs_key_images.len(), 2);
    }

    // A payment id too long for an output.
    let mut long = recipient.address();
    long.set_payment_id(&[1; 9]).unwrap();
    let mut too_long = dests;
    too_long[0].address = long;
    assert_eq!(
        wallet
            .build_transfer_at_height(&mut stream(0), &inputs, &too_long, 3_900_000)
            .unwrap_err(),
        Error::PaymentIdTooLong
    );
    // An asset that does not balance.
    let mut unbalanced = dests;
    unbalanced[1].amount = 201;
    assert_eq!(
        wallet
            .build_transfer_at_height(&mut stream(0), &inputs, &unbalanced, 3_900_000)
            .unwrap_err(),
        Error::Unbalanced
    );
}
