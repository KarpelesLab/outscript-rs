//! The block subsidy and the funding streams of the **main network**: what
//! the coinbase transaction of a block creates, and the outputs consensus
//! requires of it.
//!
//! Everything here is a rule about blocks, which this crate does not
//! validate: these functions are for whoever builds a coinbase transaction
//! (`zcash_builder::Builder::new_coinbase`) or checks one. They cover the
//! main network only, from the genesis block for the subsidy and from the
//! Canopy upgrade (height 1 046 400) for the funding streams; the test
//! network has other heights and addresses, which are left to the caller,
//! as are the Founders' Reward outputs of the blocks before Canopy.
//!
//! # Sources
//!
//! The protocol specification (section 7.8, "Calculating Block Subsidy,
//! Funding Streams, Lockbox Disbursement, and Founders' Reward"), ZIP 207
//! (funding streams, Revision 2), ZIP 214 (the streams and their
//! recipients, Revision 3), ZIP 1015 and ZIP 2001 (the lockbox, from NU6),
//! ZIP 271 (the disbursement of the lockbox at NU6.1), and for NU7: ZIP 218
//! (blocks every 25 seconds, hence a third of the subsidy and three times
//! the halving interval), ZIP 235 (60% of the transaction fees leave
//! circulation), ZIP 237 (they are issued again later) and ZIP 2008 (the
//! recipient of one stream changes), at `zcash/zips` commit `4699a8d5`.
//!
//! The reference crates have none of this (it lives in the nodes), so it
//! was checked against the chain instead: the coinbase transactions of 40
//! blocks of the main network, from height 1 to height 3 560 137, under
//! every network upgrade and on both sides of each change of rule (the
//! slow start, Blossom, both halvings, Canopy, NU5, NU6, NU6.1, NU6.3 and
//! NU7; eight address periods of the Canopy streams), have exactly the
//! total value and the funding stream outputs computed here from their
//! height and the fees of their block (see the tests here, and
//! `zcash_builder/coinbase_tests.rs` for the transactions themselves).
//!
//! Two things could not be checked on the chain, because they have not
//! happened yet as of November 2026, and are as the ZIPs state them: the
//! change of recipient of the `FS_FPF_ZCG_H3` stream (ZIP 2008), which
//! takes effect at height 3 612 390, the first of the address period that
//! follows the activation of NU7; and the end of the streams at the third
//! halving (height 6 132 390). From the height where ZIP 237 starts
//! issuing again what was removed (8 939 664) the subsidy depends on the
//! state of the chain and [`block_subsidy`] gives `None`.

/// The height at which the Blossom upgrade activated: blocks every 75
/// seconds instead of 150, and half the subsidy.
pub const BLOSSOM_ACTIVATION_HEIGHT: u32 = 653_600;
/// The height at which the Canopy upgrade activated, which is that of the
/// first halving: the funding streams replace the Founders' Reward.
pub const CANOPY_ACTIVATION_HEIGHT: u32 = 1_046_400;
/// The height at which NU5 activated: the first block with version 5
/// transactions.
pub const NU5_ACTIVATION_HEIGHT: u32 = 1_687_104;
/// The height at which NU6 activated, which is that of the second halving.
pub const NU6_ACTIVATION_HEIGHT: u32 = 2_726_400;
/// The height at which NU6.1 activated.
pub const NU6_1_ACTIVATION_HEIGHT: u32 = 3_146_400;
/// The height at which NU6.3 activated (ZIP 258).
pub const NU6_3_ACTIVATION_HEIGHT: u32 = 3_428_143;
/// The height at which NU7 activated (ZIP 259).
pub const NU7_ACTIVATION_HEIGHT: u32 = 3_543_405;
/// The height of the third halving, as NU7 moved it (ZIP 218), at which
/// the funding streams end.
pub const THIRD_HALVING_HEIGHT: u32 = 6_132_390;
/// The height from which the subsidy includes value issued again by the
/// Network Sustainability Mechanism (ZIP 237), and is no longer a function
/// of the height alone.
pub const NSM_REISSUANCE_HEIGHT: u32 = 8_939_664;

const SLOW_START_INTERVAL: u64 = 20_000;
const SLOW_START_SHIFT: u64 = SLOW_START_INTERVAL / 2;
const PRE_BLOSSOM_HALVING_INTERVAL: u64 = 840_000;
const POST_BLOSSOM_HALVING_INTERVAL: u64 = 1_680_000;
const POST_NU7_HALVING_INTERVAL: u64 = 5_040_000;
const MAX_BLOCK_SUBSIDY: u64 = 1_250_000_000;
const BLOSSOM: u64 = BLOSSOM_ACTIVATION_HEIGHT as u64;
const NU7: u64 = NU7_ACTIVATION_HEIGHT as u64;
/// `AddressChangeInterval`: a 48th of a halving interval.
const ADDRESS_CHANGE_INTERVAL: u64 = POST_BLOSSOM_HALVING_INTERVAL / 48;

/// The number of halvings of the subsidy that have happened by `height`
/// (`Halving` in the protocol specification, as ZIP 218 redefines it).
pub const fn halving(height: u32) -> u32 {
    let h = height as u64;
    let halvings = if h < SLOW_START_SHIFT {
        0
    } else if h < BLOSSOM {
        (h - SLOW_START_SHIFT) / PRE_BLOSSOM_HALVING_INTERVAL
    } else if h < NU7 {
        // a pre-Blossom block counts for two
        (2 * (BLOSSOM - SLOW_START_SHIFT) + (h - BLOSSOM)) / POST_BLOSSOM_HALVING_INTERVAL
    } else {
        // and for six blocks of NU7, of which a Blossom one is three
        (6 * (BLOSSOM - SLOW_START_SHIFT) + 3 * (NU7 - BLOSSOM) + (h - NU7))
            / POST_NU7_HALVING_INTERVAL
    };
    halvings as u32
}

/// The subsidy of the block at `height`, in zatoshis (`BlockSubsidy`):
/// what its coinbase transaction creates besides the fees. `None` from
/// [`NSM_REISSUANCE_HEIGHT`], where it depends on the state of the chain.
pub const fn block_subsidy(height: u32) -> Option<u64> {
    let h = height as u64;
    if height >= NSM_REISSUANCE_HEIGHT {
        return None;
    }
    let slow_start_rate = MAX_BLOCK_SUBSIDY / SLOW_START_INTERVAL;
    if h < SLOW_START_SHIFT {
        return Some(slow_start_rate * h);
    }
    if h < SLOW_START_INTERVAL {
        return Some(slow_start_rate * (h + 1));
    }
    let halvings = halving(height);
    if halvings >= 64 {
        return Some(0);
    }
    let spacing_ratio = if h < BLOSSOM {
        1
    } else if h < NU7 {
        2
    } else {
        6
    };
    Some((MAX_BLOCK_SUBSIDY >> halvings) / spacing_ratio)
}

/// The share of the transaction fees of the block at `height` that its
/// coinbase transaction collects, given their total `transaction_fees`:
/// all of them before NU7; from NU7, what is left once 60% of them,
/// rounded down, is removed from circulation (ZIP 235).
pub const fn miner_fees(height: u32, transaction_fees: u64) -> u64 {
    if height < NU7_ACTIVATION_HEIGHT {
        return transaction_fees;
    }
    let (q, r) = (transaction_fees / 10, transaction_fees % 10);
    transaction_fees - (6 * q + (6 * r) / 10)
}

/// Who receives a funding stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recipient {
    /// A transparent address of the main network (P2SH, or from NU7
    /// P2PKH): the coinbase transaction must have an output of the amount
    /// of the stream to its script (which
    /// [`decode_zcash_address`](crate::zcash::decode_zcash_address) gives).
    Address(&'static str),
    /// The Deferred Development Fund lockbox (ZIP 2001): no output; the
    /// amount stays out of the coinbase transaction, whose outputs are
    /// worth that much less.
    Lockbox,
}

/// A funding stream active at a height: a share of the block subsidy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FundingStream {
    /// The name of the stream in ZIP 214.
    pub name: &'static str,
    /// Its value at that height, in zatoshis.
    pub amount: u64,
    /// Who receives it.
    pub recipient: Recipient,
}

/// The funding streams active at a height: at most three.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FundingStreams {
    streams: [FundingStream; 3],
    len: usize,
}

impl FundingStreams {
    /// The streams.
    pub fn as_slice(&self) -> &[FundingStream] {
        &self.streams[..self.len]
    }

    /// The total that goes to the lockbox, which the coinbase transaction
    /// does not output.
    pub fn lockbox_total(&self) -> u64 {
        self.as_slice()
            .iter()
            .filter(|stream| stream.recipient == Recipient::Lockbox)
            .map(|stream| stream.amount)
            .sum()
    }
}

/// `AddressPeriod` of ZIP 207, as Revision 2 redefines it from NU7: the
/// periods are three times as many blocks, and the one in progress at the
/// activation keeps its index.
const fn address_period(height: u32) -> u64 {
    let h = height as u64;
    let offset = POST_BLOSSOM_HALVING_INTERVAL - CANOPY_ACTIVATION_HEIGHT as u64;
    if h < NU7 {
        (h + offset) / ADDRESS_CHANGE_INTERVAL
    } else {
        (3 * (NU7 + offset) + h - NU7) / (3 * ADDRESS_CHANGE_INTERVAL)
    }
}

/// The index, in the address list of a stream that starts at `start`, of
/// the address in use at `height`.
const fn address_index(height: u32, start: u32) -> usize {
    (address_period(height) - address_period(start)) as usize
}

const ZF_ADDRESS: &str = "t3dvVE3SQEi7kqNzwrfNePxZ1d4hUyztBA1";
const MG_ADDRESS: &str = "t3XyYW8yBFRuMnfvm5KLGFbEVz25kckZXym";
const ZCG_ADDRESS: &str = "t3cFfPt1Bcvgez9ZbMBFWeZsskxTkPzGCow";
/// The recipient of `FS_FPF_ZCG_H3` from the address period after the
/// activation of NU7 (ZIP 2008).
const ZCG_NU7_ADDRESS: &str = "t1MkHnkxVjNpNbCrSs3AJ8J7ZSp6NTYiUcG";

/// `FS_ZIP214_BP.AddressList` of ZIP 214.
const BP_ADDRESSES: [&str; 48] = [
    "t3LmX1cxWPPPqL4TZHx42HU3U5ghbFjRiif",
    "t3Toxk1vJQ6UjWQ42tUJz2rV2feUWkpbTDs",
    "t3ZBdBe4iokmsjdhMuwkxEdqMCFN16YxKe6",
    "t3ZuaJziLM8xZ32rjDUzVjVtyYdDSz8GLWB",
    "t3bAtYWa4bi8VrtvqySxnbr5uqcG9czQGTZ",
    "t3dktADfb5Rmxncpe1HS5BRS5Gcj7MZWYBi",
    "t3hgskquvKKoCtvxw86yN7q8bzwRxNgUZmc",
    "t3R1VrLzwcxAZzkX4mX3KGbWpNsgtYtMntj",
    "t3ff6fhemqPMVujD3AQurxRxTdvS1pPSaa2",
    "t3cEUQFG3KYnFG6qYhPxSNgGi3HDjUPwC3J",
    "t3WR9F5U4QvUFqqx9zFmwT6xFqduqRRXnaa",
    "t3PYc1LWngrdUrJJbHkYPCKvJuvJjcm85Ch",
    "t3bgkjiUeatWNkhxY3cWyLbTxKksAfk561R",
    "t3Z5rrR8zahxUpZ8itmCKhMSfxiKjUp5Dk5",
    "t3PU1j7YW3fJ67jUbkGhSRto8qK2qXCUiW3",
    "t3S3yaT7EwNLaFZCamfsxxKwamQW2aRGEkh",
    "t3eutXKJ9tEaPSxZpmowhzKhPfJvmtwTEZK",
    "t3gbTb7brxLdVVghSPSd3ycGxzHbUpukeDm",
    "t3UCKW2LrHFqPMQFEbZn6FpjqnhAAbfpMYR",
    "t3NyHsrnYbqaySoQqEQRyTWkjvM2PLkU7Uu",
    "t3QEFL6acxuZwiXtW3YvV6njDVGjJ1qeaRo",
    "t3PdBRr2S1XTDzrV8bnZkXF3SJcrzHWe1wj",
    "t3ZWyRPpWRo23pKxTLtWsnfEKeq9T4XPxKM",
    "t3he6QytKCTydhpztykFsSsb9PmBT5JBZLi",
    "t3VWxWDsLb2TURNEP6tA1ZSeQzUmPKFNxRY",
    "t3NmWLvZkbciNAipauzsFRMxoZGqmtJksbz",
    "t3cKr4YxVPvPBG1mCvzaoTTdBNokohsRJ8n",
    "t3T3smGZn6BoSFXWWXa1RaoQdcyaFjMfuYK",
    "t3gkDUe9Gm4GGpjMk86TiJZqhztBVMiUSSA",
    "t3eretuBeBXFHe5jAqeSpUS1cpxVh51fAeb",
    "t3dN8g9zi2UGJdixGe9txeSxeofLS9t3yFQ",
    "t3S799pq9sYBFwccRecoTJ3SvQXRHPrHqvx",
    "t3fhYnv1S5dXwau7GED3c1XErzt4n4vDxmf",
    "t3cmE3vsBc5xfDJKXXZdpydCPSdZqt6AcNi",
    "t3h5fPdjJVHaH4HwynYDM5BB3J7uQaoUwKi",
    "t3Ma35c68BgRX8sdLDJ6WR1PCrKiWHG4Da9",
    "t3LokMKPL1J8rkJZvVpfuH7dLu6oUWqZKQK",
    "t3WFFGbEbhJWnASZxVLw2iTJBZfJGGX73mM",
    "t3L8GLEsUn4QHNaRYcX3EGyXmQ8kjpT1zTa",
    "t3PgfByBhaBSkH8uq4nYJ9ZBX4NhGCJBVYm",
    "t3WecsqKDhWXD4JAgBVcnaCC2itzyNZhJrv",
    "t3ZG9cSfopnsMQupKW5v9sTotjcP5P6RTbn",
    "t3hC1Ywb5zDwUYYV8LwhvF5rZ6m49jxXSG5",
    "t3VgMqDL15ZcyQDeqBsBW3W6rzfftrWP2yB",
    "t3LC94Y6BwLoDtBoK2NuewaEbnko1zvR9rm",
    "t3cWCUZJR3GtALaTcatrrpNJ3MGbMFVLRwQ",
    "t3YYF4rPLVxDcF9hHFsXyc5Yq1TFfbojCY6",
    "t3XHAGxRP2FNfhAjxGjxbrQPYtQQjc3RCQD",
];

/// The funding streams active at `height` (ZIP 214), with their values
/// and recipients: the outputs the coinbase transaction of that block must
/// have, and what it must leave to the lockbox. `None` before Canopy
/// (where the Founders' Reward applied, which is not handled here) and
/// from [`NSM_REISSUANCE_HEIGHT`]; no stream from the third halving.
pub fn funding_streams(height: u32) -> Option<FundingStreams> {
    if height < CANOPY_ACTIVATION_HEIGHT {
        return None;
    }
    let subsidy = block_subsidy(height)?;
    let stream = |name, numerator: u64, recipient| FundingStream {
        name,
        amount: subsidy * numerator / 100,
        recipient,
    };
    let none = stream("", 0, Recipient::Lockbox);
    let (streams, len) = if height < NU6_ACTIVATION_HEIGHT {
        let index = address_index(height, CANOPY_ACTIVATION_HEIGHT);
        (
            [
                stream("FS_ZIP214_BP", 7, Recipient::Address(BP_ADDRESSES[index])),
                stream("FS_ZIP214_ZF", 5, Recipient::Address(ZF_ADDRESS)),
                stream("FS_ZIP214_MG", 8, Recipient::Address(MG_ADDRESS)),
            ],
            3,
        )
    } else if height < NU6_1_ACTIVATION_HEIGHT {
        (
            [
                stream("FS_FPF_ZCG", 8, Recipient::Address(ZCG_ADDRESS)),
                stream("FS_DEFERRED", 12, Recipient::Lockbox),
                none,
            ],
            2,
        )
    } else if height < THIRD_HALVING_HEIGHT {
        // the address changes with the first period that starts under NU7
        let last_before = address_index(NU7_ACTIVATION_HEIGHT - 1, NU6_1_ACTIVATION_HEIGHT);
        let address = if address_index(height, NU6_1_ACTIVATION_HEIGHT) <= last_before {
            ZCG_ADDRESS
        } else {
            ZCG_NU7_ADDRESS
        };
        (
            [
                stream("FS_FPF_ZCG_H3", 8, Recipient::Address(address)),
                stream("FS_CCF_H3", 12, Recipient::Lockbox),
                none,
            ],
            2,
        )
    } else {
        ([none; 3], 0)
    };
    Some(FundingStreams { streams, len })
}

/// The one-time disbursement of the lockbox (ZIP 271): the outputs the
/// coinbase transaction of one block had to have besides the others.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockboxDisbursement {
    /// The number of outputs.
    pub outputs: usize,
    /// The value of each, in zatoshis.
    pub amount: u64,
    /// The P2SH address they pay.
    pub address: &'static str,
}

/// The lockbox disbursement of the block at `height`: the ten outputs of
/// 7 875 ZEC of the block that activated NU6.1, and nothing at any other
/// height.
pub const fn lockbox_disbursement(height: u32) -> Option<LockboxDisbursement> {
    if height == NU6_1_ACTIVATION_HEIGHT {
        Some(LockboxDisbursement {
            outputs: 10,
            amount: 787_500_000_000,
            address: "t3ev37Q2uL1sfTsiJQJiWJoFzQpDhmnUwYo",
        })
    } else {
        None
    }
}

/// The total value of the outputs (transparent and shielded) that the
/// coinbase transaction of the block at `height` must have from NU6, when
/// the other transactions of the block pay `transaction_fees` in total:
/// the block subsidy, plus the miner's share of the fees
/// ([`miner_fees`]), minus what the funding streams send to the lockbox,
/// plus a lockbox disbursement. This is what
/// `zcash_builder::Builder::build_coinbase` is told.
///
/// From NU6 (ZIP 236) the coinbase transaction must create exactly this;
/// before, it could create less. `None` before Canopy and from
/// [`NSM_REISSUANCE_HEIGHT`], and if the fees are not an amount of money.
pub fn coinbase_output_total(height: u32, transaction_fees: u64) -> Option<u64> {
    if transaction_fees > 21_000_000 * 100_000_000 {
        return None;
    }
    let subsidy = block_subsidy(height)?;
    let lockbox = funding_streams(height)?.lockbox_total();
    let disbursed = match lockbox_disbursement(height) {
        Some(d) => d.outputs as u64 * d.amount,
        None => 0,
    };
    Some(subsidy + miner_fees(height, transaction_fees) - lockbox + disbursed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The total output of the coinbase transaction and the fees of blocks
    /// of the main network before Canopy, where the whole subsidy and the
    /// fees were claimed (heights, totals and fees from a public explorer,
    /// `api.mainnet.cipherscan.app`): the slow start, the end of it,
    /// Blossom and the first halving.
    #[test]
    fn early_subsidies_match_the_chain() {
        for (height, total_output, fees) in [
            (1, 62_500, 0),
            (9_999, 625_027_500, 90_000),
            (10_000, 625_107_907, 45_407),
            (15_000, 937_672_500, 110_000),
            (19_999, 1_250_020_000, 20_000),
            (20_000, 1_250_040_000, 40_000),
            (500_000, 1_250_012_575, 12_575),
            (653_599, 1_250_000_000, 0),
            (653_600, 625_000_000, 0),
            (1_046_399, 625_000_000, 0),
            (1_046_400, 312_500_000, 0),
        ] {
            assert_eq!(block_subsidy(height), Some(total_output - fees), "{height}");
        }
        assert_eq!(block_subsidy(0), Some(0));
        assert_eq!(funding_streams(1_046_399), None);
        assert_eq!(coinbase_output_total(1_046_399, 0), None);
    }

    /// The numbers the ZIPs state.
    #[test]
    fn values_of_the_zips() {
        // ZIP 214, Revision 3
        assert_eq!(block_subsidy(NU7_ACTIVATION_HEIGHT), Some(52_083_333));
        let streams = funding_streams(NU7_ACTIVATION_HEIGHT).unwrap();
        assert_eq!(streams.as_slice()[0].amount, 4_166_666);
        assert_eq!(streams.as_slice()[1].amount, 6_249_999);
        assert_eq!(streams.lockbox_total(), 6_249_999);
        // ZIP 218: the third halving, and the subsidy after it
        assert_eq!(halving(THIRD_HALVING_HEIGHT - 1), 2);
        assert_eq!(halving(THIRD_HALVING_HEIGHT), 3);
        assert_eq!(block_subsidy(THIRD_HALVING_HEIGHT), Some(26_041_666));
        assert_eq!(
            THIRD_HALVING_HEIGHT,
            NU7_ACTIVATION_HEIGHT + 3 * (4_406_400 - NU7_ACTIVATION_HEIGHT)
        );
        let last = funding_streams(THIRD_HALVING_HEIGHT - 1).unwrap();
        assert_eq!(last.as_slice().len(), 2);
        let after = funding_streams(THIRD_HALVING_HEIGHT).unwrap();
        assert!(after.as_slice().is_empty());
        assert_eq!(halving(NU6_ACTIVATION_HEIGHT - 1), 1);
        assert_eq!(halving(NU6_ACTIVATION_HEIGHT), 2);
        // ZIP 237
        assert!(block_subsidy(NSM_REISSUANCE_HEIGHT - 1).is_some());
        assert_eq!(block_subsidy(NSM_REISSUANCE_HEIGHT), None);
        assert_eq!(funding_streams(u32::MAX), None);
        // ZIP 235: floor(6 fees / 10) leaves circulation
        for fees in [
            0u64,
            1,
            9,
            10,
            11,
            19,
            22_720,
            300_000,
            2_100_000_000_000_000,
        ] {
            assert_eq!(miner_fees(NU7_ACTIVATION_HEIGHT - 1, fees), fees);
            assert_eq!(
                miner_fees(NU7_ACTIVATION_HEIGHT, fees) as u128,
                fees as u128 - 6 * fees as u128 / 10
            );
        }
        // ZIP 271
        let d = lockbox_disbursement(NU6_1_ACTIVATION_HEIGHT).unwrap();
        assert_eq!(d.outputs as u64 * d.amount, 78_750 * 100_000_000);
        assert_eq!(lockbox_disbursement(NU6_1_ACTIVATION_HEIGHT + 1), None);
        assert_eq!(coinbase_output_total(NU7_ACTIVATION_HEIGHT, u64::MAX), None);
    }

    /// The address periods: 48 a halving interval before NU7, each of
    /// 35 000 blocks, then of 105 000; ZIP 2008's change of recipient
    /// comes with the first period that starts under NU7.
    #[test]
    fn address_periods() {
        // every address of the Canopy streams is used, in order
        for (index, address) in BP_ADDRESSES.iter().enumerate() {
            for height in [
                CANOPY_ACTIVATION_HEIGHT + index as u32 * 35_000,
                CANOPY_ACTIVATION_HEIGHT + index as u32 * 35_000 + 34_999,
            ] {
                let streams = funding_streams(height).unwrap();
                assert_eq!(streams.as_slice().len(), 3);
                assert_eq!(streams.as_slice()[0].recipient, Recipient::Address(address));
                assert_eq!(streams.lockbox_total(), 0);
            }
        }
        // ZIP 214: N = AddressIndex(NU7ActivationHeight - 1) + 1 addresses
        // are the old one, of the 36 of the stream
        let n = address_index(NU7_ACTIVATION_HEIGHT - 1, NU6_1_ACTIVATION_HEIGHT) + 1;
        assert_eq!(n, 12);
        assert_eq!(
            address_index(THIRD_HALVING_HEIGHT - 1, NU6_1_ACTIVATION_HEIGHT),
            35
        );
        // the period in progress at the activation keeps its index, and
        // what was left of it is three times as long
        assert_eq!(
            address_index(NU7_ACTIVATION_HEIGHT, NU6_1_ACTIVATION_HEIGHT),
            n - 1
        );
        let pre_nu7_end = NU6_1_ACTIVATION_HEIGHT + 12 * 35_000;
        let change = NU7_ACTIVATION_HEIGHT + 3 * (pre_nu7_end - NU7_ACTIVATION_HEIGHT);
        assert_eq!(change, 3_612_390);
        let recipient = |height| funding_streams(height).unwrap().as_slice()[0].recipient;
        assert_eq!(recipient(change - 1), Recipient::Address(ZCG_ADDRESS));
        assert_eq!(recipient(change), Recipient::Address(ZCG_NU7_ADDRESS));
        assert_eq!(
            recipient(THIRD_HALVING_HEIGHT - 1),
            Recipient::Address(ZCG_NU7_ADDRESS)
        );
        assert_eq!(recipient(change + 105_000 - 1), recipient(change));
        assert_eq!(
            address_index(change + 105_000, NU6_1_ACTIVATION_HEIGHT),
            n + 1
        );
        // the addresses are addresses
        let disbursement = lockbox_disbursement(NU6_1_ACTIVATION_HEIGHT).unwrap();
        for address in BP_ADDRESSES.iter().chain(&[
            ZF_ADDRESS,
            MG_ADDRESS,
            ZCG_ADDRESS,
            ZCG_NU7_ADDRESS,
            disbursement.address,
        ]) {
            let decoded = crate::zcash::decode_zcash_address("zcash", address).unwrap();
            let p2sh = address.starts_with("t3");
            assert_eq!(decoded.format, if p2sh { "p2sh" } else { "p2pkh" });
        }
    }
}
