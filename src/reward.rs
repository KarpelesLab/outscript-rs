//! Block reward and cumulative-supply calculations across networks. Port of
//! `reward.go`.

pub use crate::Error;

use num_bigint::BigInt;
use num_traits::Zero;

#[derive(Clone, Copy)]
enum RewardModel {
    Halving,
    Doge,
    Dash,
    Zero,
}

struct ChainRewardInfo {
    model: RewardModel,
    initial_reward: i64,
    halving_interval: u64,
}

fn chain_config(network: &str) -> Option<ChainRewardInfo> {
    let cfg = |model, initial_reward, halving_interval| {
        Some(ChainRewardInfo {
            model,
            initial_reward,
            halving_interval,
        })
    };
    const COIN: i64 = 100_000_000;
    match network {
        "bitcoin" | "namecoin" | "bitcoin-cash" | "bitcoin-testnet" => {
            cfg(RewardModel::Halving, 50 * COIN, 210_000)
        }
        "litecoin" => cfg(RewardModel::Halving, 50 * COIN, 840_000),
        "monacoin" => cfg(RewardModel::Halving, 50 * COIN, 1_051_200),
        "dogecoin" => cfg(RewardModel::Doge, 0, 0),
        "dash" => cfg(RewardModel::Dash, 5 * COIN, 0),
        "electraproto" => cfg(RewardModel::Zero, 0, 0),
        _ => None,
    }
}

/// Returns the block reward at `block_height` for `network`.
pub fn block_reward(network: &str, block_height: u64) -> Result<BigInt, Error> {
    let info = chain_config(network).ok_or(Error::UnsupportedNetwork)?;
    Ok(match info.model {
        RewardModel::Halving => {
            halving_block_reward(info.initial_reward, info.halving_interval, block_height)
        }
        RewardModel::Doge => doge_block_reward(block_height),
        RewardModel::Dash => dash_block_reward(info.initial_reward, block_height),
        RewardModel::Zero => BigInt::zero(),
    })
}

fn halving_block_reward(base_reward: i64, halving_interval: u64, block_height: u64) -> BigInt {
    let halving_count = block_height / halving_interval;
    if halving_count > 32 {
        return BigInt::zero();
    }
    BigInt::from(base_reward) >> (halving_count as usize)
}

fn doge_block_reward(block_height: u64) -> BigInt {
    if block_height >= 600_000 {
        return BigInt::from(10_000i64 * 100_000_000);
    }
    let halving_index = block_height / 100_000; // 0..5
    let doge = 1_000_000i64 >> halving_index;
    BigInt::from(doge * 100_000_000)
}

/// Blocks per Dash reward year.
const DASH_BLOCKS_PER_YEAR: u64 = 210_240;

/// The first Dash reward year whose reward `5 DASH * (13/14)^year` rounds
/// down to zero (it is 1 duff in year 270); every later year is zero too.
/// Stopping there keeps the big-integer powers small whatever the height.
const DASH_ZERO_YEAR: u64 = 271;

fn dash_block_reward(base_reward: i64, block_height: u64) -> BigInt {
    dash_yearly(base_reward, block_height / DASH_BLOCKS_PER_YEAR)
}

/// Returns the total minted coins from block 0 through `block_height`
/// (inclusive) for `network`.
pub fn cumulative_reward(network: &str, block_height: u64) -> Result<BigInt, Error> {
    let info = chain_config(network).ok_or(Error::UnsupportedNetwork)?;
    Ok(match info.model {
        RewardModel::Halving => {
            cumulative_halving(info.initial_reward, info.halving_interval, block_height)
        }
        RewardModel::Doge => cumulative_doge(block_height),
        RewardModel::Dash => cumulative_dash(info.initial_reward, block_height),
        RewardModel::Zero => BigInt::zero(),
    })
}

fn cumulative_halving(base_reward: i64, halving_interval: u64, block_height: u64) -> BigInt {
    // u128: `block_height + 1` does not fit a u64 at u64::MAX
    let mut blocks_needed = u128::from(block_height) + 1;
    let mut total = BigInt::zero();
    let mut reward = BigInt::from(base_reward);
    let mut i = 0;
    while i < 33 && blocks_needed > 0 && reward.sign() == num_bigint::Sign::Plus {
        let interval_size = u128::from(halving_interval).min(blocks_needed);
        total += BigInt::from(interval_size) * &reward;
        blocks_needed -= interval_size;
        reward >>= 1;
        i += 1;
    }
    total
}

fn cumulative_doge(block_height: u64) -> BigInt {
    const INTERVAL: u128 = 100_000;
    const COIN: i64 = 100_000_000;
    // u128: `block_height + 1` does not fit a u64 at u64::MAX
    let blocks = u128::from(block_height) + 1;
    let mut total = BigInt::zero();

    // six halving intervals, from 1,000,000 DOGE per block
    for i in 0..6u32 {
        let interval_start = INTERVAL * u128::from(i);
        if blocks <= interval_start {
            return total;
        }
        let in_interval = (blocks - interval_start).min(INTERVAL);
        total += BigInt::from(in_interval) * BigInt::from((1_000_000i64 >> i) * COIN);
    }
    // then a fixed 10,000 DOGE per block
    let leftover = blocks.saturating_sub(6 * INTERVAL);
    total + BigInt::from(leftover) * BigInt::from(10_000 * COIN)
}

fn cumulative_dash(base_reward: i64, block_height: u64) -> BigInt {
    let mut total = BigInt::zero();
    let years = block_height / DASH_BLOCKS_PER_YEAR;
    let remainder = (block_height % DASH_BLOCKS_PER_YEAR) + 1;

    // the reward only decreases, so nothing is minted past the first zero year
    for i in 0..years.min(DASH_ZERO_YEAR) {
        total += dash_yearly(base_reward, i) * BigInt::from(DASH_BLOCKS_PER_YEAR);
    }
    total + dash_yearly(base_reward, years) * BigInt::from(remainder)
}

fn dash_yearly(base_reward: i64, year_index: u64) -> BigInt {
    if year_index >= DASH_ZERO_YEAR {
        return BigInt::zero();
    }
    let year = year_index as u32; // < DASH_ZERO_YEAR
    (BigInt::from(base_reward) * BigInt::from(13).pow(year)) / BigInt::from(14).pow(year)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bi(v: i64) -> BigInt {
        BigInt::from(v)
    }

    #[test]
    fn block_rewards() {
        assert_eq!(block_reward("bitcoin", 0).unwrap(), bi(50 * 100_000_000));
        assert_eq!(
            block_reward("bitcoin", 209_999).unwrap(),
            bi(50 * 100_000_000)
        );
        assert_eq!(
            block_reward("bitcoin", 210_000).unwrap(),
            bi(25 * 100_000_000)
        );
        assert_eq!(block_reward("litecoin", 0).unwrap(), bi(50 * 100_000_000));
        assert_eq!(
            block_reward("dogecoin", 0).unwrap(),
            bi(1_000_000 * 100_000_000)
        );
        assert_eq!(
            block_reward("dogecoin", 600_000).unwrap(),
            bi(10_000 * 100_000_000)
        );
        assert_eq!(block_reward("dash", 0).unwrap(), bi(5 * 100_000_000));
        assert_eq!(block_reward("dash", 210_240).unwrap(), bi(464_285_714));
        assert_eq!(block_reward("electraproto", 100).unwrap(), bi(0));
        assert_eq!(block_reward("bitcoin", 100 * 210_000).unwrap(), bi(0));
        assert!(block_reward("unsupported", 0).is_err());
    }

    #[test]
    fn cumulative_rewards() {
        assert_eq!(
            cumulative_reward("bitcoin", 0).unwrap(),
            bi(50 * 100_000_000)
        );
        assert_eq!(
            cumulative_reward("bitcoin", 1).unwrap(),
            bi(100 * 100_000_000)
        );
        assert_eq!(
            cumulative_reward("bitcoin", 209_999).unwrap(),
            bi(10_500_000) * bi(100_000_000)
        );
        assert_eq!(
            cumulative_reward("bitcoin", 210_000).unwrap(),
            bi(10_500_025) * bi(100_000_000)
        );
        assert_eq!(
            cumulative_reward("dogecoin", 0).unwrap(),
            bi(1_000_000 * 100_000_000)
        );
        assert_eq!(
            cumulative_reward("dogecoin", 1).unwrap(),
            bi(2_000_000 * 100_000_000)
        );
        assert_eq!(
            cumulative_reward("dogecoin", 100_000).unwrap(),
            bi(100_000_500_000) * bi(100_000_000)
        );
        assert_eq!(
            cumulative_reward("dogecoin", 600_000).unwrap(),
            bi(196_875_010_000) * bi(100_000_000)
        );
        assert_eq!(cumulative_reward("electraproto", 999).unwrap(), bi(0));
        assert_eq!(cumulative_reward("dash", 0).unwrap(), bi(5 * 100_000_000));
        assert_eq!(cumulative_reward("dash", 1).unwrap(), bi(10 * 100_000_000));
        assert!(cumulative_reward("dash", 210_240).unwrap().sign() == num_bigint::Sign::Plus);
        assert!(cumulative_reward("unsupported", 0).is_err());
    }

    /// The uncapped Dash formula, to check the cap against.
    fn dash_formula(year: u32) -> BigInt {
        (bi(5 * 100_000_000) * bi(13).pow(year)) / bi(14).pow(year)
    }

    #[test]
    fn dash_zero_year_is_exact() {
        let last = (DASH_ZERO_YEAR - 1) as u32;
        assert_eq!(dash_formula(last), bi(1));
        assert_eq!(dash_formula(last + 1), bi(0));
        for year in 0..DASH_ZERO_YEAR + 5 {
            assert_eq!(
                dash_yearly(5 * 100_000_000, year),
                dash_formula(year as u32),
                "year {year}"
            );
            assert_eq!(
                block_reward("dash", year * DASH_BLOCKS_PER_YEAR).unwrap(),
                dash_formula(year as u32)
            );
        }
        // the cumulative total matches a plain per-year sum, before and after
        // the reward reaches zero
        for (years, extra) in [(3u64, 17u64), (270, 0), (271, 5), (300, 210_239)] {
            let mut want = BigInt::zero();
            for y in 0..years {
                want += dash_formula(y as u32) * bi(DASH_BLOCKS_PER_YEAR as i64);
            }
            want += dash_formula(years as u32) * bi(extra as i64 + 1);
            assert_eq!(
                cumulative_reward("dash", years * DASH_BLOCKS_PER_YEAR + extra).unwrap(),
                want,
                "{years} years"
            );
        }
    }

    /// Extreme heights neither overflow nor take unbounded time.
    #[test]
    fn extreme_heights() {
        const COIN: i64 = 100_000_000;
        let max = u64::MAX;

        // bitcoin: the full schedule, 210,000 blocks at each of 33 rewards
        let mut supply = BigInt::zero();
        for halving in 0..33 {
            supply += bi(210_000) * bi((50 * COIN) >> halving);
        }
        assert_eq!(cumulative_reward("bitcoin", max).unwrap(), supply);
        assert_eq!(
            cumulative_reward("bitcoin", 33 * 210_000 - 1).unwrap(),
            supply
        );
        assert_eq!(block_reward("bitcoin", max).unwrap(), bi(0));
        for net in ["litecoin", "monacoin", "namecoin", "bitcoin-cash"] {
            assert!(cumulative_reward(net, max).unwrap() > bi(0), "{net}");
            assert_eq!(block_reward(net, max).unwrap(), bi(0), "{net}");
        }

        // dogecoin: 10,000 DOGE for every block from 600,000 on
        let at_600k = cumulative_reward("dogecoin", 599_999).unwrap();
        assert_eq!(at_600k, bi(196_875_000_000) * bi(COIN));
        assert_eq!(
            cumulative_reward("dogecoin", max).unwrap(),
            at_600k + (BigInt::from(max) + 1 - 600_000) * bi(10_000 * COIN)
        );
        assert_eq!(block_reward("dogecoin", max).unwrap(), bi(10_000 * COIN));

        // dash: nothing is minted once the reward is zero
        assert_eq!(block_reward("dash", max).unwrap(), bi(0));
        let total = cumulative_reward("dash", max).unwrap();
        assert_eq!(
            total,
            cumulative_reward("dash", DASH_ZERO_YEAR * DASH_BLOCKS_PER_YEAR).unwrap()
        );
        assert!(total > cumulative_reward("dash", 269 * DASH_BLOCKS_PER_YEAR).unwrap());

        assert_eq!(cumulative_reward("electraproto", max).unwrap(), bi(0));
    }
}
