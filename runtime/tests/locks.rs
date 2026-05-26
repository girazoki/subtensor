//! Integration tests for conviction lock behaviour under same-subnet `move_stake`.
//!
//! ## Security Finding 1 — Lock record not transferred on same-subnet hotkey move
//!
//! `validate_stake_transition` only calls `ensure_available_to_unstake` when
//! `origin_netuid != destination_netuid`. For same-subnet `move_stake` (same coldkey,
//! different hotkeys), `transfer_lock` returns early because the coldkey is unchanged,
//! meaning the move is not blocked AND the lock record stays on the origin hotkey.
//!
//! This creates a state inconsistency: alpha is on `hotkey_b` but the lock record
//! remains on `hotkey_a`. However, `available_to_unstake` sums across ALL hotkeys via
//! `total_coldkey_alpha_on_subnet`, so the lock still blocks unstaking from `hotkey_b`.
//!
//! The two tests here document this exact behaviour:
//! 1. The move succeeds and the lock record does NOT follow the stake.
//! 2. Despite the lock being on the old hotkey, the user cannot unstake from the new
//!    hotkey — enforcement is still effective.

#![allow(clippy::unwrap_used)]

use frame_support::{assert_noop, assert_ok, traits::Hooks};
use node_subtensor_runtime::{
    BuildStorage, Runtime, RuntimeGenesisConfig, RuntimeOrigin, SubtensorModule, System,
};
use pallet_subtensor::{
    BurnHalfLife, BurnIncreaseMult, FirstEmissionBlockNumber, Lock, NetworkRegistrationAllowed,
    SubnetAlphaIn, SubnetTAO, SubtokenEnabled, TxRateLimit,
};
use sp_runtime::{AccountId32, Saturating};
use substrate_fixed::types::U64F64;
use subtensor_runtime_common::{AlphaBalance, NetUid, TaoBalance, Token};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn new_test_ext() -> sp_io::TestExternalities {
    sp_tracing::try_init_simple();
    let mut ext: sp_io::TestExternalities = RuntimeGenesisConfig {
        balances: pallet_balances::GenesisConfig {
            balances: vec![],
            dev_accounts: None,
        },
        ..Default::default()
    }
    .build_storage()
    .expect("genesis storage should build")
    .into();
    ext.execute_with(|| {
        System::set_block_number(1);
        // Disable the tx rate limit so stake operations in the same block don't
        // trigger TxRateLimitExceeded (the real runtime default is 1000 blocks;
        // the mock sets it to 0).
        TxRateLimit::<Runtime>::put(0u64);
    });
    ext
}

/// Fund `account` with `amount` TAO using the pallet's own mint path so that
/// `TotalIssuance` stays consistent with `pallet_balances` (same pattern used
/// by `runtime/tests/evm_transaction_fee.rs`).
fn fund_account(account: &AccountId32, amount: TaoBalance) {
    let credit = SubtensorModule::mint_tao(amount);
    SubtensorModule::spend_tao(account, credit, amount)
        .expect("spend_tao should succeed after minting");
}

/// Finalize the current block (draining `StakingOperationRateLimiter`) and
/// advance to the next block number, so subsequent staking calls don't hit
/// the one-op-per-block-per-(hotkey, coldkey, netuid) guard.
fn step_block() {
    let n = System::block_number();
    SubtensorModule::on_finalize(n);
    System::set_block_number(n + 1);
}

/// Register a dynamic subnet owned by `owner_coldkey`/`owner_hotkey`, then
/// enable the subnet features that tests need.  Returns the newly registered
/// `NetUid`.
fn add_dynamic_subnet(owner_coldkey: &AccountId32, owner_hotkey: &AccountId32) -> NetUid {
    let netuid = SubtensorModule::get_next_netuid();
    let lock_cost = SubtensorModule::get_network_lock_cost();

    fund_account(
        owner_coldkey,
        lock_cost.saturating_add(TaoBalance::from(10_000_000_000u64)),
    );

    assert_ok!(SubtensorModule::register_network(
        RuntimeOrigin::signed(owner_coldkey.clone()),
        owner_hotkey.clone(),
    ));

    NetworkRegistrationAllowed::<Runtime>::insert(netuid, true);
    FirstEmissionBlockNumber::<Runtime>::insert(netuid, 0u64);
    SubtokenEnabled::<Runtime>::insert(netuid, true);
    BurnHalfLife::<Runtime>::insert(netuid, 1u16);
    BurnIncreaseMult::<Runtime>::insert(netuid, U64F64::from_num(1));

    netuid
}

/// Seed the AMM liquidity pool for `netuid` so that `add_stake` swaps succeed.
fn setup_reserves(netuid: NetUid, stake_tao: u64) {
    SubnetTAO::<Runtime>::set(
        netuid,
        TaoBalance::from(stake_tao.saturating_mul(1_000_000u64)),
    );
    SubnetAlphaIn::<Runtime>::set(
        netuid,
        AlphaBalance::from(stake_tao.saturating_mul(10_000_000u64)),
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// **Finding 1a — Same-subnet `move_stake` succeeds even when all alpha is locked.**
///
/// When `move_stake` is called with `origin_netuid == destination_netuid`, the lock
/// validation path is skipped: `validate_stake_transition` only calls
/// `ensure_available_to_unstake` for cross-subnet moves, and `transfer_lock` returns
/// early because the origin and destination coldkey are the same.
///
/// After the move:
/// - alpha is held by `hotkey_b` for the coldkey;
/// - the `Lock` record remains on `hotkey_a` — no lock is created on `hotkey_b`.
///
/// This documents the divergence: stake and lock records point to different hotkeys.
#[test]
fn test_move_stake_same_subnet_lock_not_transferred() {
    new_test_ext().execute_with(|| {
        let owner_coldkey = AccountId32::from([100u8; 32]);
        let owner_hotkey = AccountId32::from([101u8; 32]);
        let coldkey = AccountId32::from([1u8; 32]);
        let hotkey_a = AccountId32::from([2u8; 32]);
        let hotkey_b = AccountId32::from([3u8; 32]);

        // 1. Set up a dynamic subnet with AMM liquidity.
        let netuid = add_dynamic_subnet(&owner_coldkey, &owner_hotkey);
        let stake_tao_amount = 100_000_000_000u64;
        setup_reserves(netuid, stake_tao_amount);

        // 2. Fund the coldkey and stake into hotkey_a via the `add_stake` extrinsic.
        fund_account(
            &coldkey,
            TaoBalance::from(stake_tao_amount).saturating_add(TaoBalance::from(10_000_000_000u64)),
        );
        assert_ok!(SubtensorModule::create_account_if_non_existent(&coldkey, &hotkey_a));
        assert_ok!(SubtensorModule::add_stake(
            RuntimeOrigin::signed(coldkey.clone()),
            hotkey_a.clone(),
            netuid,
            TaoBalance::from(stake_tao_amount),
        ));
        step_block();

        let total_alpha = SubtensorModule::total_coldkey_alpha_on_subnet(&coldkey, netuid);
        assert!(total_alpha > AlphaBalance::ZERO, "stake should produce some alpha");

        // 3. Enable perpetual lock mode for this coldkey via the `set_perpetual_lock`
        //    extrinsic, so locked_mass stays constant and the lock remains clearly
        //    visible after the move.
        assert_ok!(SubtensorModule::set_perpetual_lock(
            RuntimeOrigin::signed(coldkey.clone()),
            netuid,
            true,
        ));

        // 4. Lock ALL alpha to hotkey_a via the `lock_stake` extrinsic.
        assert_ok!(SubtensorModule::lock_stake(
            RuntimeOrigin::signed(coldkey.clone()),
            hotkey_a.clone(),
            netuid,
            total_alpha,
        ));
        step_block();

        // Confirm the lock exists on hotkey_a before the move.
        let lock_before = Lock::<Runtime>::get((&coldkey, netuid, &hotkey_a));
        assert!(lock_before.is_some(), "lock must exist on hotkey_a before the move");
        assert!(
            lock_before.unwrap().locked_mass > AlphaBalance::ZERO,
            "locked_mass must be non-zero"
        );

        // 5. Register hotkey_b (no public extrinsic for this; internal helper used).
        assert_ok!(SubtensorModule::create_account_if_non_existent(&coldkey, &hotkey_b));

        // 6. Move ALL alpha from hotkey_a to hotkey_b on the SAME subnet via the
        //    `move_stake` extrinsic.  Despite the full lock, this must succeed because
        //    same-subnet moves bypass the lock check.
        let alpha_on_a =
            SubtensorModule::get_stake_for_hotkey_and_coldkey_on_subnet(&hotkey_a, &coldkey, netuid);
        assert!(alpha_on_a > AlphaBalance::ZERO, "hotkey_a must have stake to move");

        assert_ok!(SubtensorModule::move_stake(
            RuntimeOrigin::signed(coldkey.clone()),
            hotkey_a.clone(),
            hotkey_b.clone(),
            netuid,
            netuid,
            alpha_on_a,
        ));

        // 7. Alpha has moved: hotkey_a is empty, hotkey_b holds it all.
        let alpha_on_a_after =
            SubtensorModule::get_stake_for_hotkey_and_coldkey_on_subnet(&hotkey_a, &coldkey, netuid);
        assert_eq!(
            alpha_on_a_after,
            AlphaBalance::ZERO,
            "all alpha should have left hotkey_a"
        );

        let alpha_on_b_after =
            SubtensorModule::get_stake_for_hotkey_and_coldkey_on_subnet(&hotkey_b, &coldkey, netuid);
        assert!(alpha_on_b_after > AlphaBalance::ZERO, "hotkey_b should hold the moved alpha");

        // 8. The lock record did NOT follow the alpha — it is still on hotkey_a …
        let lock_a_after = Lock::<Runtime>::get((&coldkey, netuid, &hotkey_a));
        assert!(
            lock_a_after.is_some(),
            "lock should STILL be on hotkey_a after same-subnet move"
        );
        assert!(
            lock_a_after.unwrap().locked_mass > AlphaBalance::ZERO,
            "locked_mass on hotkey_a should remain non-zero"
        );

        // … and there is NO lock record on hotkey_b.
        let lock_b_after = Lock::<Runtime>::get((&coldkey, netuid, &hotkey_b));
        assert!(
            lock_b_after.is_none(),
            "no lock should have been created on hotkey_b"
        );
    });
}

/// **Finding 1b — Lock enforcement is still effective after the same-subnet move.**
///
/// Even though the lock record stays on `hotkey_a`, `available_to_unstake` uses
/// `total_coldkey_alpha_on_subnet` which sums alpha across ALL hotkeys for the coldkey.
/// Since the lock covers the full original alpha and that alpha simply moved to `hotkey_b`
/// (still counted in the total), `available_to_unstake == 0`.
///
/// Attempting to `remove_stake` from `hotkey_b` is rejected with `StakeUnavailable`.
///
/// This confirms the inconsistency is a record-keeping issue, not an exploitable bypass:
/// the user cannot extract locked alpha by moving it between hotkeys first.
#[test]
fn test_move_stake_same_subnet_lock_still_enforced_after_move() {
    new_test_ext().execute_with(|| {
        let owner_coldkey = AccountId32::from([100u8; 32]);
        let owner_hotkey = AccountId32::from([101u8; 32]);
        let coldkey = AccountId32::from([1u8; 32]);
        let hotkey_a = AccountId32::from([2u8; 32]);
        let hotkey_b = AccountId32::from([3u8; 32]);

        // --- Same setup as test 1 ---

        let netuid = add_dynamic_subnet(&owner_coldkey, &owner_hotkey);
        let stake_tao_amount = 100_000_000_000u64;
        setup_reserves(netuid, stake_tao_amount);

        fund_account(
            &coldkey,
            TaoBalance::from(stake_tao_amount).saturating_add(TaoBalance::from(10_000_000_000u64)),
        );
        assert_ok!(SubtensorModule::create_account_if_non_existent(&coldkey, &hotkey_a));
        assert_ok!(SubtensorModule::add_stake(
            RuntimeOrigin::signed(coldkey.clone()),
            hotkey_a.clone(),
            netuid,
            TaoBalance::from(stake_tao_amount),
        ));
        step_block();

        let total_alpha = SubtensorModule::total_coldkey_alpha_on_subnet(&coldkey, netuid);

        assert_ok!(SubtensorModule::set_perpetual_lock(
            RuntimeOrigin::signed(coldkey.clone()),
            netuid,
            true,
        ));
        assert_ok!(SubtensorModule::lock_stake(
            RuntimeOrigin::signed(coldkey.clone()),
            hotkey_a.clone(),
            netuid,
            total_alpha,
        ));
        step_block();

        assert_ok!(SubtensorModule::create_account_if_non_existent(&coldkey, &hotkey_b));

        let alpha_on_a =
            SubtensorModule::get_stake_for_hotkey_and_coldkey_on_subnet(&hotkey_a, &coldkey, netuid);
        assert_ok!(SubtensorModule::move_stake(
            RuntimeOrigin::signed(coldkey.clone()),
            hotkey_a.clone(),
            hotkey_b.clone(),
            netuid,
            netuid,
            alpha_on_a,
        ));

        // --- Verify lock enforcement from hotkey_b ---

        let alpha_on_b =
            SubtensorModule::get_stake_for_hotkey_and_coldkey_on_subnet(&hotkey_b, &coldkey, netuid);
        assert!(
            alpha_on_b > AlphaBalance::ZERO,
            "hotkey_b must hold the moved alpha for this assertion to be meaningful"
        );

        // Attempting to remove stake from hotkey_b must fail: the lock on hotkey_a
        // still covers the full total_coldkey_alpha_on_subnet, so available == 0.
        assert_noop!(
            SubtensorModule::remove_stake(
                RuntimeOrigin::signed(coldkey.clone()),
                hotkey_b.clone(),
                netuid,
                alpha_on_b,
            ),
            pallet_subtensor::Error::<Runtime>::StakeUnavailable
        );
    });
}
