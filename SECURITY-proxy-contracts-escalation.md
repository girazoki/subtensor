# Security Finding: Restricted proxies can move funds via `pallet-contracts` (and `pallet-evm` / `pallet-crowdloan`)

- **Component:** `runtime` proxy call-filtering (`runtime/src/proxy_filters/`)
- **Branch:** `girazoki-v2-aot`
- **Severity:** High (documented proxy-type guarantee fully bypassed; direct theft of a delegator's native TAO and stake)
- **Status:** Confirmed with passing black-box PoC tests against the real runtime
- **Affected proxy types:** `NonTransfer`, `NonFungible` (and any other restricted type granted `InfraCommonCalls`)

---

## 1. Summary

The `NonTransfer` and `NonFungible` proxy types are documented as unable to move a
delegator's value — `NonFungible` is literally annotated *"Nothing involving moving TAO"*
(`common/src/proxy.rs:32`). Their filters explicitly deny `Balances::transfer_*` and
`SubtensorModule::transfer_stake`.

However, both proxy types are granted the `ContractsCalls` group (via `InfraCommonCalls`),
so a delegate holding such a proxy can dispatch `Contracts::call` **as the delegator**.
`pallet-contracts` is a general value-moving and origin-executing primitive:

- `Contracts::call { value }` debits `value` from the **origin** (the delegator, under
  `Proxy::proxy`), so the delegate can push the delegator's native TAO into an
  attacker-controlled contract that forwards it out.
- The subtensor chain-extension lets a contract dispatch subtensor calls; the `caller_*`
  variants dispatch **as the real caller** (the delegator, under proxy), so the delegate can
  execute `transfer_stake` and other denied staking calls as the delegator.

Net effect: a proxy the victim believes cannot move their TAO can move **all** of it —
native balance and stake — laundered through `pallet-contracts`.

The same class of leak also grants restricted proxies `EVM::*` (`EvmCalls`) and the
`Crowdloan` create→finalize arbitrary-call path (`CrowdloanCalls`); see §6.

---

## 2. Affected code

### 2.1 The leak

`InfraCommonCalls` bundles infrastructure pallets and is granted wholesale to the broad
restricted proxies. It contains value-moving / origin-executing pallets:

```
runtime/src/proxy_filters/call_groups.rs:643
pub(super) type InfraCommonCalls = (
    ...
    SchedulerCalls,      // :650  (inert — see §7)
    EthereumCalls,       // :654  (inert — see §7)
    EvmCalls,            // :655  (LEAK — see §6)
    ...
    CrowdloanCalls,      // :658  (LEAK — see §6)
    SwapCalls,           // :659  (lesser leak — see §6)
    ContractsCalls,      // :660  (PRIMARY — this finding)
    ...
    LimitOrdersCalls,    // :662  (lesser leak — see §6)
);
```

`NonTransfer` and `NonFungible` both include `InfraCommonCalls`:

- `runtime/src/proxy_filters/mod.rs:53` — `NonTransferAllowed = (InfraCommonCalls, ...)`
- `runtime/src/proxy_filters/mod.rs:72` — `NonFungibleAllowed = (InfraCommonCalls, ...)`

`ContractsCalls` includes `Contracts::call` / `instantiate*`:

- `runtime/src/proxy_filters/call_groups.rs:143-155`

### 2.2 Why it dispatches as the victim

`pallet-proxy` dispatches the inner call with a freshly built `Signed(real)` origin:

```
pallets/proxy/src/lib.rs:1126
let mut origin: T::RuntimeOrigin = frame_system::RawOrigin::Signed(real.clone()).into();
```

So `Contracts::call`'s origin is the delegator. `pallet-contracts` transfers `value` from
that origin (`substrate .../frame/contracts/src/lib.rs::call`, arg order
`dest, value, gas_limit, storage_deposit_limit, data`).

### 2.3 Permissionless contract deployment

Anyone can upload and instantiate contracts:

```
runtime/src/lib.rs:1455  type UploadOrigin      = EnsureSigned<AccountId>;
runtime/src/lib.rs:1456  type InstantiateOrigin = EnsureSigned<AccountId>;
```

### 2.4 Chain-extension caller/origin semantics (stake vector)

```
chain-extensions/src/lib.rs:983  fn caller(&mut self) -> AccountId { self.env.ext().address().clone() }  // the CONTRACT
chain-extensions/src/lib.rs:987  fn origin(&mut self) -> Origin     { self.env.ext().caller() }             // the REAL caller
```

- `*_stake` messages dispatch as `env.caller()` = the **contract's** address.
- `caller_*_stake` messages dispatch as `env.origin()` = the **real caller** = the delegator
  under `Proxy::proxy`.

So `caller_transfer_stake` executes `SubtensorModule::transfer_stake` **as the delegator**,
bypassing the `StakeTransferCalls` denial in `NonTransfer`/`NonFungible`.

---

## 3. Exploit — native TAO drain

Precondition: the attacker holds a `NonTransfer`/`NonFungible` proxy over a victim who has
free balance.

1. Attacker deploys a payable contract that sweeps received value (see `ink-contract-drainer/`).
2. Attacker signs:

   ```
   Proxy::proxy {
     real: victim,
     force_proxy_type: None,          // matches the existing NonFungible proxy
     call: Contracts::call {
       dest:  <attacker contract>,
       value: <victim free balance>,
       data:  steal(payout),          // payable; terminates, forwarding balance to payout
     }
   }
   ```

3. `Contracts::call` passes the `NonFungible` filter, dispatches as the victim, `value` is
   debited from the victim, the contract terminates and forwards it to the attacker.

**Observed (PoC):** victim `99999906839580 → 9999906854496` (−90,000 TAO), payout
`0 → 90000000000500` (+90,000 TAO). `ProxyExecuted = Ok`.

---

## 4. Exploit — stake theft (no custom contract needed)

Precondition: proxy as above; victim has stake. Uses the stock `ts-tests/ink/bittensor.wasm`.

```
Proxy::proxy {
  real: victim,
  call: Contracts::call {
    dest: <bittensor contract>,
    value: 0,
    data: caller_transfer_stake(destination_coldkey = attacker, hotkey, netuid, netuid, amount),
  }
}
```

The `caller_transfer_stake` message dispatches `transfer_stake` as `env.origin()` = the
victim, moving the victim's alpha to the attacker's coldkey.

**Observed (PoC):** victim stake `449886673230 → 224943336615`, attacker stake
`0 → 224943336615`; events `StakeRemoved, StakeAdded, StakeTransferred, contracts.Called`.
`ProxyExecuted = Ok`.

> Note: the plain `transfer_stake` message runs as the *contract's* address (§2.4) and reverts
> (no stake) — it is **not** the exploit; `caller_transfer_stake` is.

---

## 5. Impact and scope

- **Impact:** complete violation of the `NonTransfer`/`NonFungible` guarantee. A delegate can
  drain the delegator's native TAO and steal their stake.
- **Scope boundary:** bounded to the specific delegator that granted the proxy (and the
  delegate's own account). The origin is welded to `real` by `pallet-proxy`; it does not reach
  arbitrary third parties.
- **Preconditions:** (a) victim grants a `NonTransfer`/`NonFungible` proxy; (b) victim holds
  free balance (native vector) or stake (stake vector). Contract deployment is permissionless
  and reusable across victims (`steal`'s beneficiary is a call parameter).

---

## 6. Sibling leaks in the same tuple

- **`EvmCalls` (`:655`) — LEAK.** Same shape: `EVM::call`/`create` are value-moving/origin-
  executing and are granted to `NonTransfer`/`NonFungible`.
- **`CrowdloanCalls` (`:658`) — LEAK (arbitrary-call).** `Crowdloan::create` stores an
  arbitrary call (`pallets/crowdloan/src/lib.rs:347`); `finalize` dispatches it as the creator
  with a fresh, unfiltered `Signed(who)` origin (`pallets/crowdloan/src/lib.rs:649-651`). A
  restricted proxy can create as the victim, fund the cap, and finalize to run *any* call as
  the victim.
- **`SwapCalls` (`:659`) / `LimitOrdersCalls` (`:662`) — lesser.** Move the victim's TAO/alpha
  into pools/orders; contradicts "no value movement" though funds remain nominally the
  victim's.

---

## 7. Non-issues (grants that are inert)

- **`SchedulerCalls` (`:650`):** `ScheduleOrigin = EnsureRoot` (`runtime/src/lib.rs:672`); a
  signed proxy cannot schedule. Dead grant.
- **`EthereumCalls` (`:654`):** `Ethereum::transact` requires `RawOrigin::EthereumTransaction`;
  a signed proxy origin fails the origin check. Dead grant.
- **`Utility::batch*`:** re-dispatch inner calls with the same filtered origin, so the proxy
  filter re-applies; `dispatch_as` is `ensure_root`.

---

## 8. Root cause

The broad restricted proxies are defined **subtractively** — "all calls minus a denylist":

```
runtime/src/proxy_filters/mod.rs:305,316   allowed = all_runtime_calls() - denied
```

`InfraCommonCalls` is an "infrastructure" bucket that happens to contain value-moving and
origin-laundering pallets. Anything not explicitly denied leaks in, and the invariant tests
assert against the same denylist, so they pass while the guarantee is broken (they encode the
bug rather than detecting it).

Contrast Moonbeam, whose `NonTransfer` is **additive** (an explicit allowlist of ~13 named
pallets) and which blocks `RuntimeCall::EVM(_)` at the base call filter. A new value-moving
pallet there fails closed by default.

---

## 9. Remediation

1. **Immediate:** remove `EvmCalls`, `ContractsCalls`, and `CrowdloanCalls` from
   `InfraCommonCalls`; grant them only to `Any` and `NonCritical` (which permit value movement
   by design). Reconsider `SwapCalls`/`LimitOrdersCalls` for the "no value movement" types.
2. **Tests:** add `group_calls::<ContractsCalls>()` (and `EvmCalls`, `CrowdloanCalls`) to the
   denied sets in `non_transfer_is_*` / `non_fungible_is_*` so the invariant is actually
   asserted.
3. **Structural:** flip the broad proxies from subtractive denylists to **additive allowlists**
   so the next value-moving primitive is denied by default (fails closed).
4. **Crowdloan:** filter the stored `call` in `Crowdloan::create`/`finalize` (apply the
   creator's context filter, or restrict the stored-call surface).

---

## 10. Proof-of-concept

Black-box dev tests against the real runtime (`foundationMethods: "dev"`), each with a CONTROL
case (direct call → `system.CallFiltered`) and an EXPLOIT case (through `contracts` → succeeds):

- `ts-tests/suites/dev/subtensor/proxy/test-contracts-proxy-drain-funds.ts` — native TAO drain.
- `ts-tests/suites/dev/subtensor/proxy/test-contracts-proxy-escalation.ts` — stake theft.
- `ink-contract-drainer/` — the attacker contract (payable `steal` → `terminate_contract`).

Build + run:

```bash
# attacker contract (native-drain test only)
cd ink-contract-drainer && cargo contract build --release
cp target/ink/drainer.wasm ../ts-tests/ink/drainer.wasm
# run the dev suite
cd ../ts-tests && <your dev test runner>
```

Both tests pass; the full dev suite (93 tests) passes with no regressions.
