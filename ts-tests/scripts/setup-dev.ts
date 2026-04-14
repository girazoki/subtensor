/**
 * setup-dev.ts
 *
 * Starts a fresh local node with instant sealing, then sets up subnets,
 * funded accounts, and initial alpha stakes as specified in a JSON config.
 *
 * Staking TAO naturally seeds each subnet's AMM pool (increases SubnetTAO
 * and mints alpha) — no separate pool-seeding step is needed or available.
 *
 * Usage:
 *   pnpm tsx scripts/setup-dev.ts [path/to/config.json]
 *
 * Defaults to scripts/setup-dev.json if no path is given.
 * The node keeps running after setup — press Ctrl+C to stop it.
 */

import { ApiPromise, WsProvider, Keyring } from "@polkadot/api";
import { spawn, type ChildProcess } from "child_process";
import { readFileSync } from "fs";
import { resolve } from "path";

// ── Config types ──────────────────────────────────────────────────────────────

interface AccountConfig {
    uri: string;
    balanceTao: number;
}

interface StakeConfig {
    coldkeyUri: string;
    taoAmount: number;
}

interface SubnetConfig {
    ownerUri: string;
    hotkeyUri: string;
    stakes: StakeConfig[];
}

interface Config {
    nodeBinary: string;
    wsUrl: string;
    blockIntervalMs: number;
    fundAccounts: AccountConfig[];
    subnets: SubnetConfig[];
}

function loadConfig(configPath: string): Config {
    const raw = readFileSync(resolve(configPath), "utf-8");
    return JSON.parse(raw) as Config;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const RAO_PER_TAO = 1_000_000_000n;

function tao(amount: number): bigint {
    return BigInt(amount) * RAO_PER_TAO;
}

function startNode(binaryPath: string): ChildProcess {
    const abs = resolve(binaryPath);
    const args = ["--one", "--dev", "--force-authoring", "--sealing=manual", "--tmp",
                  "--rpc-cors=all", "--no-prometheus", "--no-telemetry", "--reserved-only"];
    console.log(`Starting: ${abs} ${args.join(" ")}\n`);
    const proc = spawn(abs, args, {
        stdio: ["ignore", "pipe", "pipe"],
    });
    proc.stdout?.on("data", (d: Buffer) => process.stdout.write(`[node] ${d}`));
    proc.stderr?.on("data", (d: Buffer) => process.stderr.write(`[node] ${d}`));
    return proc;
}

async function waitForNode(wsUrl: string, timeoutMs = 60_000): Promise<ApiPromise> {
    const deadline = Date.now() + timeoutMs;
    process.stdout.write(`Waiting for node at ${wsUrl}`);

    while (Date.now() < deadline) {
        process.stdout.write(".");
        try {
            const provider = new WsProvider(wsUrl, 0); // 0 = no auto-reconnect

            // Wait for actual TCP connection before creating the API.
            await new Promise<void>((resolve, reject) => {
                const timer = setTimeout(() => {
                    provider.disconnect().catch(() => {});
                    reject(new Error("timeout"));
                }, 2_000);
                provider.on("connected", () => { clearTimeout(timer); resolve(); });
                provider.on("error",     () => { clearTimeout(timer); reject(new Error("error")); });
                provider.connect().catch(reject);
            });

            const api = await ApiPromise.create({ provider, noInitWarn: true });
            await api.isReady;
            console.log(" ready!");
            return api;
        } catch {
            await new Promise((r) => setTimeout(r, 1_000));
        }
    }

    console.log();
    throw new Error(`Node did not become ready within ${timeoutMs / 1000}s`);
}

/**
 * Sign and submit a transaction into the pool, then seal a block.
 * Uses submitExtrinsic (fire-and-forget into pool) rather than signAndSend
 * subscriptions, which are unreliable with manual sealing.
 */
async function send(api: ApiPromise, tx: any, signer: any): Promise<void> {
    const signed = await tx.signAsync(signer, { nonce: -1 });
    await api.rpc.author.submitExtrinsic(signed);
    await (api.rpc as any).engine.createBlock(true /* createEmpty */, true /* finalize */);
}

// ── Setup steps ───────────────────────────────────────────────────────────────

async function setup(
    api: ApiPromise,
    config: Config
): Promise<Array<{ netuid: number; subnet: SubnetConfig }>> {
    const keyring = new Keyring({ type: "sr25519" });
    const alice = keyring.addFromUri("//Alice");
    const registered: Array<{ netuid: number; subnet: SubnetConfig }> = [];

    // 1. Relax rate limits so all subnet registrations can happen back-to-back.
    console.log("[1/4] Relaxing subnet rate limits...");
    await send(api, api.tx.sudo.sudo(api.tx.adminUtils.sudoSetLockReductionInterval(1)), alice);
    await send(api, api.tx.sudo.sudo(api.tx.adminUtils.sudoSetNetworkRateLimit(0)), alice);

    // 2. Fund accounts.
    console.log(`[2/4] Funding ${config.fundAccounts.length} account(s)...`);
    for (const acc of config.fundAccounts) {
        const pair = keyring.addFromUri(acc.uri);
        await send(
            api,
            api.tx.sudo.sudo(api.tx.balances.forceSetBalance(pair.address, tao(acc.balanceTao))),
            alice
        );
        console.log(`      ${acc.uri.padEnd(14)} ${pair.address}  ${acc.balanceTao} TAO`);
    }

    // 3. Register subnets, enable subtokens, associate hotkeys.
    console.log(`[3/4] Registering ${config.subnets.length} subnet(s)...`);
    for (const subnet of config.subnets) {
        const owner  = keyring.addFromUri(subnet.ownerUri);
        const hotkey = keyring.addFromUri(subnet.hotkeyUri);

        await send(api, api.tx.subtensorModule.registerNetwork(hotkey.address), owner);

        const events = await api.query.system.events() as any;
        const netuid = (events as any[])
            .find((e: any) => e.event.method === "NetworkAdded")
            .event.data[0].toNumber();

        await send(api, api.tx.sudo.sudo(api.tx.adminUtils.sudoSetSubtokenEnabled(netuid, true)), alice);
        await send(api, api.tx.subtensorModule.tryAssociateHotkey(hotkey.address), owner);

        registered.push({ netuid, subnet });
        console.log(`      netuid=${netuid}  owner=${subnet.ownerUri}  hotkey=${subnet.hotkeyUri}`);
    }

    // 4. Stake into each subnet.
    //    addStake moves TAO into SubnetTAO and mints alpha for the staker —
    //    this is the only way to seed AMM reserves on a live chain.
    console.log("[4/4] Staking (seeds pool reserves + gives alpha)...");
    for (const { netuid, subnet } of registered) {
        const hotkey = keyring.addFromUri(subnet.hotkeyUri);
        for (const stake of subnet.stakes) {
            const coldkey = keyring.addFromUri(stake.coldkeyUri);
            await send(
                api,
                api.tx.subtensorModule.addStake(hotkey.address, netuid, tao(stake.taoAmount)),
                coldkey
            );
            console.log(`      netuid=${netuid}  ${stake.coldkeyUri} staked ${stake.taoAmount} TAO`);
        }
    }

    return registered;
}

// ── Summary ───────────────────────────────────────────────────────────────────

async function getAlphaStake(api: ApiPromise, hotkey: string, coldkey: string, netuid: number): Promise<bigint> {
    const value = await api.query.subtensorModule.alphaV2(hotkey, coldkey, netuid) as any;
    const mantissa = BigInt(value.mantissa);
    const exponent = BigInt(value.exponent);
    return exponent >= 0n
        ? mantissa * 10n ** exponent
        : mantissa / 10n ** -exponent;
}

async function printSummary(
    api: ApiPromise,
    config: Config,
    registered: Array<{ netuid: number; subnet: SubnetConfig }>
): Promise<void> {
    const keyring = new Keyring({ type: "sr25519" });
    console.log("\n══════════════════════════════════════════════════════");
    console.log("  Dev node ready");
    console.log(`  WS  ${config.wsUrl}`);
    console.log("\n  Accounts:");
    for (const acc of config.fundAccounts) {
        const addr = keyring.addFromUri(acc.uri).address;
        console.log(`    ${acc.uri.padEnd(14)} ${addr}  (${acc.balanceTao} TAO)`);
    }
    console.log("\n  Subnets:");
    for (const { netuid, subnet } of registered) {
        const hotkey = keyring.addFromUri(subnet.hotkeyUri);
        console.log(`    netuid=${netuid}  owner=${subnet.ownerUri}`);
        for (const stake of subnet.stakes) {
            const coldkey = keyring.addFromUri(stake.coldkeyUri);
            const alpha = await getAlphaStake(api, hotkey.address, coldkey.address, netuid);
            const alphaTao = Number(alpha) / 1e9;
            console.log(`      ${stake.coldkeyUri.padEnd(14)} alpha=${alphaTao.toFixed(4)}`);
        }
    }
    console.log("\n  Press Ctrl+C to stop the node.");
    console.log("══════════════════════════════════════════════════════\n");
}

// ── Entry point ───────────────────────────────────────────────────────────────

async function main(): Promise<void> {
    const configPath = process.argv[2] ?? "scripts/setup-dev.json";
    const config = loadConfig(configPath);

    let shuttingDown = false;
    const nodeProc = startNode(config.nodeBinary);

    nodeProc.on("exit", (code) => {
        if (shuttingDown) {
            console.log("Node stopped.");
            process.exit(0);
        } else {
            console.log(`Node exited unexpectedly with code ${code}`);
            process.exit(code ?? 1);
        }
    });

    process.on("SIGINT", () => {
        if (shuttingDown) return;
        shuttingDown = true;
        console.log("\nShutting down...");
        nodeProc.kill("SIGTERM");
        // Force-kill if it doesn't stop within 5 s.
        setTimeout(() => {
            try { nodeProc.kill("SIGKILL"); } catch {}
        }, 5_000).unref();
    });

    console.log(`Waiting for node at ${config.wsUrl}...`);
    const api = await waitForNode(config.wsUrl);
    console.log("Node ready.\n");

    const registered = await setup(api, config);
    await printSummary(api, config, registered);

    // Periodically seal a block so transactions submitted externally
    // (e.g. from a frontend or backend) are included automatically.
    console.log(`Sealing a block every ${config.blockIntervalMs}ms. Node is ready for external use.\n`);
    setInterval(async () => {
        try {
            // createEmpty: true — always produce a block so polkadot.js subscriptions
            // see proper inBlock → finalized transitions and don't retry banned hashes.
            await (api.rpc as any).engine.createBlock(true /* createEmpty */, true /* finalize */);
        } catch (e) {
            console.error("[seal]", e);
        }
    }, config.blockIntervalMs);

    // Keep alive so the node keeps running.
    await new Promise(() => {});
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
