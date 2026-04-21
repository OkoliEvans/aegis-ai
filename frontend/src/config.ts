type ConfigKey =
  | "VITE_API_BASE_URL"
  | "VITE_GUARDIAN_RPC"
  | "VITE_CHAIN_ID"
  | "VITE_CHAIN_NAME"
  | "VITE_CHAIN_PRETTY_NAME"
  | "VITE_CHAIN_RPC"
  | "VITE_CHAIN_REST"
  | "VITE_CHAIN_INDEXER"
  | "VITE_CHAIN_JSON_RPC"
  | "VITE_CHAIN_DENOM"
  | "VITE_CHAIN_ASSET_NAME"
  | "VITE_CHAIN_ASSET_SYMBOL"
  | "VITE_CHAIN_ASSET_DECIMALS"
  | "VITE_CHAIN_VM"
  | "VITE_GUARDIAN_POLICY_CONTRACT_ADDRESS"
  | "VITE_DEMO_RISK_LAB_CONTRACT_ADDRESS"
  | "VITE_BRIDGE_SOURCE_CHAIN_ID"
  | "VITE_BRIDGE_SOURCE_DENOM";

export type GuardianFrontendConfig = {
  api: {
    baseUrl: string;
    guardianRpcUrl: string;
  };
  chain: {
    id: string;
    name: string;
    prettyName: string;
    upstreamRpc: string;
    rest: string;
    indexer: string;
    jsonRpc?: string;
    denom: string;
    assetName: string;
    assetSymbol: string;
    assetDecimals: number;
    vm: string;
  };
  contract: {
    guardianPolicyAddress?: string;
    demoRiskLabAddress?: string;
  };
  bridge: {
    sourceChainId: string;
    sourceDenom: string;
  };
  fallbacksInUse: ConfigKey[];
  usingFallbacks: boolean;
};

function inferHost() {
  if (typeof window === "undefined") {
    return "localhost";
  }

  return window.location.hostname || "localhost";
}

function inferProtocol() {
  if (typeof window !== "undefined" && window.location.protocol === "https:") {
    return "https:";
  }

  return "http:";
}

function buildLocalDemoFallbacks(): Record<ConfigKey, string> {
  const host = inferHost();
  const protocol = inferProtocol();

  return {
    VITE_API_BASE_URL: `${protocol}//${host}:3000`,
    VITE_GUARDIAN_RPC: `${protocol}//${host}:3000/rpc`,
    VITE_CHAIN_ID: "aegis-guard",
    VITE_CHAIN_NAME: "Guardian",
    VITE_CHAIN_PRETTY_NAME: "Guardian Appchain",
    VITE_CHAIN_RPC: `${protocol}//${host}:26657`,
    VITE_CHAIN_REST: `${protocol}//${host}:1317`,
    VITE_CHAIN_INDEXER: `${protocol}//${host}:8088`,
    VITE_CHAIN_JSON_RPC: "",
    VITE_CHAIN_DENOM: "umin",
    VITE_CHAIN_ASSET_NAME: "Guardian Token",
    VITE_CHAIN_ASSET_SYMBOL: "GRD",
    VITE_CHAIN_ASSET_DECIMALS: "6",
    VITE_CHAIN_VM: "miniwasm",
    VITE_GUARDIAN_POLICY_CONTRACT_ADDRESS:
      "init1qg5ega6dykkxc307y25pecuufrjkxkaggkkxh7nad0vhyhtuhw3sfl43fx",
    VITE_DEMO_RISK_LAB_CONTRACT_ADDRESS:
      "init1qg5ega6dykkxc307y25pecuufrjkxkaggkkxh7nad0vhyhtuhw3sfl43fx",
    VITE_BRIDGE_SOURCE_CHAIN_ID: "initiation-2",
    VITE_BRIDGE_SOURCE_DENOM: "uinit"
  };
}

function resolveValue(
  envValue: string | undefined,
  label: ConfigKey,
  fallback: string,
  fallbacksInUse: ConfigKey[]
) {
  const trimmed = envValue?.trim();
  if (trimmed) {
    return trimmed;
  }

  if (fallback) {
    fallbacksInUse.push(label);
  }

  return fallback;
}

function parseDecimals(value: string) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : 6;
}

function resolveGuardianFrontendConfig(env: ImportMetaEnv): GuardianFrontendConfig {
  const fallbacks = buildLocalDemoFallbacks();
  const fallbacksInUse: ConfigKey[] = [];

  const apiBaseUrl = resolveValue(
    env.VITE_API_BASE_URL,
    "VITE_API_BASE_URL",
    fallbacks.VITE_API_BASE_URL,
    fallbacksInUse
  );
  const guardianRpcUrl = resolveValue(
    env.VITE_GUARDIAN_RPC,
    "VITE_GUARDIAN_RPC",
    fallbacks.VITE_GUARDIAN_RPC,
    fallbacksInUse
  );
  const chainId = resolveValue(
    env.VITE_CHAIN_ID,
    "VITE_CHAIN_ID",
    fallbacks.VITE_CHAIN_ID,
    fallbacksInUse
  );
  const chainName = resolveValue(
    env.VITE_CHAIN_NAME,
    "VITE_CHAIN_NAME",
    fallbacks.VITE_CHAIN_NAME,
    fallbacksInUse
  );
  const chainPrettyName = resolveValue(
    env.VITE_CHAIN_PRETTY_NAME,
    "VITE_CHAIN_PRETTY_NAME",
    fallbacks.VITE_CHAIN_PRETTY_NAME,
    fallbacksInUse
  );
  const chainRpc = resolveValue(
    env.VITE_CHAIN_RPC,
    "VITE_CHAIN_RPC",
    fallbacks.VITE_CHAIN_RPC,
    fallbacksInUse
  );
  const chainRest = resolveValue(
    env.VITE_CHAIN_REST,
    "VITE_CHAIN_REST",
    fallbacks.VITE_CHAIN_REST,
    fallbacksInUse
  );
  const chainIndexer = resolveValue(
    env.VITE_CHAIN_INDEXER,
    "VITE_CHAIN_INDEXER",
    fallbacks.VITE_CHAIN_INDEXER,
    fallbacksInUse
  );
  const chainJsonRpc = resolveValue(
    env.VITE_CHAIN_JSON_RPC,
    "VITE_CHAIN_JSON_RPC",
    fallbacks.VITE_CHAIN_JSON_RPC,
    fallbacksInUse
  );
  const chainDenom = resolveValue(
    env.VITE_CHAIN_DENOM,
    "VITE_CHAIN_DENOM",
    fallbacks.VITE_CHAIN_DENOM,
    fallbacksInUse
  );
  const chainAssetName = resolveValue(
    env.VITE_CHAIN_ASSET_NAME,
    "VITE_CHAIN_ASSET_NAME",
    fallbacks.VITE_CHAIN_ASSET_NAME,
    fallbacksInUse
  );
  const chainAssetSymbol = resolveValue(
    env.VITE_CHAIN_ASSET_SYMBOL,
    "VITE_CHAIN_ASSET_SYMBOL",
    fallbacks.VITE_CHAIN_ASSET_SYMBOL,
    fallbacksInUse
  );
  const chainAssetDecimals = resolveValue(
    env.VITE_CHAIN_ASSET_DECIMALS,
    "VITE_CHAIN_ASSET_DECIMALS",
    fallbacks.VITE_CHAIN_ASSET_DECIMALS,
    fallbacksInUse
  );
  const chainVm = resolveValue(
    env.VITE_CHAIN_VM,
    "VITE_CHAIN_VM",
    fallbacks.VITE_CHAIN_VM,
    fallbacksInUse
  );
  const guardianPolicyAddress = resolveValue(
    env.VITE_GUARDIAN_POLICY_CONTRACT_ADDRESS,
    "VITE_GUARDIAN_POLICY_CONTRACT_ADDRESS",
    fallbacks.VITE_GUARDIAN_POLICY_CONTRACT_ADDRESS,
    fallbacksInUse
  );
  const demoRiskLabAddress = resolveValue(
    env.VITE_DEMO_RISK_LAB_CONTRACT_ADDRESS,
    "VITE_DEMO_RISK_LAB_CONTRACT_ADDRESS",
    fallbacks.VITE_DEMO_RISK_LAB_CONTRACT_ADDRESS,
    fallbacksInUse
  );
  const bridgeSourceChainId = resolveValue(
    env.VITE_BRIDGE_SOURCE_CHAIN_ID,
    "VITE_BRIDGE_SOURCE_CHAIN_ID",
    fallbacks.VITE_BRIDGE_SOURCE_CHAIN_ID,
    fallbacksInUse
  );
  const bridgeSourceDenom = resolveValue(
    env.VITE_BRIDGE_SOURCE_DENOM,
    "VITE_BRIDGE_SOURCE_DENOM",
    fallbacks.VITE_BRIDGE_SOURCE_DENOM,
    fallbacksInUse
  );

  return {
    api: {
      baseUrl: apiBaseUrl,
      guardianRpcUrl
    },
    chain: {
      id: chainId,
      name: chainName,
      prettyName: chainPrettyName,
      upstreamRpc: chainRpc,
      rest: chainRest,
      indexer: chainIndexer,
      jsonRpc: chainJsonRpc || undefined,
      denom: chainDenom,
      assetName: chainAssetName,
      assetSymbol: chainAssetSymbol,
      assetDecimals: parseDecimals(chainAssetDecimals),
      vm: chainVm
    },
    contract: {
      guardianPolicyAddress: guardianPolicyAddress || undefined,
      demoRiskLabAddress: demoRiskLabAddress || guardianPolicyAddress || undefined
    },
    bridge: {
      sourceChainId: bridgeSourceChainId,
      sourceDenom: bridgeSourceDenom
    },
    fallbacksInUse: Array.from(new Set(fallbacksInUse)),
    usingFallbacks: fallbacksInUse.length > 0
  };
}

export const guardianFrontendConfig = resolveGuardianFrontendConfig(import.meta.env);
