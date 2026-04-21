/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE_URL?: string;
  readonly VITE_CHAIN_ID?: string;
  readonly VITE_CHAIN_NAME?: string;
  readonly VITE_CHAIN_PRETTY_NAME?: string;
  readonly VITE_CHAIN_RPC?: string;
  readonly VITE_CHAIN_REST?: string;
  readonly VITE_CHAIN_INDEXER?: string;
  readonly VITE_CHAIN_JSON_RPC?: string;
  readonly VITE_CHAIN_DENOM?: string;
  readonly VITE_CHAIN_ASSET_NAME?: string;
  readonly VITE_CHAIN_ASSET_SYMBOL?: string;
  readonly VITE_CHAIN_ASSET_DECIMALS?: string;
  readonly VITE_CHAIN_VM?: string;
  readonly VITE_GUARDIAN_POLICY_CONTRACT_ADDRESS?: string;
  readonly VITE_BRIDGE_SOURCE_CHAIN_ID?: string;
  readonly VITE_BRIDGE_SOURCE_DENOM?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
