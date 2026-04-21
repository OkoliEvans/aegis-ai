import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createConfig, http, WagmiProvider } from "wagmi";
import { mainnet } from "wagmi/chains";
import {
  injectStyles,
  InterwovenKitProvider,
  TESTNET
} from "@initia/interwovenkit-react";
import InterwovenKitStyles from "@initia/interwovenkit-react/styles.js";
import "@initia/interwovenkit-react/styles.css";

import App from "./App";
import { guardianFrontendConfig } from "./config";
import "./styles.css";

injectStyles(InterwovenKitStyles);

const queryClient = new QueryClient();
const wagmiConfig = createConfig({
  chains: [mainnet],
  transports: {
    [mainnet.id]: http()
  }
});

const customChain = {
  chain_id: guardianFrontendConfig.chain.id,
  chain_name: guardianFrontendConfig.chain.name,
  pretty_name: guardianFrontendConfig.chain.prettyName,
  network_type: "testnet",
  bech32_prefix: "init",
  apis: {
    rpc: [{ address: guardianFrontendConfig.api.guardianRpcUrl }],
    rest: [{ address: guardianFrontendConfig.chain.rest }],
    indexer: [{ address: guardianFrontendConfig.chain.indexer }],
    ...(guardianFrontendConfig.chain.jsonRpc
      ? { "json-rpc": [{ address: guardianFrontendConfig.chain.jsonRpc }] }
      : {})
  },
  fees: {
    fee_tokens: [
      {
        denom: guardianFrontendConfig.chain.denom,
        fixed_min_gas_price: 0,
        low_gas_price: 0,
        average_gas_price: 0,
        high_gas_price: 0
      }
    ]
  },
  staking: {
    staking_tokens: [{ denom: guardianFrontendConfig.chain.denom }]
  },
  native_assets: [
    {
      denom: guardianFrontendConfig.chain.denom,
      name: guardianFrontendConfig.chain.assetName,
      symbol: guardianFrontendConfig.chain.assetSymbol,
      decimals: guardianFrontendConfig.chain.assetDecimals
    }
  ],
  metadata: {
    is_l1: false,
    minitia: {
      type: guardianFrontendConfig.chain.vm
    }
  }
};

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <WagmiProvider config={wagmiConfig}>
      <QueryClientProvider client={queryClient}>
        <InterwovenKitProvider
          {...TESTNET}
          defaultChainId={guardianFrontendConfig.chain.id}
          customChain={customChain}
          customChains={[customChain]}
        >
          <App />
        </InterwovenKitProvider>
      </QueryClientProvider>
    </WagmiProvider>
  </React.StrictMode>
);
