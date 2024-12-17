export type HexBytes = string;

export enum Chain {
  Ethereum = "ethereum",
  Starknet = "starknet",
  Arbitrum = "arbitrum",
}

export enum ChangeType {
  Update = "Update",
  Deletion = "Deletion",
  Creation = "Creation",
  Unspecified = "Unspecified",
}

export interface ProtocolComponentsParams {
  protocol_system?: string;
  component_addresses?: HexBytes[];
  tvl_gt?: number;
}

export interface ProtocolStateParams {
  include_balances?: boolean;
  protocol_ids?: { chain: Chain; id: string }[];
  protocol_system?: string;
  version?: {
    block?: {
      hash?: HexBytes;
      chain?: Chain;
      number?: number;
    };
    timestamp?: Date;
  };
}

export interface ContractStateParams {
  contract_ids?: string[];
  protocol_system?: string;
  version?: {
    block?: {
      hash?: HexBytes;
      chain?: Chain;
      number?: number;
    };
    timestamp?: Date;
  };
}

export interface TokensParams {
  min_quality?: number;
  pagination?: {
    page?: number;
    page_size?: number;
  };
  token_addresses?: HexBytes[];
  traded_n_days_ago?: number;
}

export interface FeedMessage {
  state_msgs: Record<string, StateSyncMessage>;
  sync_states: Record<string, SynchronizerState>;
}

export interface StateSyncMessage {
  header: Header;
  snapshots: Snapshot;
  deltas?: BlockChanges;
  removed_components: Record<string, ProtocolComponent>;
}

export interface Header {
  number: number;
  hash: HexBytes;
  parent_hash: HexBytes;
  revert: boolean;
}

export interface Snapshot {
  states: Record<string, ComponentWithState>;
  vm_storage: Record<HexBytes, ResponseAccount>;
}

export interface ComponentWithState {
  state: ResponseProtocolState;
  component: ProtocolComponent;
}

export interface BlockChanges {
  extractor: string;
  chain: Chain;
  block: Block;
  finalized_block_height: number;
  revert: boolean;
  new_tokens: Record<HexBytes, ResponseToken>;
  account_updates: Record<HexBytes, AccountUpdate>;
  state_updates: Record<string, ProtocolStateDelta>;
  new_protocol_components: Record<string, ProtocolComponent>;
  deleted_protocol_components: Record<string, ProtocolComponent>;
  component_balances: Record<string, TokenBalances>;
  component_tvl: Record<string, number>;
}

export interface Block {
  number: number;
  hash: HexBytes;
  parent_hash: HexBytes;
  chain: Chain;
  ts: Date;
}

export interface ProtocolComponent {
  id: string;
  protocol_system: string;
  protocol_type_name: string;
  chain: Chain;
  tokens: HexBytes[];
  contract_ids: HexBytes[];
  static_attributes: Record<string, HexBytes>;
  change: ChangeType;
  creation_tx: HexBytes;
  created_at: Date;
}

export interface ResponseProtocolState {
  component_id: string;
  attributes: Record<string, HexBytes>;
  balances: Record<HexBytes, HexBytes>;
}

export interface ResponseAccount {
  chain: Chain;
  address: HexBytes;
  title: string;
  slots: Record<HexBytes, HexBytes>;
  balance: HexBytes;
  code: HexBytes;
  code_hash: HexBytes;
  balance_modify_tx: HexBytes;
  code_modify_tx: HexBytes;
  creation_tx?: HexBytes;
}

export interface ResponseToken {
  chain: Chain;
  address: HexBytes;
  symbol: string;
  decimals: number;
  tax: number;
  gas: (number | null)[];
  quality: number;
}

export enum SynchronizerStateEnum {
  Started = "started",
  Ready = "ready",
  Stale = "stale",
  Delayed = "delayed",
  Advanced = "advanced",
  Ended = "ended",
}

export interface SynchronizerState {
  status: SynchronizerStateEnum;
  header?: Header;
}

export interface AccountUpdate {
  address: HexBytes;
  chain: Chain;
  slots: Record<HexBytes, HexBytes>;
  balance?: HexBytes;
  code?: HexBytes;
  change: ChangeType;
}

export interface ProtocolStateDelta {
  component_id: string;
  updated_attributes: Record<string, HexBytes>;
  deleted_attributes: string[];
}

export interface TokenBalances {
  [key: string]: ComponentBalance;
}

export interface ComponentBalance {
  token: HexBytes;
  balance: HexBytes;
  balance_float: number;
  modify_tx: HexBytes;
  component_id: string;
}
