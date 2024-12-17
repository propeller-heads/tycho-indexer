import axios, { AxiosInstance } from "axios";
import {
  Chain,
  ProtocolComponent,
  ResponseProtocolState,
  ResponseAccount,
  ResponseToken,
  ProtocolComponentsParams,
  ProtocolStateParams,
  ContractStateParams,
  TokensParams,
} from "./dto";
import { TychoClientException } from "./exceptions";

interface RpcClientConfig {
  rpcUrl?: string;
  authToken?: string;
  chain?: Chain;
}

export class TychoRPCClient {
  private client: AxiosInstance;
  private chain: Chain;

  constructor({
    rpcUrl = "http://0.0.0.0:4242",
    authToken,
    chain = Chain.Ethereum,
  }: RpcClientConfig = {}) {
    this.client = axios.create({
      baseURL: rpcUrl,
      headers: {
        accept: "application/json",
        "Content-Type": "application/json",
        ...(authToken && { Authorization: authToken }),
      },
    });
    this.chain = chain;
  }

  private async postRequest(endpoint: string, body?: any): Promise<any> {
    try {
      const response = await this.client.post(endpoint, {
        ...body,
        chain: this.chain,
      });
      return response.data;
    } catch (error) {
      throw new TychoClientException(
        `Failed to post request to ${endpoint}: ${error.message}`
      );
    }
  }

  async getProtocolComponents(
    params: ProtocolComponentsParams
  ): Promise<ProtocolComponent[]> {
    const res = await this.postRequest("/v1/protocol_components", params);
    return res.protocol_components;
  }

  async getProtocolState(
    params: ProtocolStateParams
  ): Promise<ResponseProtocolState[]> {
    const res = await this.postRequest("/v1/protocol_state", params);
    return res.states;
  }

  async getContractState(
    params: ContractStateParams
  ): Promise<ResponseAccount[]> {
    const res = await this.postRequest("/v1/contract_state", params);
    return res.accounts;
  }

  async getTokens(params: TokensParams): Promise<ResponseToken[]> {
    const res = await this.postRequest("/v1/tokens", params);
    return res.tokens;
  }
}
