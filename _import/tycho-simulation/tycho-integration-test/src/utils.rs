// TODO: to be shared with quickstarts
// /// Default to USDC if no token provided
// fn buy_token_address_for_chain(cli: &Cli, chain: &Chain) -> miette::Result<Bytes> {
//     let address = match &cli.buy_token {
//         token if token != DEFAULT_ARG_VALUE => token,
//         _ => match chain.to_string().as_str() {
//             "ethereum" => "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
//             "base" => "0x4200000000000000000000000000000000000006",
//             "unichain" => "0x4200000000000000000000000000000000000006",
//             _ => return Err(miette!("Execution does not yet support chain {chain}")),
//         },
//     };
//     Bytes::from_str(address)
//         .into_diagnostic()
//         .wrap_err("Invalid address for buy token")
// }
//
// /// Default to WETH if no token provided
// fn sell_token_address_for_chain(cli: &Cli, chain: &Chain) -> miette::Result<Bytes> {
//     let address = match &cli.buy_token {
//         token if token != DEFAULT_ARG_VALUE => token,
//         _ => match chain.to_string().as_str() {
//             "ethereum" => "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
//             "base" => "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
//             "unichain" => "0x078d782b760474a361dda0af3839290b0ef57ad6",
//             _ => return Err(miette!("Execution does not yet support chain {chain}")),
//         },
//     };
//     Bytes::from_str(address)
//         .into_diagnostic()
//         .wrap_err("Invalid address for buy token")
// }

// TODO: to be shared with quickstarts
// fn get_amounts_out(
//     message: Update,
//     pairs: &HashMap<String, ProtocolComponent>,
//     amount_in: BigUint,
//     sell_token: Token,
//     buy_token: Token,
// ) -> HashMap<String, BigUint> {
//     let mut amounts_out: HashMap<String, BigUint> = HashMap::new();
//     for (id, state) in message.states.into_iter() {
//         if let Some(component) = pairs.get(&id) {
//             let tokens = &component.tokens;
//             if HashSet::from([&buy_token, &sell_token])
//                 .is_subset(&HashSet::from_iter(tokens.iter()))
//             {
//                 // TODO
//                 // if let Ok(amount_out) =
//                 //     state.get_amount_out(amount_in.clone(), &buy_token, &sell_token)
//                 // {
//                 //     amounts_out.insert(id.clone(), amount_out.amount);
//                 // }
//                 if let Ok(amount_out) =
//                     state.get_amount_out(amount_in.clone(), &sell_token, &buy_token)
//                 {
//                     amounts_out.insert(id, amount_out.amount);
//                 }
//             }
//         }
//     }
//     amounts_out
// }

// TODO: to be shared with quickstarts
// /// Format token amounts to human-readable values
// fn format_token_amount(amount: &BigUint, token: &Token) -> String {
//     let decimal_amount = amount.to_f64().unwrap_or(0.0) / 10f64.powi(token.decimals as i32);
//     format!("{decimal_amount:.6}")
// }
//
// /// Calculate price ratios in both directions
// fn format_price_ratios(
//     amount_in: &BigUint,
//     amount_out: &BigUint,
//     token_in: &Token,
//     token_out: &Token,
// ) -> (f64, f64) {
//     let decimal_in = amount_in.to_f64().unwrap_or(0.0) / 10f64.powi(token_in.decimals as i32);
//     let decimal_out = amount_out.to_f64().unwrap_or(0.0) / 10f64.powi(token_out.decimals as i32);
//
//     if decimal_in > 0.0 && decimal_out > 0.0 {
//         let forward = decimal_out / decimal_in;
//         let reverse = decimal_in / decimal_out;
//         (forward, reverse)
//     } else {
//         (0.0, 0.0)
//     }
// }

// async fn simulate_swap_transaction(
//     provider: FillProvider<
//         JoinFill<Identity, WalletFiller<EthereumWallet>>,
//         RootProvider<Ethereum>,
//     >,
//     amount_in: &BigUint,
//     signer: &PrivateKeySigner,
//     sell_token_address: &Bytes,
//     tx: &Transaction,
//     chain: &Chain,
// ) -> miette::Result<()> {
//     info!("simulating swap transaction...");
//     let swap_request =
//         build_swap_tx_req(provider.clone(), signer.address(), tx.clone(), chain.id()).await?;
//     let payload = SimulatePayload {
//         block_state_calls: vec![SimBlock {
//             block_overrides: None,
//             state_overrides: Some(state_override),
//             calls: vec![swap_request],
//         }],
//         trace_transfers: true,
//         validation: true,
//         return_full_transactions: true,
//     };
//     // TODO: add retry logic to handle rate limiting
//     match provider.simulate(&payload).await {
//         Ok(output) => {
//             for block in output.iter() {
//                 info!("simulated block {}", block.inner.header.number);
//                 for (idx, transaction) in block.calls.iter().enumerate() {
//                     use alloy::{primitives::U256, sol_types::SolValue};
//                     let swap_amount = U256::abi_decode(&transaction.return_data)
//                         .map_err(|e| miette!("Failed to decode swap amount: {e:?}"))?;
//                     info!("Swap amount: {}", swap_amount);
//
//                     info!(
//                         "transaction {transaction_num}, status: {status:?}, gas used:
// {gas_used}",                         transaction_num = idx + 1,
//                         status = transaction.status,
//                         gas_used = transaction.gas_used
//                     );
//                 }
//             }
//             Ok(())
//         }
//         Err(e) => Err(miette!("error during simulation: {e:?}")),
//     }
// }

// async fn build_swap_tx_req(
//     provider: FillProvider<
//         JoinFill<Identity, WalletFiller<EthereumWallet>>,
//         RootProvider<Ethereum>,
//     >,
//     user_address: Address,
//     tx: Transaction,
//     chain_id: u64,
// ) -> miette::Result<TransactionRequest> {
//     let block = provider
//         .get_block_by_number(BlockNumberOrTag::Latest)
//         .await
//         .into_diagnostic()
//         .wrap_err("Failed to fetch latest block")?
//         .ok_or_else(|| miette::miette!("Block not found"))?;
//     let base_fee = block
//         .header
//         .base_fee_per_gas
//         .ok_or_else(|| miette::miette!("Base fee not available"))?;
//     let max_priority_fee_per_gas = 1_000_000_000u64;
//     let max_fee_per_gas = base_fee + max_priority_fee_per_gas;
//     let nonce = provider
//         .get_transaction_count(user_address)
//         .await
//         .into_diagnostic()
//         .wrap_err("Failed to get nonce")?;
//     let swap_request = TransactionRequest {
//         to: Some(TxKind::Call(Address::from_slice(&tx.to))),
//         from: Some(user_address),
//         value: Some(biguint_to_u256(&tx.value)),
//         input: TransactionInput { input: Some(AlloyBytes::from(tx.data)), data: None },
//         gas: Some(800_000u64),
//         chain_id: Some(chain_id),
//         max_fee_per_gas: Some(max_fee_per_gas.into()),
//         max_priority_fee_per_gas: Some(max_priority_fee_per_gas.into()),
//         nonce: Some(nonce + 1),
//         ..Default::default()
//     };
//     Ok(swap_request)
// }

// TODO: to be shared with quickstarts
// async fn execute_swap_transaction(
//     provider: FillProvider<
//         JoinFill<Identity, WalletFiller<EthereumWallet>>,
//         RootProvider<Ethereum>,
//     >,
//     amount_in: &BigUint,
//     signer: &PrivateKeySigner,
//     sell_token_address: &Bytes,
//     tx: &Transaction,
//     chain: &Chain,
// ) -> miette::Result<()> {
//     info!("executing by performing an approval (for permit2) and a swap transaction...");
//     let (approval_request, swap_request) = get_tx_requests(
//         provider.clone(),
//         biguint_to_u256(amount_in),
//         signer.address(),
//         Address::from_slice(sell_token_address),
//         tx.clone(),
//         chain.id(),
//     )
//     .await?;
//
//     // TODO: add retry logic to handle rate limiting
//     let approval_receipt = provider
//         .send_transaction(approval_request)
//         .await
//         .into_diagnostic()?;
//
//     let approval_result = approval_receipt
//         .get_receipt()
//         .await
//         .into_diagnostic()?;
//     info!(
//         "approval transaction sent with hash: {hash:?} and status: {status:?}",
//         hash = approval_result.transaction_hash,
//         status = approval_result.status()
//     );
//
//     // TODO: add retry logic to handle rate limiting
//     let swap_receipt = provider
//         .send_transaction(swap_request)
//         .await
//         .into_diagnostic()?;
//
//     let swap_result = swap_receipt
//         .get_receipt()
//         .await
//         .into_diagnostic()?;
//     info!(
//         "swap transaction sent with hash: {hash:?} and status: {status:?}",
//         hash = swap_result.transaction_hash,
//         status = swap_result.status()
//     );
//
//     if !swap_result.status() {
//         return Err(miette!(
//             "Swap transaction with hash {hash:?} failed.",
//             hash = swap_result.transaction_hash
//         ));
//     }
//
//     info!("swap executed successfully");
//
//     Ok(())
// }
