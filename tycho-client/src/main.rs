// Only include this file for non-WASM builds
#[cfg(not(target_arch = "wasm32"))]
mod main_impl {
    use tycho_client::cli::run_cli;

    pub fn main() {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                run_cli().await;
            });
    }
}

// Entry point that only exists for non-WASM builds
#[cfg(not(target_arch = "wasm32"))]
fn main() {
    main_impl::main();
}
