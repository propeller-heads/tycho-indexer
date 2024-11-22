let
  mozillaOverlay =
    import (builtins.fetchGit {
      url = "https://github.com/mozilla/nixpkgs-mozilla.git";
      rev = "78e723925daf5c9e8d0a1837ec27059e61649cb6";
    });
  nixpkgs = import <nixpkgs> { overlays = [ mozillaOverlay ]; };
  rust-nightly = with nixpkgs; ((rustChannelOf { date = "2024-09-05"; channel = "stable"; }).rust.override {
    extensions = [ "rust-src" ];
  });
in
with nixpkgs; pkgs.mkShell {
  nativeBuildInputs = [
    tokio-console
    rust-nightly
  ];
  buildInputs = [
    pkg-config
    openssl.dev
  ] ++ lib.optionals stdenv.isDarwin [
    darwin.apple_sdk.frameworks.Security
  ];

  LD_LIBRARY_PATH = lib.makeLibraryPath [ openssl ];
}
