{ pkgs ? import <nixpkgs> { } }:
let manifest = (pkgs.lib.importTOML ./Cargo.toml).package;
in
pkgs.rustPlatform.buildRustPackage rec {
  nativeBuildInputs = with pkgs; [ cmake pkg-config ncurses6.dev ];
  OPENSSL_NO_VENDOR = 1;
  PKG_CONFIG_PATH="${pkgs.openssl.dev}/lib/pkgconfig";

  pname = manifest.name;
  version = manifest.version;
  cargoLock.lockFile = ./Cargo.lock;
  src = pkgs.lib.cleanSource ./.;
  buildInputs = with pkgs; [ darwin.apple_sdk.frameworks.Foundation openssl_1_1 openssl_1_1.dev ];
}
