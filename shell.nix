{ pkgs ? import <nixpkgs> { } }:
pkgs.mkShell {
  inputsFrom = [ (pkgs.callPackage ./default.nix { }) ];
  buildInputs = with pkgs; [
    openssl_1_1 
    ncurses6
    darwin.apple_sdk.frameworks.Foundation
  ];

  shellHook = ''
    export OPENSSL_DIR=${pkgs.openssl_1_1.dev};
    export OPENSSL_INCLUDE_DIR=${pkgs.openssl_1_1.dev}/include;
    export OPENSSL_LIB_DIR=${pkgs.openssl_1_1.out}/lib;
    export OPENSSL_NO_VENDOR = 1;

    export PKG_CONFIG_PATH="${pkgs.openssl.dev}/lib/pkgconfig";
  '';
}
