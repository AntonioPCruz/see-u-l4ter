{ 
description = "Flake to manage my Distributed Systems uni course.";

inputs.nixpkgs.url = "nixpkgs/nixpkgs-unstable";

outputs = inputs: 
let
  system = "aarch64-darwin";
  pkgs = inputs.nixpkgs.legacyPackages.${system};
in { 
  devShell.${system} = pkgs.mkShell {
    name = "openssl-shell";
    buildInputs = with pkgs; [ openssl ncurses ];

    shellHook = ''
      export OPENSSL_DIR=${pkgs.openssl.dev};
      export OPENSSL_INCLUDE_DIR=${pkgs.openssl.dev}/include;
      export OPENSSL_LIB_DIR=${pkgs.openssl.out}/lib;
    '';
  };
 };
}
