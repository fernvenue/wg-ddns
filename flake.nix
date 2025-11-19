{
  description = "WireGuard DDNS - A lightweight tool that provides DDNS dynamic DNS support for WireGuard";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages.default = pkgs.buildGoModule rec {
          pname = "wg-ddns";
          version = "0.1.2";

          src = ./.;

          vendorHash = "sha256-VfSLrWuvJF4XwAW2BQGxh+3v9RiWmPdysw/nIdt2A9M=";

          ldflags = [ "-s" "-w" ];

          installPhase = ''
            runHook preInstall
            mkdir -p $out/bin
            install -Dm755 $GOPATH/bin/wg-ddns $out/bin/wg-ddns
            runHook postInstall
          '';

          meta = with pkgs.lib; {
            description = "A lightweight tool that provides DDNS dynamic DNS support for WireGuard";
            homepage = "https://github.com/fernvenue/wg-ddns";
            license = licenses.gpl3Only;
            maintainers = [ ];
            platforms = platforms.linux ++ platforms.darwin;
            mainProgram = "wg-ddns";
          };
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go
            gotools
            gopls
            delve
          ];
        };
      });
}