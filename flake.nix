{
  description = "MicroTAK server: a lightweight, mesh-federated TAK server for grid-down / island deployments";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
  };

  outputs =
    { self, nixpkgs, flake-utils, rust-overlay, crane }:
    flake-utils.lib.eachSystem
      [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ]
      (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };
          rustToolchain = pkgs.rust-bin.stable.latest.default;
          craneLib = (crane.mkLib pkgs).overrideToolchain (_: rustToolchain);

          src = craneLib.cleanCargoSource ./.;

          commonArgs = {
            inherit src;
            strictDeps = true;
            # Only pulled in on Darwin; a no-op list on Linux.
            buildInputs = pkgs.lib.optionals pkgs.stdenv.hostPlatform.isDarwin [
              pkgs.libiconv
              pkgs.darwin.apple_sdk.frameworks.Security
              pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
            ];
          };

          cargoArtifacts = craneLib.buildDepsOnly commonArgs;

          microtak-server = craneLib.buildPackage (
            commonArgs
            // {
              inherit cargoArtifacts;
              pname = "microtak-server";
              # Only the daemon binary is meant to be installed; the lib
              # crate exists for the test suite, not as a public artifact.
              cargoExtraArgs = "--locked --bin microtakd";
              doCheck = false; # see `checks.test` below -- run once, not twice
            }
          );
        in
        {
          packages = {
            default = microtak-server;
            microtak-server = microtak-server;
          };

          apps.default = flake-utils.lib.mkApp {
            drv = microtak-server;
            name = "microtakd";
          };

          checks = {
            inherit microtak-server;

            test = craneLib.cargoTest (commonArgs // { inherit cargoArtifacts; });

            clippy = craneLib.cargoClippy (
              commonArgs
              // {
                inherit cargoArtifacts;
                cargoClippyExtraArgs = "--all-targets -- -D warnings";
              }
            );
          };

          devShells.default = pkgs.mkShell {
            inputsFrom = [ microtak-server ];
            packages = [ rustToolchain ];
          };
        }
      )
    // {
      # A plain package covers CLI-style usage (`nix run`); a NixOS module
      # is what makes this a real installable *service* -- the way an
      # operator running NixOS would actually want to run a server daemon,
      # per docs/PACKAGING.md's Phase 1 plan.
      nixosModules.default =
        {
          config,
          lib,
          pkgs,
          ...
        }:
        let
          cfg = config.services.microtak-server;
        in
        {
          options.services.microtak-server = {
            enable = lib.mkEnableOption "the MicroTAK server";

            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.microtak-server;
              description = "The microtak-server package to run.";
            };

            configFile = lib.mkOption {
              type = lib.types.nullOr lib.types.path;
              default = null;
              description = ''
                Path to a `microtak.toml`. Left unset, the server falls back
                to its own built-in defaults (see the upstream README).
              '';
            };
          };

          config = lib.mkIf cfg.enable {
            systemd.services.microtak-server = {
              description = "MicroTAK server";
              wantedBy = [ "multi-user.target" ];
              after = [ "network.target" ];
              environment = lib.mkIf (cfg.configFile != null) {
                MICROTAK_CONFIG = toString cfg.configFile;
              };
              serviceConfig = {
                ExecStart = "${cfg.package}/bin/microtakd";
                Restart = "on-failure";
                DynamicUser = true;
                StateDirectory = "microtak-server";
                WorkingDirectory = "/var/lib/microtak-server";
                ProtectSystem = "strict";
                ProtectHome = true;
                NoNewPrivileges = true;
              };
            };
          };
        };
    };
}
