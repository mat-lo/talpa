{ lib
, rustPlatform
, pkg-config
, openssl
, darwin
, stdenv
}:

rustPlatform.buildRustPackage rec {
  pname = "talpa";
  version = "0.1.0";

  src = ./.;

  cargoLock = {
    lockFile = ./Cargo.lock;
  };

  nativeBuildInputs = [
    pkg-config
  ];

  buildInputs = [
    openssl
  ] ++ lib.optionals stdenv.isDarwin [
    darwin.apple_sdk.frameworks.Security
    darwin.apple_sdk.frameworks.SystemConfiguration
  ];

  meta = with lib; {
    description = "Cloudflare Tunnel route manager";
    homepage = "https://github.com/mat-lo/talpa";
    license = licenses.mit;
    maintainers = [ ];
    mainProgram = "talpa";
  };
}
