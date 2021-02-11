let
  sources = import ./nix/sources.nix;
  pkgs = import sources.nixpkgs { };
  sgxsdk = /nix/store/znr7dg5bkv2kspcmqrak59hb88hcqv4k-sgxsdk;
in
pkgs.stdenv.mkDerivation {
  inherit sgxsdk;
  name = "sgx-quote";
  #src = ./.;
  src = pkgs.fetchFromGitHub {
    owner = "sbellem";
    repo = "sgx-quote-sample";
    rev = "a8ae70430be1d5ad3dd2962032d435b543c3552b";
    # Command to get the sha256 hash (note the --fetch-submodules arg):
    # nix run -f '<nixpkgs>' nix-prefetch-github -c nix-prefetch-github --rev a8ae70430be1d5ad3dd2962032d435b543c3552b sbellem sgx-quote-sample
    sha256 = "0d8czkfl0yk1d2d25d2siwxmkw22zx861xlcq30790mmq9ilph7m";
  };
  #source $SGX_SDK/environment
  preConfigure = ''
    export SGX_SDK=$sgxsdk/sgxsdk
    export PATH=$PATH:$SGX_SDK/bin:$SGX_SDK/bin/x64
    export PKG_CONFIG_PATH=$SGX_SDK/pkgconfig
    export LD_LIBRARY_PATH=$SGX_SDK/sdk_libs
    ./bootstrap
    '';
  configureFlags = ["--with-sgxsdk=$SGX_SDK"];
  buildInputs = with pkgs; [
    sgxsdk
    unixtools.xxd
    bashInteractive
    autoconf
    automake
    libtool
    file
    openssl
    which
  ];

  installPhase = ''
    runHook preInstall

    mkdir -p $out/bin
    cp Enclave/Enclave.so $out/bin/
    cp Enclave/Enclave.signed.so $out/bin/

    runHook postInstall
  '';
    #cp mrsigner $out/bin
  postInstall = ''
    $sgxsdk/sgxsdk/bin/x64/sgx_sign dump -cssfile enclave_sigstruct_raw -dumpfile /dev/null -enclave $out/bin/Enclave.signed.so
    cp enclave_sigstruct_raw $out/bin/
    '';
    #./mrsigner enclave_sigstruct_raw > $out/bin/mrsigner.txt
  dontFixup = true;
}
