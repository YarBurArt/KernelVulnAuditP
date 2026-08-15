{
  description = "KernelVulnAuditP - Linux Kernel Vulnerability Analyzer & PoC Sandbox (QEMU-only)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";

    # Custom recon tool: kernel-focused LinPEAS script built from the PEASS
    # source via its builder (there is no nix package for it). lynis and
    # linux-exploit-suggester are shipped by nixpkgs directly.
    peass-src = { url = "github:peass-ng/PEASS-ng"; flake = false; };
  };

  outputs = { self, nixpkgs, flake-utils, peass-src }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        python = pkgs.python314;

        # Runtime tools the app shells out to. QEMU backend needs
        # qemu-system-x86_64, cpio, busybox and musl-gcc (the initrd build);
        # git is used to clone PoCs; gcc backs the musl-gcc wrapper.
        runtimeTools = [
          pkgs.lynis
          pkgs.linux-exploit-suggester
          linpeas
          pkgs.qemu_kvm
          pkgs.cpio
          pkgs.busybox
          pkgs.musl.dev
          pkgs.gcc
          pkgs.git
          pkgs.coreutils
          pkgs.findutils
        ];

        # Custom kernel-focused LinPEAS built from PEASS source. The
        # "kernel,CVE,exploit" module set pulls no external binaries and no
        # GTFOBins lists, so the build is offline-safe inside the nix sandbox.
        # Requires requests + pyyaml at build time.
        linpeas = pkgs.stdenv.mkDerivation {
          pname = "linpeas-kernel";
          version = "0.1.0";
          src = peass-src;
          nativeBuildInputs = [
            (python.withPackages (p: [ p.requests p.pyyaml ]))
          ];
          buildPhase = ''
            runHook preBuild
            mkdir -p $out/bin
            # the builder writes linpeas_base_tmp.sh / linpeas.sh next to the
            # sources, so work on a writable copy instead of the store path
            cp -r $src ./peass
            chmod -R u+w ./peass
            cd ./peass/linPEAS
            python -m builder.linpeas_builder \
              --include "kernel,CVE,exploit" \
              --output $out/bin/linpeas_kernel.sh
            chmod +x $out/bin/linpeas_kernel.sh
            runHook postBuild
          '';
          installPhase = "true";
        };

        appPython = python.withPackages (p: [
          p.httpx
          p.h2 # httpx[http2] runtime extra
          p.sqlalchemy
          p.rich
          p.textual
          p.streamlit # optional web report (kishirika-report)
        ]);

        appSrc = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = path: type: let
            base = builtins.baseNameOf path;
          in !(builtins.elem base [ ".venv" ".git" "result" "flake.lock" ]);
        };

        app = pkgs.stdenv.mkDerivation {
          pname = "kernelvulnauditp";
          version = "0.1.1";
          src = appSrc;
          nativeBuildInputs = [ pkgs.makeWrapper ];

          installPhase = ''
            runHook preInstall
            mkdir -p $out/share/kernelvulnauditp $out/bin
            cp -r . $out/share/kernelvulnauditp/

            # Point recon-tool paths at the store and force the QEMU backend
            substituteInPlace $out/share/kernelvulnauditp/config.py \
              --replace '"/tmp/linpeas_kernel.sh"' '"${linpeas}/bin/linpeas_kernel.sh"' \
              --replace '"/tmp/linux-exploit-suggester/linux-exploit-suggester.sh"' '"${pkgs.linux-exploit-suggester}/bin/linux-exploit-suggester"' \
              --replace '"auto"' '"qemu"'

            makeWrapper ${appPython}/bin/python $out/bin/kishirika-gui \
              --add-flags "$out/share/kernelvulnauditp/main.py --gui" \
              --prefix PATH : ${pkgs.lib.makeBinPath runtimeTools} \
              --set PYTHONPATH $out/share/kernelvulnauditp

            makeWrapper ${appPython}/bin/python $out/bin/kishirika-cli \
              --add-flags "$out/share/kernelvulnauditp/main.py --cli" \
              --prefix PATH : ${pkgs.lib.makeBinPath runtimeTools} \
              --set PYTHONPATH $out/share/kernelvulnauditp

            makeWrapper ${appPython}/bin/python $out/bin/kishirika-report \
              --add-flags "$out/share/kernelvulnauditp/report.py" \
              --prefix PATH : ${pkgs.lib.makeBinPath runtimeTools} \
              --set PYTHONPATH $out/share/kernelvulnauditp
            runHook postInstall
          '';

          meta = {
            description = "Linux Kernel Vulnerability Analyzer & PoC Sandbox";
            mainProgram = "kishirika-cli";
            license = pkgs.lib.licenses.mit;
          };
        };

        devPython = python.withPackages (p: [
          p.httpx
          p.h2
          p.sqlalchemy
          p.rich
          p.textual
          p.streamlit
          p.pytest
          p.ruff
          p.mypy
          p.black
          p.bandit
          p.pylint
          p.scalene
        ]);

      in {
        packages = {
          default = app;
          linpeas = linpeas;
        };

        apps = {
          default = flake-utils.lib.mkApp { drv = app; name = "kishirika-cli"; };
          cli = flake-utils.lib.mkApp { drv = app; name = "kishirika-cli"; };
          gui = flake-utils.lib.mkApp { drv = app; name = "kishirika-gui"; };
          report = flake-utils.lib.mkApp { drv = app; name = "kishirika-report"; };
        };

        devShells.default = pkgs.mkShell {
          buildInputs = [
            devPython
            pkgs.lynis
            pkgs.linux-exploit-suggester
            linpeas
            pkgs.qemu_kvm
            pkgs.cpio
            pkgs.busybox
            pkgs.musl.dev
            pkgs.gcc
            pkgs.git
            pkgs.coreutils
            pkgs.findutils
          ];
          shellHook = ''
            export KERNEL_AUDIT_SANDBOX=qemu
            export PYTHONPATH="$PWD''${PYTHONPATH:+:$PYTHONPATH}"
            echo "KernelVulnAuditP dev shell (QEMU sandbox)."
            echo "Tools: lynis, linux-exploit-suggester, linpeas_kernel.sh, qemu-system-x86_64"
          '';
        };
      }
    );
}
