# Integration-test suites for KernelVulnAuditP, imported by ../flake.nix.
# fast variant for mocked/offline tests (no QEMU boots); runs in GitHub CI;
# qemu for real TCG VM boots of the isolate module; for dev locally via nix
{
  pkgs,
  python,
  appSrc,
  runtimeTools,
  kernel,
}:
let
  lib = pkgs.lib;

  # app runtime deps used by tests + pytest; dishka/streamlit are not needed
  testPython = python.withPackages (p: [
    p.httpx
    p.h2
    p.sqlalchemy
    p.rich
    p.textual
    p.pyyaml
    p.pytest
  ]);

  # procps provides pgrep; glibc provides ldd, which
  # QemuEnvironment._install_runtime_libs uses to copy guest libs
  testTools = runtimeTools ++ [ pkgs.procps pkgs.glibc.bin ];

  mkSuite = { name, testFiles }:
    let
      testArgs = "-m integration "
        + lib.concatMapStringsSep " " (f: "${appSrc}/tests_integration/${f}") testFiles;
    in {
      # derivation whose build *is* the test run (flake check target)
      check = pkgs.runCommand "${name}" {
        nativeBuildInputs = [ testPython ] ++ testTools;
        env = {
          KERNEL_AUDIT_SANDBOX = "qemu";
          KERNEL_AUDIT_VMLINUZ = "${kernel}/bzImage";
          PYTHONPATH = "${appSrc}";
          PYTEST_ADDOPTS = "-q -p no:cacheprovider";
        };
      } ''
        export HOME="$NIX_BUILD_TOP"
        # glibc's ldd must win over musl's: _install_runtime_libs uses it to
        # copy guest libs; musl ldd cannot trace glibc binaries
        export PATH=${pkgs.glibc.bin}/bin:$PATH
        mkdir -p "$NIX_BUILD_TOP/pytest-tmp"
        # a writable copy of the project root: some tests resolve fixtures
        # relative to it, others write runtime dirs (logs/) into cwd
        cp -r "${appSrc}" src && chmod -R u+w src
        cd src
        pytest ${testArgs} --basetemp="$NIX_BUILD_TOP/pytest-tmp"
        touch $out
      '';

      # same run as an `nix run` app for local use
      cli = pkgs.writeShellScriptBin "run-${name}" ''
        export KERNEL_AUDIT_SANDBOX=qemu
        export KERNEL_AUDIT_VMLINUZ=${kernel}/bzImage
        export PYTHONPATH=${appSrc}
        export PATH=${lib.makeBinPath ([ testPython ] ++ testTools)}:$PATH
        export PATH=${pkgs.glibc.bin}/bin:$PATH
        cp -r ${appSrc} "$PWD/nix-src" && chmod -R u+w nix-src
        cd nix-src
        exec pytest ${testArgs}
      '';
    };
in {
  fast = mkSuite {
    name = "integration-fast";
    testFiles = [
      "remote_feeds_recon_test.py"
      "sqxpl_discovery_test.py"
      "isolate_flow_test.py" # its virtme-ng test self-skips without virtme-ng
    ];
  };

  qemu = mkSuite {
    name = "integration-qemu";
    testFiles = [ "isolate_intergration_test.py" ];
  };
}
