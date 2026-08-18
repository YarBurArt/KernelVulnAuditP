help_m() {
    echo "Usage: $0 [OUTPUT_PATH]"
    echo
    echo "Download & build reconnaissance tools for current audit environment"
    echo
    echo "Arguments:"
    echo "  OUTPUT_PATH   Path to generated linpeas script (default: lib_tools/linpeas_kernel.sh)"
    echo
    echo "Options:"
    echo "  -h, --help    Show this help message"
    exit 0
}

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    help_m
fi

if ! command -v git >/dev/null 2>&1; then
    echo "git not found in PATH. You must install git or add the git to PATH..."
    exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$SCRIPT_DIR/lib_tools"
mkdir -p "$TOOLS_DIR"
cd "$TOOLS_DIR"
pwd

git clone --depth 1 https://github.com/CISOfy/lynis
echo "config.py default matches: $TOOLS_DIR/lynis/lynis"
echo "Check here https://github.com/CISOfy/lynis/blob/master/README.md"

echo
git clone --depth 1 https://github.com/The-Z-Labs/linux-exploit-suggester.git
echo "config.py default matches: $TOOLS_DIR/linux-exploit-suggester/linux-exploit-suggester.sh"
echo "Check here https://github.com/The-Z-Labs/linux-exploit-suggester/blob/master/README.md"

echo
OUTPUT="${1:-$TOOLS_DIR/linpeas_kernel.sh}"
echo "Building linpeas with kernel/CVE checks only..."
# use python peass builder https://github.com/peass-ng/PEASS-ng/blob/master/linPEAS/builder/README.md
git clone --depth 1 https://github.com/peass-ng/PEASS-ng.git
cd "$TOOLS_DIR/PEASS-ng/linPEAS"
python3 -m builder.linpeas_builder \
    --include "kernel,CVE,exploit" \
    --output "$OUTPUT"

echo
echo "Check here https://github.com/peass-ng/PEASS-ng/blob/master/README.md"
echo "Built: $OUTPUT"
echo "config.py defaults point here, no manual path edits needed:"
ls -lh "$OUTPUT"

echo
if command -v vng >/dev/null 2>&1; then
    echo "virtme-ng found, checking for kernel image..."
    if [ ! -f /boot/vmlinuz-$(uname -r) ] && [ ! -f /boot/vmlinuz ]; then
        echo "You may need to install kernel headers or build a kernel"
        echo "For kernel build, see: https://github.com/arighi/virtme-ng"
    else
        echo "Host kernel found - virtme-ng ready to use"
    fi
else
    echo "virtme-ng not found in PATH, try qemu way"
fi

