from pathlib import Path

from sqxpl import GitHubExploitSearcher, _fix_stale_compile_cmd

C_README = """
## Usage

Run the exploit:

```bash
gcc exploit.c -o exploit -lmnl -lnftnl -no-pie -lpthread
./exploit
```

![](./imgs/poc.png)
"""

DOTTED_BINARY_README = """
# CVE

## Instructions

1. wget
2. tune
3. gcc exploit.c
4. ./a.out
"""

IMAGE_ONLY_README = """
# PwnKit

Self-contained exploit.

```bash
gcc -shared PwnKit.c -o PwnKit -Wl,-e,entry -fPIC
./PwnKit
```

![](./imgs/oneliner.png)
"""


def test_extract_test_command_skips_markdown_image_ref():
    cmd = GitHubExploitSearcher._extract_test_command(C_README, "C")
    assert cmd == "./exploit"


def test_extract_test_command_keeps_dotted_binary():
    cmd = GitHubExploitSearcher._extract_test_command(DOTTED_BINARY_README, "C")
    assert cmd == "./a.out"


def test_extract_test_command_not_image_path():
    cmd = GitHubExploitSearcher._extract_test_command(IMAGE_ONLY_README, "C")
    assert cmd == "./PwnKit"
    assert "imgs" not in cmd


def test_extract_c_compile_from_code_block():
    cmd = GitHubExploitSearcher._extract_c_compile(C_README)
    assert cmd == "gcc exploit.c -o exploit -lmnl -lnftnl -no-pie -lpthread"


def test_fix_stale_compile_cmd_rewrites_missing_source(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "CVE-2022-2586.c").write_text("int main(void){return 0;}")
    xpl = {
        "compile_cmd": "gcc exploit.c -o exploit -lmnl -lnftnl -no-pie -lpthread",
        "test_cmd": None,
    }
    _fix_stale_compile_cmd(xpl, repo)
    assert xpl["compile_cmd"] == (
        "gcc CVE-2022-2586.c -o exploit -lmnl -lnftnl -no-pie -lpthread"
    )


def test_fix_stale_compile_cmd_leaves_make_and_matching(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "exploit.c").write_text("int main(void){return 0;}")
    xpl = {"compile_cmd": "gcc exploit.c -o exploit", "test_cmd": None}
    _fix_stale_compile_cmd(xpl, repo)
    assert xpl["compile_cmd"] == "gcc exploit.c -o exploit"

    xpl2 = {"compile_cmd": "make", "test_cmd": None}
    _fix_stale_compile_cmd(xpl2, repo)
    assert xpl2["compile_cmd"] == "make"


def test_fix_stale_compile_cmd_skips_multiple_sources(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.c").write_text("")
    (repo / "b.c").write_text("")
    xpl = {"compile_cmd": "gcc exploit.c -o exploit", "test_cmd": None}
    _fix_stale_compile_cmd(xpl, repo)
    assert xpl["compile_cmd"] == "gcc exploit.c -o exploit"
