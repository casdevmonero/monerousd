# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class LocalChainDiscoveryTests(unittest.TestCase):
    def test_status_lists_only_local_chain_directories_in_numeric_order(self):
        with tempfile.TemporaryDirectory() as home:
            nodes = Path(home) / "nodes"
            nodes.mkdir()
            for name in ("local10", "local2", "local-dev", "local", "local01", "local0"):
                (nodes / name).mkdir()
            (nodes / "local1").touch()
            result = subprocess.run(
                [sys.executable, str(Path(__file__).with_name("musd")), "chain", "status"],
                env={**os.environ, "MUSD_HOME": home},
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), [
                "local0: never started", "local2: never started", "local10: never started",
            ])


if __name__ == "__main__":
    unittest.main()
