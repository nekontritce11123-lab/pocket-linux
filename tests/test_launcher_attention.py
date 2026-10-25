import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class LauncherAttentionTests(unittest.TestCase):
    def test_offline_session_and_real_failures(self):
        compiler = Path(os.environ['SystemRoot']) / 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
        with tempfile.TemporaryDirectory(prefix="linux-attention-") as temporary:
            executable = Path(temporary) / 'LauncherAttentionRegression.exe'
            build = subprocess.run([str(compiler), '/nologo', '/target:exe', '/platform:x64',
                                    '/out:' + str(executable), str(ROOT / 'launcher-wpf/AttentionPolicy.cs'),
                                    str(ROOT / 'tests/LauncherAttentionRegression.cs')],
                                   capture_output=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
            self.assertEqual(build.returncode, 0, (build.stdout + build.stderr).decode(errors='replace'))
            result = subprocess.run([str(executable)], capture_output=True, timeout=30,
                                    creationflags=subprocess.CREATE_NO_WINDOW)
            self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode(errors='replace'))


if __name__ == '__main__':
    unittest.main()
