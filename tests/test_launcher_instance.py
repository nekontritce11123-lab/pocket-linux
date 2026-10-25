"""Actual App startup in separate lightweight WPF processes, without a VM."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == 'nt', 'requires native Windows WPF')
class LauncherInstanceTests(unittest.TestCase):
    def test_per_installation_process_ownership_and_activation(self):
        compiler = Path(os.environ['SystemRoot']) / 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
        references = Path(os.environ['USERPROFILE']) / '.nuget/packages/microsoft.netframework.referenceassemblies.net48/1.0.3/build/.NETFramework/v4.8'
        with tempfile.TemporaryDirectory(prefix='launcher-instance-') as directory:
            executable = Path(directory) / 'LauncherInstanceRegression.exe'
            command = [str(compiler), '/nologo', '/target:exe', '/platform:x64',
                       '/main:LauncherInstanceRegression', '/out:' + str(executable),
                       *['/reference:' + str(references / (name + '.dll')) for name in
                         ('System.Xaml', 'WindowsBase', 'PresentationCore', 'PresentationFramework')],
                       str(ROOT / 'launcher-wpf/App.xaml.cs'), str(ROOT / 'tests/LauncherInstanceRegression.cs')]
            build = subprocess.run(command, capture_output=True, timeout=45, creationflags=subprocess.CREATE_NO_WINDOW)
            self.assertEqual(build.returncode, 0, (build.stdout + build.stderr).decode(errors='replace'))
            result = subprocess.run([str(executable), directory], capture_output=True, timeout=45,
                                    creationflags=subprocess.CREATE_NO_WINDOW)
            self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode(errors='replace'))
            print(result.stdout.decode(errors='replace').strip())


if __name__ == '__main__':
    unittest.main()
