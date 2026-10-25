"""Compile the actual WPF window and resources with a deterministic backend."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == 'nt', 'requires WPF')
class LauncherLifecycleTests(unittest.TestCase):
    def test_native_window_lifecycle(self):
        vswhere = Path(os.environ['ProgramFiles(x86)']) / 'Microsoft Visual Studio/Installer/vswhere.exe'
        found = subprocess.check_output([str(vswhere), '-latest', '-products', '*', '-requires',
                                         'Microsoft.Component.MSBuild', '-find',
                                         r'MSBuild\**\Bin\amd64\MSBuild.exe'], text=True).strip().splitlines()
        self.assertTrue(found, 'MSBuild required')
        with tempfile.TemporaryDirectory(prefix='launcher-lifecycle-') as directory:
            work = Path(directory)
            ns = 'http://schemas.microsoft.com/developer/msbuild/2003'
            ET.register_namespace('', ns)
            tree = ET.parse(ROOT / 'launcher-wpf/Launcher.Wpf.csproj')
            project = tree.getroot()
            for group in list(project):
                for item in list(group):
                    if item.tag == '{' + ns + '}PackageReference' or item.tag == '{' + ns + '}ApplicationManifest':
                        group.remove(item)
                    elif item.tag in ('{' + ns + '}Compile', '{' + ns + '}Page', '{' + ns + '}Resource'):
                        original = item.attrib['Include']
                        if original in ('Bridge.cs', 'App.xaml.cs'):
                            group.remove(item)
                        else:
                            item.set('Include', str(ROOT / 'launcher-wpf' / original))
                    elif item.tag == '{' + ns + '}ApplicationIcon':
                        item.text = str(ROOT / 'ui/AppIcon.ico')
                if group.tag == '{' + ns + '}Target':
                    project.remove(group)
            props = ET.Element('{' + ns + '}PropertyGroup')
            project.insert(len(project) - 1, props)
            for key, value in {'OutputType': 'Exe', 'AssemblyName': 'LauncherLifecycleRegression',
                               'StartupObject': 'LauncherLifecycleRegression', 'OutputPath': str(work / 'out') + '/',
                               'OutDir': str(work / 'out') + '/',
                               'TargetFrameworkRootPath': str(Path(os.environ['USERPROFILE']) / '.nuget/packages/microsoft.netframework.referenceassemblies.net48/1.0.3/build') + '/'}.items():
                ET.SubElement(props, '{' + ns + '}' + key).text = value
            group = ET.SubElement(project, '{' + ns + '}ItemGroup')
            ET.SubElement(group, '{' + ns + '}Compile', Include=str(ROOT / 'tests/LauncherLifecycleRegression.cs'))
            ui = Path(os.environ['USERPROFILE']) / '.nuget/packages/wpf-ui/3.0.5/lib/net472/Wpf.Ui.dll'
            ref = ET.SubElement(group, '{' + ns + '}Reference', Include='Wpf.Ui')
            ET.SubElement(ref, '{' + ns + '}HintPath').text = str(ui)
            path = work / 'Lifecycle.csproj'
            tree.write(path, encoding='utf-8', xml_declaration=True)
            result = subprocess.run([found[0], str(path), '-nologo', '-v:minimal', '-t:Build'],
                                    capture_output=True, timeout=90)
            self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode(errors='replace'))
            result = subprocess.run([str(work / 'out/LauncherLifecycleRegression.exe')],
                                    capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode(errors='replace'))
            print(result.stdout.decode(errors='replace').strip())


if __name__ == '__main__':
    unittest.main()
