import configparser
import importlib.util
from pathlib import Path
import unittest
from unittest import mock
import xml.etree.ElementTree as ET

spec = importlib.util.spec_from_file_location('guest_style', Path(__file__).with_name('guest_style.py'))
style = importlib.util.module_from_spec(spec)
spec.loader.exec_module(style)


class StyleTests(unittest.TestCase):
    def test_official_uppercase_claude_launcher_on_case_sensitive_linux(self):
        folder = mock.Mock()
        folder.glob.return_value = [Path('/apps/pocket-claude-code.desktop'),
                                    Path('/apps/com.anthropic.Claude.desktop')]
        self.assertEqual(style.desktop_launcher(folder).name, 'com.anthropic.Claude.desktop')
        folder.glob.assert_called_once_with('*.desktop')

    def test_ini_keeps_command_placeholders_and_is_idempotent(self):
        source = '[Desktop Entry]\nExec=claude-desktop %U\nIcon=claude\n'
        changed = style.ini_update(source, {'Desktop Entry': {'Name': 'Claude Desktop'}})
        self.assertIn('Exec=claude-desktop %U', changed)
        self.assertEqual(style.ini_update(changed, {'Desktop Entry': {'Name': 'Claude Desktop'}}), changed)

    def test_one_compact_panel_uses_upstream_keys(self):
        text = style.panel_config(['/usr/share/applications/claude.desktop',
                                   '/usr/share/applications/pocket-claude-code.desktop'])
        panel = configparser.ConfigParser(interpolation=None)
        panel.optionxform = str
        panel.read_string('[General]\n' + text)
        self.assertEqual(panel['General']['panels'], 'panel1')
        self.assertEqual(panel['panel1']['position'], 'Bottom')
        self.assertEqual(panel['panel1']['panelSize'], '38')
        self.assertEqual(panel['panel1']['iconSize'], '24')
        self.assertNotIn('volume', panel['panel1']['plugins'])
        self.assertNotIn('sensors', panel['panel1']['plugins'])
        self.assertEqual(panel['quicklaunch']['apps\\size'], '2')
        self.assertEqual(panel['quicklaunch']['apps\\1\\desktop'], '/usr/share/applications/claude.desktop')

    def test_openbox_retains_bindings_and_sets_arc_and_two_desktops(self):
        source = '<openbox_config xmlns="http://openbox.org/3.4/rc"><keyboard><keybind key="W-e"><action name="Execute"><command>pcmanfm-qt</command></action></keybind></keyboard><theme><name>Old</name></theme><desktops><number>4</number></desktops></openbox_config>'
        text = style.openbox_config(source)
        root = ET.fromstring(text)
        ns = {'o': 'http://openbox.org/3.4/rc'}
        self.assertEqual(root.find('o:theme/o:name', ns).text, 'Arc')
        self.assertEqual(root.find('o:desktops/o:number', ns).text, '2')
        self.assertEqual(root.find('o:keyboard/o:keybind/o:action/o:command', ns).text, 'pcmanfm-qt')
        self.assertEqual(style.openbox_config(text), text)

    def test_windows_guard_stops_before_reading_or_writing(self):
        with mock.patch.object(style.sys, 'platform', 'win32'), \
                mock.patch.object(Path, 'open') as opened:
            with self.assertRaises(RuntimeError):
                style.guard_guest()
        opened.assert_not_called()

    def test_non_root_guest_is_refused_before_marker_read(self):
        with mock.patch.object(style.sys, 'platform', 'linux'), \
                mock.patch.object(style.os, 'geteuid', return_value=1000, create=True), \
                mock.patch.object(Path, 'open') as opened:
            with self.assertRaises(RuntimeError):
                style.guard_guest()
        opened.assert_not_called()

    def test_unmarked_guest_is_refused(self):
        with mock.patch.object(style.sys, 'platform', 'linux'), \
                mock.patch.object(style.os, 'geteuid', return_value=0, create=True), \
                mock.patch.object(Path, 'is_file', return_value=False), \
                mock.patch.object(Path, 'is_symlink', return_value=False), \
                mock.patch.object(Path, 'open') as opened:
            with self.assertRaises(RuntimeError):
                style.guard_guest()
        opened.assert_not_called()


if __name__ == '__main__':
    unittest.main()
