import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('plasma_style', Path(__file__).with_name('guest_plasma.py'))
plasma = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plasma)


class PlasmaTests(unittest.TestCase):
    def test_packaged_wallpaper_is_js_escaped(self):
        script = plasma.layout_script(Path('/wallpaper/quote";invalid.png'))
        self.assertIn('file:///wallpaper/quote\\";invalid.png', script)
        self.assertEqual(script.count('new Panel'), 1)
        self.assertNotIn('.remove()', script)


if __name__ == '__main__':
    unittest.main()
