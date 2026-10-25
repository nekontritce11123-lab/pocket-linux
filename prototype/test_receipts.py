import io
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_probe import complete_serial_lines


class ReceiptStreamTests(unittest.TestCase):
    def test_partial_receipt_is_delivered_once_after_newline(self):
        path = Mock()
        seen, delivered = 0, []
        for snapshot in ['boot\r\nPL_READY {"ok":', 'boot\r\nPL_READY {"ok":true}\r',
                         'boot\r\nPL_READY {"ok":true}\r\n',
                         'boot\r\nPL_READY {"ok":true}\r\nPL_DONE {}\n']:
            path.open.return_value = io.StringIO(snapshot, newline='')
            lines = complete_serial_lines(path)
            delivered.extend(lines[seen:])
            seen = len(lines)
        self.assertEqual(delivered, ['boot\r', 'PL_READY {"ok":true}\r', 'PL_DONE {}'])
        path.open.assert_called_with(encoding='utf-8', errors='replace', newline='')


if __name__ == '__main__':
    unittest.main()
