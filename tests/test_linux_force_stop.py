from contextlib import nullcontext
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import runtime_supervisor as runtime
import portable_app as app


class RecoveryCapabilityTests(unittest.TestCase):
    def test_actual_diagnostics_only_offer_recovery_for_unfinished_safe_session(self):
        scratch = Path(__file__).resolve().parents[2] / 'backend-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        cases = [(None, False), ('stopped', False), ('failed', True), ('stopping', True),
                 ('cleanup', False), ('cleanup-running', False), ('cleanup-stopping', False), ('cleanup-failed', True),
                 ('running', False), ('orphan', False), ('foreign', False)]
        for phase, expected in cases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory(dir=scratch) as temporary:
                root = Path(temporary)
                owner = {'pid': 10, 'created': '100', 'image': str(root / 'runtime/python-3.12.14/python.exe')}
                work = {'pid': 11, 'created': '101', 'image': str(root / 'runtime/qemu-11.1.0/qemu-system-x86_64.exe')}
                network = {'pid': 12, 'created': '102', 'image': str(root / 'PocketNet.exe')}
                identities = {}
                if phase:
                    state = {'schema': 1, 'nonce': '1'*32, 'phase': phase if phase in ('stopped', 'failed', 'stopping', 'running') else 'stopped',
                             'work': None, 'supervisor': None, 'network': None, 'folders': None, 'control_port': None}
                    if phase.startswith('cleanup') or phase == 'running':
                        state.update(work=work, supervisor=owner)
                        if phase.startswith('cleanup-'):
                            state['phase'] = phase.split('-', 1)[1]
                        identities[10] = owner
                        if phase == 'running':
                            identities[11] = work
                    if phase == 'orphan':
                        state.update(work=work, network=network, phase='failed')
                        identities[12] = network
                    if phase == 'foreign':
                        state.update(work=work, phase='failed')
                        identities[11] = work | {'created': '999'}
                    runtime.write_json(root / 'state/session.json', state)
                store = mock.Mock()
                store.selected_summary.return_value = None
                with mock.patch.object(app, 'host_facts', return_value={'windows': True, 'x64': True, 'whpx': True, 'ram_available_mib': 8000}), \
                     mock.patch.object(app, 'ProfileStore', return_value=store), \
                     mock.patch.object(app, 'image_ready', return_value=True), \
                     mock.patch.object(runtime, 'process_identity', side_effect=lambda pid: identities.get(pid)):
                    result = app.report(root, full=True)
                self.assertEqual(result['capabilities']['recover_session'], expected)
                if phase and phase.startswith('cleanup'):
                    self.assertEqual(result['checks']['runtime_state']['passed'], phase != 'cleanup-failed')


class ForceStopTests(unittest.TestCase):
    def setUp(self):
        self.root = Path('C:/Pocket')
        self.work = {'pid': 10, 'created': '100', 'image': str(self.root / 'runtime/qemu-11.1.0/qemu-system-x86_64.exe')}
        self.owner = {'pid': 11, 'created': '101', 'image': str(self.root / 'runtime/python-3.12.14/python.exe')}
        self.state = {'nonce': '1' * 32, 'work': self.work, 'supervisor': self.owner,
                      'phase': 'stopping', 'stop_requested_unix': 100, 'control_port': 12345}
        self.view = {'state': self.state, 'active': True, 'uncertain': False, 'work': 'stopping',
                     'control_available': True, 'identities': {'work': 'alive', 'supervisor': 'alive'}}
        self.session = {key: self.state[key] for key in ('nonce', 'work', 'supervisor')}

    def test_offer_only_after_120_seconds_and_known_owner(self):
        with mock.patch.object(runtime, 'snapshot', return_value=self.view), mock.patch.object(runtime.time, 'time', return_value=219):
            self.assertIsNone(runtime.force_stop_offer(self.root))
        with mock.patch.object(runtime, 'snapshot', return_value=self.view), mock.patch.object(runtime.time, 'time', return_value=220):
            self.assertEqual(runtime.force_stop_offer(self.root), self.session)
            self.view['control_available'] = False
            self.assertIsNone(runtime.force_stop_offer(self.root))

    def test_no_confirmation_or_cancel_performs_no_action(self):
        for request in ({}, {'confirmed': False, 'session': self.session}, {'confirmed': 1, 'session': self.session}):
            with mock.patch.object(runtime, 'send_control') as send, self.assertRaises(ValueError):
                runtime.force_stop_session(self.root, request)
            send.assert_not_called()

    def test_borrowed_handle_identity_never_reopens_or_closes_process(self):
        kernel = mock.Mock()
        def exit_code(handle, code):
            code._obj.value = 259
            return True
        def image(handle, flags, buffer, length):
            buffer.value = self.work['image']
            return True
        def times(handle, created, *unused):
            created._obj.dwLowDateTime = 100
            return True
        kernel.GetExitCodeProcess.side_effect = exit_code
        kernel.QueryFullProcessImageNameW.side_effect = image
        kernel.GetProcessTimes.side_effect = times
        with mock.patch.object(runtime.ctypes, 'WinDLL', return_value=kernel):
            self.assertTrue(runtime.same_identity(self.work, runtime.process_identity(10, handle=456)))
        kernel.OpenProcess.assert_not_called()
        kernel.CloseHandle.assert_not_called()

    def test_force_control_is_authenticated_and_bound_to_session(self):
        token = 'a' * 64
        request = {'nonce': self.state['nonce'], 'token': token, 'action': 'force-stop',
                   'confirmed': True, 'session': self.session}
        self.assertEqual(runtime.decode_control(json.dumps(request).encode(), self.state['nonce'], token), 'force-stop')
        for change in ({'confirmed': False}, {'session': dict(self.session, nonce='2'*32)}, {'token': 'b'*64}):
            with self.assertRaises(ValueError):
                runtime.decode_control(json.dumps(request | change).encode(), self.state['nonce'], token)

    def test_owned_handle_is_rechecked_and_reused_pid_or_nonce_never_killed(self):
        vm = mock.Mock(pid=10, _handle=456)
        vm.poll.return_value = None
        for identities, latest in (([self.work, self.work | {'created': '999'}], self.state),
                                   ([self.work], self.state | {'nonce': '2'*32})):
            kernel = mock.Mock()
            with mock.patch.object(runtime, 'read_state', return_value=latest), \
                 mock.patch.object(runtime, 'process_identity', side_effect=identities), \
                 mock.patch.object(runtime.ctypes, 'WinDLL', return_value=kernel), \
                 mock.patch.object(runtime, 'write_json'), self.assertRaises(ValueError):
                runtime.force_owned_guest(self.root, self.state, vm, self.session)
            kernel.TerminateProcess.assert_not_called()

    def test_owned_force_records_abnormal_exit_after_wait(self):
        vm = mock.Mock(pid=10, _handle=456)
        vm.poll.return_value = None
        kernel = mock.Mock()
        kernel.TerminateProcess.return_value = True
        with mock.patch.object(runtime, 'read_state', return_value=self.state), \
             mock.patch.object(runtime, 'process_identity', return_value=self.work), \
             mock.patch.object(runtime.ctypes, 'WinDLL', return_value=kernel), \
             mock.patch.object(runtime, 'write_json'):
            runtime.force_owned_guest(self.root, self.state, vm, self.session)
        self.assertTrue(self.state['forced_stop'])
        self.assertFalse(self.state['graceful_shutdown'])
        vm.wait.assert_called_once_with(timeout=10)
        kernel.TerminateProcess.assert_called_once_with(456, 1)

    def test_stale_session_confirmation_never_reaches_supervisor(self):
        with mock.patch.object(runtime, 'force_stop_offer', return_value=self.session | {'nonce': '2'*32}), \
             mock.patch.object(runtime, 'send_control') as send, self.assertRaises(ValueError):
            runtime.force_stop_session(self.root, {'confirmed': True, 'session': self.session})
        send.assert_not_called()

    def test_dispatch_force_uses_operation_lock(self):
        with mock.patch.object(runtime, 'operation_lock', return_value=nullcontext()) as lock, \
             mock.patch.object(runtime, 'force_stop_session', return_value={'ok': True, 'forced': True}) as force, \
             mock.patch.object(app, 'report', return_value={}):
            self.assertTrue(app.dispatch(self.root, 'force-stop', {'confirmed': True, 'session': self.session})['forced'])
        lock.assert_called_once_with(self.root)
        force.assert_called_once()

    def test_operation_lock_failure_does_not_send_force(self):
        with mock.patch.object(runtime, 'operation_lock', side_effect=runtime.BackendError('busy')), \
             mock.patch.object(runtime, 'force_stop_session') as force, self.assertRaises(ValueError):
            app.dispatch(self.root, 'force-stop', {'confirmed': True, 'session': self.session})
        force.assert_not_called()

    def test_graceful_timeout_returns_offer_without_forcing(self):
        clock = [0]
        def pause(seconds):
            clock[0] += seconds
        with mock.patch.object(runtime, 'snapshot', return_value=self.view), \
             mock.patch.object(runtime, 'send_control') as send, \
             mock.patch.object(runtime, 'force_owned_guest') as force, \
             mock.patch.object(runtime.time, 'monotonic', side_effect=lambda: clock[0]), \
             mock.patch.object(runtime.time, 'time', return_value=220), \
             mock.patch.object(runtime.time, 'sleep', side_effect=pause):
            result = runtime.stop_session(self.root)
        self.assertEqual(clock[0], 120)
        self.assertEqual(result['code'], 'shutdown_unconfirmed')
        self.assertEqual(result['force_stop_session'], self.session)
        send.assert_called_once_with(self.root, 'stop')
        force.assert_not_called()

    def test_guest_crash_while_stopping_is_not_reported_graceful(self):
        dead = self.view | {'active': False, 'work': 'stopped', 'state': self.state | {'phase': 'failed'}}
        with mock.patch.object(runtime, 'snapshot', side_effect=[self.view, dead]), \
             mock.patch.object(runtime, 'send_control'):
            result = runtime.stop_session(self.root)
        self.assertEqual(result['code'], 'abnormal_shutdown')
        self.assertFalse(result['ok'])

    def test_force_waits_for_owner_and_disk_recovery_before_success(self):
        dead = self.view | {'active': False, 'work': 'stopped', 'state': self.state | {'forced_stop': True}}
        order = []
        with mock.patch.object(runtime, 'force_stop_offer', return_value=self.session), \
             mock.patch.object(runtime, 'send_control', side_effect=lambda *a, **kw: order.append('force')), \
             mock.patch.object(runtime, 'snapshot', return_value=dead), \
             mock.patch.object(runtime, 'recover_session', side_effect=lambda root: order.append('recover') or {'ok': True}):
            result = runtime.force_stop_session(self.root, {'confirmed': True, 'session': self.session})
        self.assertEqual(order, ['force', 'recover'])
        self.assertTrue(result['forced'])
        self.assertFalse(result['graceful'])

    def test_dead_guest_waits_for_owner_cleanup_but_orphan_helpers_are_preserved(self):
        dead = self.view | {'work': 'stopped', 'identities': {'work': 'dead', 'supervisor': 'alive', 'network': 'alive'}}
        stopped = dead | {'active': False, 'identities': {'work': 'dead', 'supervisor': 'dead', 'network': 'dead'}}
        helper = mock.Mock()
        helper.disk_lock.return_value = nullcontext()
        with mock.patch.object(runtime, 'snapshot', side_effect=[dead, stopped, stopped]), \
             mock.patch.object(runtime, 'helper_module', return_value=helper), \
             mock.patch.object(runtime, 'write_json'), mock.patch.object(Path, 'exists', return_value=False), \
             mock.patch.object(runtime.time, 'sleep'):
            self.assertTrue(runtime.recover_session(self.root)['ok'])
        orphan = dead | {'identities': {'work': 'dead', 'supervisor': 'dead', 'network': 'alive'}}
        with mock.patch.object(runtime, 'snapshot', return_value=orphan), self.assertRaisesRegex(ValueError, 'владелец'):
            runtime.recover_session(self.root)

    def test_cleanup_wait_is_bounded_and_nonce_change_aborts(self):
        dead = self.view | {'identities': {'work': 'dead', 'supervisor': 'alive', 'network': 'alive'}}
        clock = [0]
        with mock.patch.object(runtime, 'snapshot', return_value=dead), \
             mock.patch.object(runtime.time, 'monotonic', side_effect=lambda: clock[0]), \
             mock.patch.object(runtime.time, 'sleep', side_effect=lambda delay: clock.__setitem__(0, clock[0] + delay)), \
             mock.patch.object(runtime, 'helper_module') as helper:
            result = runtime.recover_session(self.root)
        self.assertEqual(result['code'], 'cleanup_pending')
        self.assertEqual(clock[0], 15)
        helper.assert_not_called()
        changed = dead | {'state': self.state | {'nonce': '2'*32}}
        with mock.patch.object(runtime, 'snapshot', side_effect=[dead, changed]), \
             mock.patch.object(runtime.time, 'sleep'), self.assertRaises(ValueError):
            runtime.recover_session(self.root)


if __name__ == '__main__':
    unittest.main()
