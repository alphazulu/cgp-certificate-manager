"""Console acknowledgement previews require an explicit operator decision."""
import contextlib
import json
import subprocess
import unittest
from unittest.mock import Mock, patch

from cgp_cert_manager import console as c

NAME = 'example.com'
TOKEN = 'a' * 32 + 'b' * 32
TITLE = 'Acknowledge previous settings (TLS unverified)'


class ResolutionConsoleTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.w = Mock()
        self.w.getmaxyx.return_value = (24, 80)
        self.stack.enter_context(patch.object(c, 'language', return_value='en'))
        self.stack.enter_context(patch.object(c.curses, 'has_colors', return_value=False))
        self.stack.enter_context(patch.object(c.curses, 'curs_set'))
        self.screen = c.Screen(self.w)
        self.preview = {
            'domain': NAME, 'phase': 'restoring', 'state': 'previous',
            'server_matches': True, 'confirmation_token': TOKEN,
            'tls': 'unverified', 'pending_journal': True,
            'authorization_recorded': False,
        }

    def mock_flow(self):
        self.screen.view = Mock(return_value=True)
        self.screen.input_reason = Mock(return_value='Previous certificate expired')
        self.screen.confirm = Mock(return_value=True)
        self.screen.execute = Mock()

    def test_preview_view_has_distinct_continue_and_cancel(self):
        self.w.getch.side_effect = [c.curses.KEY_DOWN, 10]
        self.assertTrue(self.screen.view(TITLE, ['TLS: unverified'], allow_continue=True))
        self.w.getch.side_effect = [27]
        self.assertFalse(self.screen.view(TITLE, ['TLS: unverified'], allow_continue=True))
        self.w.getch.side_effect = [10, 27]
        self.assertIsNone(self.screen.view(TITLE, ['TLS: unverified']))

    def test_reason_supports_unicode_editing_and_trims_spaces(self):
        self.w.get_wch.side_effect = [' ', *'Причина', 'x', c.curses.KEY_BACKSPACE, ' ', '\n']
        self.assertEqual(self.screen.input_reason(), 'Причина')

    def test_reason_rejects_blank_controls_and_excess_length(self):
        self.screen.put = Mock()
        self.w.get_wch.side_effect = ['\n', '\t', c.curses.KEY_RESIZE] + ['x'] * 500 + ['y', '\n']
        self.assertEqual(self.screen.input_reason(), 'x' * 500)
        rendered = [args.args[2] for args in self.screen.put.call_args_list]
        for message in ('A reason is required', 'Use printable characters only', 'Maximum reason length is 500 characters'):
            self.assertIn(message, rendered)

    def test_reason_cancel_and_interrupt(self):
        for key in ('\x1b', '\x03', c.curses.KEY_F10):
            with self.subTest(key=key):
                self.w.get_wch.side_effect = [key]
                self.assertIsNone(self.screen.input_reason())
        self.w.get_wch.side_effect = KeyboardInterrupt()
        self.assertIsNone(self.screen.input_reason())

    def test_acceptance_uses_exact_preview_and_keeps_output_unverified(self):
        self.mock_flow()
        self.preview['PrivateSecureKey'] = 'PRIVATE MATERIAL MUST NOT BE SHOWN'
        with patch.object(c, 'capture', return_value=(0, json.dumps(self.preview), '')) as capture:
            self.screen.acknowledge_previous(NAME)
        capture.assert_called_once_with(c.CLI + ['--acknowledge-restored', '--domain', NAME, '--json'])
        self.screen.execute.assert_called_once_with(
            c.CLI + ['--acknowledge-restored', '--domain', NAME, '--confirm-transaction', TOKEN,
                     '--reason', 'Previous certificate expired'], TITLE+' — '+NAME)
        self.screen.confirm.assert_called_once_with('Acknowledge '+NAME+' / '+TOKEN[:12]+' (TLS unverified)')
        lines = self.screen.view.call_args.args[1]
        self.assertIn('TLS: unverified', lines)
        self.assertIn(TOKEN[:32], lines)
        self.assertIn(TOKEN[32:], lines)
        self.assertNotIn('PRIVATE MATERIAL', '\n'.join(lines))
        self.assertEqual(self.screen.view.call_args.kwargs, {'allow_continue': True})

    def test_crash_retry_preview_without_pending_journal_is_supported(self):
        self.mock_flow()
        self.preview.update(phase='acknowledging', state='both', pending_journal=False, authorization_recorded=True)
        with patch.object(c, 'capture', return_value=(0, json.dumps(self.preview), '')):
            self.screen.acknowledge_previous(NAME)
        self.screen.execute.assert_called_once()
        self.assertIn('Pending journal: False', self.screen.view.call_args.args[1])
        self.assertIn('Authorization recorded: True', self.screen.view.call_args.args[1])
        self.assertIn('Repeat the original acknowledgement reason.', self.screen.view.call_args.args[1])

    def test_cancel_at_each_stage_never_executes(self):
        for stage in ('preview', 'reason', 'confirmation'):
            with self.subTest(stage=stage):
                self.mock_flow()
                if stage == 'preview': self.screen.view.return_value = False
                elif stage == 'reason': self.screen.input_reason.return_value = None
                else: self.screen.confirm.return_value = False
                with patch.object(c, 'capture', return_value=(0, json.dumps(self.preview), '')) as capture:
                    self.screen.acknowledge_previous(NAME)
                capture.assert_called_once()
                self.screen.execute.assert_not_called()
                if stage == 'preview': self.screen.input_reason.assert_not_called()
                if stage != 'confirmation': self.screen.confirm.assert_not_called()

    def test_preview_refusal_and_transport_failure_do_not_offer_confirmation(self):
        self.mock_flow()
        for reply in ((1, '', 'Unknown CGP state'), (1, '', '')):
            with self.subTest(reply=reply), patch.object(c, 'capture', return_value=reply):
                self.screen.acknowledge_previous(NAME)
                self.assertIn(reply[2] or 'Acknowledgement preview unavailable', self.screen.view.call_args.args[1])
        for error in (OSError(), subprocess.TimeoutExpired('preview', 1), c.curses.error()):
            with self.subTest(error=type(error).__name__), patch.object(c, 'capture', side_effect=error):
                self.screen.acknowledge_previous(NAME)
        self.screen.input_reason.assert_not_called()
        self.screen.confirm.assert_not_called()
        self.screen.execute.assert_not_called()

    def test_invalid_preview_is_not_rendered_or_acknowledged(self):
        self.mock_flow()
        changes = [
            None, {'domain': 'other.example.com'}, {'phase': 'committed'},
            {'state': 'intended'}, {'server_matches': False}, {'tls': 'verified'},
            {'pending_journal': None}, {'authorization_recorded': 1},
            {'confirmation_token': None}, {'confirmation_token': 'a' * 63},
        ]
        for change in changes:
            payload = None if change is None else dict(self.preview, **change)
            with self.subTest(change=change), patch.object(c, 'capture', return_value=(0, json.dumps(payload), '')):
                self.screen.acknowledge_previous(NAME)
            self.screen.view.assert_called_with(TITLE, ['Acknowledgement preview unavailable'])
        self.screen.input_reason.assert_not_called()
        self.screen.execute.assert_not_called()

    def test_execution_error_never_refetches_and_retries_preview(self):
        self.mock_flow()
        self.screen.execute.side_effect = c.core.Error('Preview is stale')
        with patch.object(c, 'capture', return_value=(0, json.dumps(self.preview), '')) as capture:
            self.screen.acknowledge_previous(NAME)
        capture.assert_called_once()
        self.screen.execute.assert_called_once()

    def test_domain_action_routes_to_special_confirmation_flow(self):
        self.screen.rows = [{'domain': NAME}]
        self.screen.menu = Mock(side_effect=[13, None])
        self.screen.confirm = Mock()
        self.screen.acknowledge_previous = Mock()
        self.screen.domain_menu()
        self.screen.acknowledge_previous.assert_called_once_with(NAME)
        self.screen.confirm.assert_not_called()
        self.assertEqual(c.command_for(NAME, 12), c.CLI + ['--domain', NAME, '--acknowledge-restored'])

    def test_f9_acknowledgement_selection_works_without_discovery(self):
        self.screen.menu = Mock(side_effect=[2, 0])
        self.screen.acknowledge_previous = Mock()
        rows = [{'domain': 'other.example.com'}, {'domain': NAME}, {'domain': NAME}]
        with patch.object(c, 'capture', return_value=(0, json.dumps(rows), '')) as capture:
            self.screen.transaction_menu()
        self.assertEqual(self.screen.rows, [])
        capture.assert_called_once_with(c.CLI + ['--transactions', '--json'])
        self.screen.menu.assert_called_with('Select pending transaction', [NAME, 'other.example.com', 'Back'])
        self.screen.acknowledge_previous.assert_called_once_with(NAME)

    def test_global_selection_cancel_and_empty_result(self):
        self.screen.menu = Mock()
        self.screen.view = Mock()
        self.screen.acknowledge_previous = Mock()
        for choice in (None, 1):
            self.screen.menu.return_value = choice
            with patch.object(c, 'capture', return_value=(0, json.dumps([{'domain': NAME}]), '')):
                self.screen.select_acknowledgement()
        with patch.object(c, 'capture', return_value=(0, '[]', '')):
            self.screen.select_acknowledgement()
        self.screen.view.assert_called_with(TITLE, ['No pending transactions'])
        self.screen.acknowledge_previous.assert_not_called()

    def test_global_selection_refuses_error_and_malformed_responses(self):
        self.screen.view = Mock()
        self.screen.menu = Mock()
        self.screen.acknowledge_previous = Mock()
        replies = [(1, '', 'Inspection refused'), (1, '', ''), (0, 'null', ''),
                   (0, '[null]', ''), (0, '[{"domain": 1}]', ''),
                   (0, '[{"domain":"../invalid"}]', ''), (0, 'bad JSON', '')]
        for reply in replies:
            with self.subTest(reply=reply), patch.object(c, 'capture', return_value=reply):
                self.screen.select_acknowledgement()
        with patch.object(c, 'capture', side_effect=OSError()):
            self.screen.select_acknowledgement()
        self.screen.view.assert_called_with(TITLE, ['Transaction inspection unavailable'])
        self.screen.menu.assert_not_called()
        self.screen.acknowledge_previous.assert_not_called()

    def test_new_navigation_and_safety_labels_have_russian_translations(self):
        for label in (TITLE, 'Reason for acknowledgement', 'Select pending transaction',
                      'Up/Down | Enter Continue | Esc/Q Cancel', 'TLS: unverified',
                      'Acknowledging previous settings does not verify TLS.'):
            self.assertNotEqual(c.translate(label, 'ru'), label)
        self.assertEqual(c.translate('Confirm: Acknowledge '+NAME+' / '+TOKEN[:12]+' (TLS unverified)', 'ru'),
                         'Подтвердите: '+NAME+' / '+TOKEN[:12]+' (TLS не подтверждён)')

