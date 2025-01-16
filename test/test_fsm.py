import unittest
from unittest.mock import Mock

from src.fsm import FSM, FSMInvalidEventForStateError


class TestFSM(unittest.TestCase):
    def setUp(self):
        self.start_processing = Mock()
        self.complete_processing = Mock()

        self.states = ['idle', 'processing', 'completed']
        self.events = ['start', 'complete', 'reset', 'unknown']

        self.transition_table = {
            ('idle', 'start'): ('processing', self.start_processing),
            ('processing', 'complete'): ('completed', self.complete_processing),
            ('completed', 'reset'): ('idle', None),
        }

        self.fsm = FSM(self.states, 'idle', self.transition_table)

    def test_should_proceed_to_start_state(self):
        self.start_processing.return_value = True
        self.fsm.transition(self.events[0])
        self.assertEqual(self.fsm.get_current_state(), self.states[1])

    def test_should_raise_exception_on_invalid_event_for_current_state(self):
        self.assertRaises(FSMInvalidEventForStateError, self.fsm.transition, self.events[1])

    def test_should_not_proceed_to_start_when_callback_returns_false(self):
        self.start_processing.return_value = False
        self.fsm.transition(self.events[0])
        self.assertEqual(self.fsm.get_current_state(), self.states[0])
