import unittest
from unittest.mock import Mock

from src.fsm import FSM


class TestFSM(unittest.TestCase):
    def setUp(self):
        start_processing = Mock()
        complete_processing = Mock()

        start_processing.return_value = True

        self.states = ['idle', 'processing', 'completed']
        self.events = ['start', 'complete', 'reset', 'unknown']

        self.transition_table = {
            ('idle', 'start'): ('processing', start_processing),
            ('processing', 'complete'): ('completed', complete_processing),
            ('completed', 'reset'): ('idle', None),
        }

        self.fsm = FSM(self.states, 'idle', self.transition_table)

    def test_should_proceed_to_start_state(self):
        self.fsm.transition(self.events[0])
        self.assertEqual(self.fsm.current_state, self.states[1])
