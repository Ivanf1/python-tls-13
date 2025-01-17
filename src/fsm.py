class FSM:
    def __init__(self, states, initial_state, table):
        """
        Initialize the FSM.

        :param states: List of states.
        :param initial_state: The starting state.
        :param table: Transition table as a dictionary. The callback for the transition must return a boolean value.
        If it returns **True** the transition is performed, otherwise the transition is not performed and the
        current state remains the same.
        eg: \n
        transition_table = {
            ('idle', 'start'): ('processing', callback1),
            ('processing', 'complete'): ('completed', callback2),
            ('completed', 'reset'): ('idle', None),
        }
        """
        self.states = states
        self.current_state = initial_state
        self.table = table

    def transition(self, event, ctx = None):
        """
        Transition to the next state based on the event. If the event is not defined for the current state
        an **FSMInvalidEventForStateError** exception will be raised.

        :param event: The event triggering the transition.
        :param ctx: A context that will be passed to the transition callback.
        """
        if (self.current_state, event) in self.table:
            next_state, action = self.table[(self.current_state, event)]

            if action and action(ctx):
                self.current_state = next_state
        else:
            raise FSMInvalidEventForStateError(f"No transition defined for state {self.current_state} on event '{event}'")

    def get_current_state(self):
        return self.current_state

class FSMInvalidEventForStateError(Exception):
    pass