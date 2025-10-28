import queue
from multiprocessing import Queue
from multiprocessing.synchronize import Event as EventType

class ThreatBusDispatcher:
    """
    A central dispatcher that forwards messages from a central bus to all
    subscribed monitors, creating a publish-subscribe communication channel.
    """
    def __init__(self, bus_queue: Queue, monitor_queues: dict, shutdown_event: EventType):
        self.bus_queue = bus_queue
        self.monitor_queues = monitor_queues
        self.shutdown_event = shutdown_event

    def run(self):
        """Continuously reads from the bus and dispatches to all monitors."""
        while not self.shutdown_event.is_set():
            try:
                message = self.bus_queue.get(timeout=1)
                for monitor_name, queue_ in self.monitor_queues.items():
                    try:
                        # Avoid sending a message back to the sender
                        if message.get("publisher") != monitor_name:
                            queue_.put_nowait(message)
                    except queue.Full:
                        # In a real-world scenario, you'd want to log this
                        # or have a strategy for handling slow consumers.
                        pass
            except queue.Empty:
                continue

def run_bus_dispatcher_wrapper(dispatcher: ThreatBusDispatcher):
    """A wrapper to allow the dispatcher process to handle KeyboardInterrupt gracefully."""
    try:
        dispatcher.run()
    except KeyboardInterrupt:
        # On Ctrl+C, the shutdown_event will be set by the main agent,
        # and the run loop will terminate, allowing a clean exit.
        pass
