# ./core/threading_classes.py 

import threading 
import signal 
import sys 


class ActiveProcesses:
    def __init__(self):
        self.processes = []
        self.lock = threading.Lock()

class ThreadKiller:
    def __init__(self, active_processes, executor):
        self.active_processes = active_processes
        self.executor = executor
        self.shutdown_event = threading.Event()
        signal.signal(signal.SIGINT, self.handle_signal)

    def handle_signal(self, signum, frame):
        print("\nReceived interrupt signal. Shutting down gracefully...")
        self.shutdown_event.set()
        self.terminate_processes()
        self.executor.shutdown(wait=False)
        sys.exit(0)

    def terminate_processes(self):
        print("Terminating active Nmap scans...")
        with self.active_processes.lock:
            for proc in self.active_processes.processes:
                if proc.poll() is None:
                    print(f"Terminating subprocess with PID {proc.pid}")
                    proc.terminate()
            self.active_processes.processes.clear()

