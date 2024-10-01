# ./core/threading_classes.py 

import threading 
import signal 
import sys 
import os

BOLD = '\033[1;37m'
LINK = '\033[4;34m'
ORANGE = '\033[1;31m'
END = '\033[0m'

class ActiveProcesses:
    def __init__(self):
        self.processes = []
        self.lock = threading.Lock()

class ThreadKiller:
    def __init__(self, active_processes, executor, temp_xml):
        self.active_processes = active_processes
        self.executor = executor
        self.temp_xml = temp_xml
        self.shutdown_event = threading.Event()
        signal.signal(signal.SIGINT, self.handle_signal)
        signal.signal(signal.SIGTERM, self.handle_signal)

    def handle_signal(self, signum, frame):
        print(f"{BOLD}Received interrupt signal. Shutting down gracefully...{END}\n")
        for file in self.temp_xml:
            os.remove(file)
        self.shutdown_event.set()
        self.terminate_processes()
        self.executor.shutdown(wait=False)
        sys.exit(0)

    def terminate_processes(self):
        print(f"{BOLD}Terminating all active subprocesses...{END}\n")
        with self.active_processes.lock:
            for proc in self.active_processes.processes:
                if proc.poll() is None:
                    print(f"{ORANGE}Terminating subprocess with PID{END} {LINK}{proc.pid}{END}\n")
                    proc.terminate()
            self.active_processes.processes.clear()

