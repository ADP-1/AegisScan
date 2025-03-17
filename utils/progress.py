import threading

class ProgressHandler:
    def __init__(self):
        self.lock = threading.Lock()
        self.progress = 0
        self.running = False
    
    def update_progress(self, value):
        with self.lock:
            self.progress = value
    
    def get_progress(self):
        with self.lock:
            return self.progress 