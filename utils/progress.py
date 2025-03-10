class ProgressHandler:
    def __init__(self):
        self.progress = 0
        self.running = False
        self.lock = threading.Lock()
    
    def update_progress(self, value):
        with self.lock:
            self.progress = min(max(value, 0), 100)
    
    def get_progress(self):
        with self.lock:
            return self.progress 