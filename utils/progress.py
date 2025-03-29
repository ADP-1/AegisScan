import threading
import time
import sys
import shutil
from colorama import Fore, Style, init

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class ProgressHandler:
    def __init__(self):
        self.lock = threading.Lock()
        self.progress = 0
        self.running = False
        self.message = "Initializing..."
        self.last_update_time = time.time()
        self.terminal_width = shutil.get_terminal_size().columns
    
    def update_progress(self, value, message=None):
        with self.lock:
            self.progress = value
            if message:
                self.message = message
            self.last_update_time = time.time()
    
    def get_progress(self):
        with self.lock:
            return self.progress
    
    def get_message(self):
        with self.lock:
            return self.message
    
    def display_progress_bar(self):
        """Display an advanced progress bar with percentage and message"""
        with self.lock:
            progress = self.progress
            message = self.message
        
        # Calculate bar width based on terminal size
        term_width = self.terminal_width
        bar_width = min(50, term_width - 30)
        
        # Create the progress bar
        filled_width = int(bar_width * progress / 100)
        bar = f"[{Fore.CYAN}{'█' * filled_width}{Style.RESET_ALL}{'░' * (bar_width - filled_width)}]"
        
        # Format the percentage with color
        percentage = f"{Fore.GREEN}{progress:3d}%{Style.RESET_ALL}"
        
        # Truncate message if needed
        max_msg_len = term_width - len(bar) - len(percentage) - 5
        if len(message) > max_msg_len:
            message = message[:max_msg_len-3] + "..."
        
        # Build the complete line
        line = f"\r{bar} {percentage} {message}"
        
        # Print the progress line
        sys.stdout.write(line)
        sys.stdout.flush() 