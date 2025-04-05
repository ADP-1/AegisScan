from .sql_injection import SQLiScanner
from .xss import XSSScanner
from .csrf import CSRFScanner  # Changed from CSRFAnalyzer to CSRFScanner

__version__ = "0.1.0"
__all__ = ["SQLiScanner", "XSSScanner", "CSRFScanner"]  # Changed from CSRFAnalyzer to CSRFScanner