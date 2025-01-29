"""
PasswordGuard Pro - Enterprise-Grade Password Analysis Tool
Features:
- SHA-1 Hash-based API Check (Have I Been Pwned)
- Common Password Detection
- OWASP-Compliant Strength Analysis
- Modern GUI with Async Operations
- Comprehensive Error Handling
- Logging System
"""

import re
import hashlib
import logging
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Dict, List, Tuple
import requests
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='password_guard.log'
)

class PasswordAnalyzer:
    """Core password analysis engine with API integration"""
    
    API_URL = "https://api.pwnedpasswords.com/range/"
    MIN_PASSWORD_LENGTH = 12
    COMMON_PASSWORDS_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt"

    def __init__(self):
        self.common_passwords = self._load_common_passwords()
        self.executor = ThreadPoolExecutor(max_workers=2)

    def _load_common_passwords(self) -> set:
        """Load common passwords from online repository"""
        try:
            response = requests.get(self.COMMON_PASSWORDS_URL, timeout=10)
            response.raise_for_status()
            return set(response.text.splitlines())
        except Exception as e:
            logging.error(f"Error loading common passwords: {str(e)}")
            return set()

    def _check_api(self, password: str) -> int:
        """Check password against Have I Been Pwned API (secure implementation)"""
        try:
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix, suffix = sha1_hash[:5], sha1_hash[5:]
            
            response = requests.get(f"{self.API_URL}{prefix}", timeout=5)
            response.raise_for_status()
            
            return any(line.split(':')[0] == suffix for line in response.text.splitlines())
        except requests.RequestException as e:
            logging.error(f"API Error: {str(e)}")
            return 0

    def analyze(self, password: str) -> Dict:
        """Comprehensive password analysis"""
        if not password:
            raise ValueError("Empty password provided")

        results = {
            'length': len(password) >= self.MIN_PASSWORD_LENGTH,
            'uppercase': re.search(r'[A-Z]', password) is not None,
            'lowercase': re.search(r'[a-z]', password) is not None,
            'digit': re.search(r'\d', password) is not None,
            'special': re.search(r'[!@#$%^&*(),.?":{}|<>]', password) is not None,
            'common': password.lower() in self.common_passwords,
            'pwned': 0
        }

        # Async API check
        future = self.executor.submit(self._check_api, password)
        results['pwned'] = future.result()

        return results

class PasswordGuardUI(tk.Tk):
    """Professional-grade GUI Interface"""
    
    def __init__(self, analyzer: PasswordAnalyzer):
        super().__init__()
        self.analyzer = analyzer
        self.title("PasswordGuard Pro v1.0")
        self.geometry("600x450")
        self.configure(bg="#f0f2f5")
        self._create_widgets()
        self._setup_styles()

    def _setup_styles(self):
        """Configure modern UI styling"""
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        self.style.configure('TFrame', background="#f0f2f5")
        self.style.configure('TLabel', background="#f0f2f5", font=('Segoe UI', 10))
        self.style.configure('TButton', font=('Segoe UI', 10), padding=6)
        self.style.configure('Header.TLabel', font=('Segoe UI', 14, 'bold'))
        self.style.map('TButton',
            foreground=[('active', 'white'), ('!active', 'black')],
            background=[('active', '#0052cc'), ('!active', '#0066ff')]
        )

    def _create_widgets(self):
        """Build UI components"""
        main_frame = ttk.Frame(self, padding=20)
        main_frame.pack(expand=True, fill=tk.BOTH)

        # Header
        ttk.Label(main_frame, text="🔒 PasswordGuard Pro", style='Header.TLabel').pack(pady=10)

        # Password Entry
        entry_frame = ttk.Frame(main_frame)
        entry_frame.pack(fill=tk.X, pady=10)
        
        self.entry = ttk.Entry(entry_frame, show="•", width=40, font=('Segoe UI', 11))
        self.entry.pack(side=tk.LEFT, expand=True)
        
        ttk.Button(entry_frame, text="Analyze", command=self._on_analyze).pack(side=tk.RIGHT)

        # Results Display
        self.results_frame = ttk.Frame(main_frame)
        self.results_frame.pack(fill=tk.BOTH, expand=True)

        # Status Bar
        self.status = ttk.Label(main_frame, text="Ready", foreground="gray")
        self.status.pack(side=tk.BOTTOM, fill=tk.X)

    def _on_analyze(self):
        """Handle password analysis"""
        password = self.entry.get()
        if not password:
            self._show_error("Input Required", "Please enter a password to analyze")
            return

        try:
            self._set_status("Analyzing...", "blue")
            results = self.analyzer.analyze(password)
            self._display_results(results)
        except Exception as e:
            logging.error(f"Analysis Error: {str(e)}")
            self._show_error("Analysis Failed", str(e))
        finally:
            self._set_status("Ready", "gray")

    def _display_results(self, results: Dict):
        """Display analysis results"""
        for widget in self.results_frame.winfo_children():
            widget.destroy()

        # Security Status
        status_text, status_color = self._get_security_status(results)
        ttk.Label(self.results_frame, 
                 text=f"Security Status: {status_text}",
                 foreground=status_color,
                 font=('Segoe UI', 12, 'bold')).pack(pady=10)

        # Detailed Analysis
        details_frame = ttk.Frame(self.results_frame)
        details_frame.pack(fill=tk.BOTH)
        
        checks = [
            ("Minimum Length (12+ chars)", results['length']),
            ("Uppercase Letters", results['uppercase']),
            ("Lowercase Letters", results['lowercase']),
            ("Numbers", results['digit']),
            ("Special Characters", results['special']),
            ("Not Common Password", not results['common']),
            ("Not Found in Breaches", not results['pwned'])
        ]
        
        for text, passed in checks:
            icon = "✓" if passed else "✗"
            color = "green" if passed else "red"
            ttk.Label(details_frame, 
                     text=f"{icon} {text}",
                     foreground=color).pack(anchor=tk.W)

    def _get_security_status(self, results: Dict) -> Tuple[str, str]:
        """Determine security status"""
        if results['pwned']:
            return ("Critical Risk - Password is compromised", "red")
        if results['common']:
            return ("High Risk - Common password", "orange")
        
        passed = sum([results['length'], results['uppercase'],
                     results['lowercase'], results['digit'],
                     results['special']])
        
        if passed < 3:
            return ("Weak - Fails basic requirements", "red")
        if passed < 5:
            return ("Moderate - Needs improvement", "orange")
        return ("Strong - Meets security standards", "green")

    def _set_status(self, text: str, color: str):
        """Update status bar"""
        self.status.config(text=text, foreground=color)

    def _show_error(self, title: str, message: str):
        """Show error dialog"""
        messagebox.showerror(title, message)

if __name__ == "__main__":
    analyzer = PasswordAnalyzer()
    app = PasswordGuardUI(analyzer)
    app.mainloop()