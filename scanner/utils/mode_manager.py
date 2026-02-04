"""
Mode manager for different scanning behaviors.
Enforces ethical boundaries and use-case separation.
"""

class ScanMode:
    """Defines scanner operational modes."""
    
    SCAN = "scan"           # Safe detection only
    LAB = "lab"             # Validated exploitation
    CTF = "ctf"             # Flag hunting
    CTF_AUTH = "ctf-auth"   # Authenticated CTF
    
    DESCRIPTIONS = {
        SCAN: "Safe vulnerability detection (default)",
        LAB: "Exploit validation on test environments",
        CTF: "Flag-focused exploitation (CTFs only)",
        CTF_AUTH: "Authenticated CTF exploitation"
    }
    
    @staticmethod
    def get_available_modes():
        return [ScanMode.SCAN, ScanMode.LAB, ScanMode.CTF, ScanMode.CTF_AUTH]


class ModeManager:
    """Manages scanner mode and enforces safety rules."""
    
    def __init__(self):
        self.current_mode = ScanMode.SCAN
        self.credentials = None
        self.flag_patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'htb\{[^}]+\}',
            r'thm\{[^}]+\}'
        ]
    
    def set_mode(self, mode: str) -> bool:
        """
        Set scanner mode with safety warnings.
        
        Returns:
            True if mode set successfully
        """
        if mode not in ScanMode.get_available_modes():
            print(f"[✗] Invalid mode: {mode}")
            print(f"    Available: {', '.join(ScanMode.get_available_modes())}")
            return False
        
        # Show warning for dangerous modes
        if mode in [ScanMode.CTF, ScanMode.CTF_AUTH]:
            print("\n" + "="*60)
            print("⚠️  EXPLOITATION MODE ENABLED")
            print("="*60)
            print("This mode performs ACTIVE EXPLOITATION.")
            print("Use ONLY on:")
            print("  - CTF platforms (HTB, TryHackMe, picoCTF)")
            print("  - Your own labs")
            print("  - Authorized test environments")
            print("\nNEVER use on:")
            print("  - Production websites")
            print("  - Bug bounty targets")
            print("  - Systems without explicit permission")
            print("="*60)
            
            confirm = input("\nType 'I UNDERSTAND' to continue: ")
            if confirm.strip() != "I UNDERSTAND":
                print("[!] Mode change cancelled")
                return False
        
        self.current_mode = mode
        print(f"\n[✓] Mode set to: {mode}")
        print(f"    {ScanMode.DESCRIPTIONS[mode]}")
        return True
    
    def set_credentials(self, username: str, password: str):
        """Set credentials for authenticated modes."""
        if self.current_mode not in [ScanMode.CTF_AUTH, ScanMode.LAB]:
            print("[!] Credentials only used in lab/ctf-auth modes")
        
        self.credentials = {
            'username': username,
            'password': password
        }
        print(f"[✓] Credentials set: {username}:{'*' * len(password)}")
    
    def can_exploit(self) -> bool:
        """Check if current mode allows exploitation."""
        return self.current_mode in [ScanMode.LAB, ScanMode.CTF, ScanMode.CTF_AUTH]
    
    def can_use_auth(self) -> bool:
        """Check if current mode allows authenticated scanning."""
        return self.current_mode in [ScanMode.LAB, ScanMode.CTF_AUTH]
    
    def should_hunt_flags(self) -> bool:
        """Check if current mode hunts for flags."""
        return self.current_mode in [ScanMode.CTF, ScanMode.CTF_AUTH]
    
    def get_flag_patterns(self):
        """Get flag regex patterns."""
        return self.flag_patterns
    
    def get_mode_config(self) -> dict:
        """Get configuration for current mode."""
        configs = {
            ScanMode.SCAN: {
                'exploit': False,
                'auth': False,
                'flags': False,
                'aggressive': False,
                'max_depth': 2,
                'timeout': 10
            },
            ScanMode.LAB: {
                'exploit': True,
                'auth': True,
                'flags': False,
                'aggressive': True,
                'max_depth': 3,
                'timeout': 15
            },
            ScanMode.CTF: {
                'exploit': True,
                'auth': False,
                'flags': True,
                'aggressive': True,
                'max_depth': 5,
                'timeout': 20
            },
            ScanMode.CTF_AUTH: {
                'exploit': True,
                'auth': True,
                'flags': True,
                'aggressive': True,
                'max_depth': 5,
                'timeout': 20
            }
        }
        
        return configs.get(self.current_mode, configs[ScanMode.SCAN])


# Global mode manager instance
_mode_manager = ModeManager()

def get_mode_manager() -> ModeManager:
    """Get global mode manager."""
    return _mode_manager