"""
Mode manager for different scanning behaviors.
Enforces ethical boundaries and use-case separation.
"""

class ScanMode:
    """Defines scanner operational modes."""
    
    SCAN = "scan"           # Standard vulnerability detection
    
    DESCRIPTIONS = {
        SCAN: "Vulnerability detection and reporting",
    }
    
    @staticmethod
    def get_available_modes():
        return [ScanMode.SCAN]


class ModeManager:
    """Manages scanner mode configuration."""
    
    def __init__(self):
        self.current_mode = ScanMode.SCAN
    
    def set_mode(self, mode: str) -> bool:
        """Set scanner mode. Returns True if valid."""
        if mode not in ScanMode.get_available_modes():
            return False
        self.current_mode = mode
        return True
    
    def get_mode_config(self) -> dict:
        """Get configuration for current mode."""
        return {
            'exploit': False,
            'auth': False,
            'aggressive': True,
            'max_depth': 3,
            'timeout': 10
        }


# Global mode manager instance
_mode_manager = ModeManager()

def get_mode_manager() -> ModeManager:
    """Get global mode manager."""
    return _mode_manager
