"""
Flag detection for CTF challenges.
Only active in CTF modes.
"""
import re
from typing import List, Dict
import requests


class FlagHunter:
    """Hunt for CTF flags in responses."""
    
    def __init__(self, flag_patterns: List[str]):
        self.patterns = [re.compile(p, re.IGNORECASE) for p in flag_patterns]
        self.found_flags = []
    
    def scan_response(self, url: str, response_text: str) -> List[Dict]:
        """
        Scan HTTP response for flags.
        
        Returns:
            List of found flags with locations
        """
        findings = []
        
        for pattern in self.patterns:
            matches = pattern.findall(response_text)
            
            for match in matches:
                if match not in [f['flag'] for f in self.found_flags]:
                    finding = {
                        'type': 'flag',
                        'flag': match,
                        'url': url,
                        'context': self._get_context(response_text, match)
                    }
                    
                    findings.append(finding)
                    self.found_flags.append(finding)
                    
                    print(f"\n🚩 FLAG FOUND!")
                    print(f"   Flag: {match}")
                    print(f"   Location: {url}")
                    print(f"   Context: {finding['context']}\n")
        
        return findings
    
    def scan_file_content(self, filepath: str, content: str) -> List[Dict]:
        """Scan file contents for flags (comments, source code, etc.)."""
        findings = []
        
        for pattern in self.patterns:
            matches = pattern.findall(content)
            
            for match in matches:
                if match not in [f['flag'] for f in self.found_flags]:
                    finding = {
                        'type': 'flag',
                        'flag': match,
                        'location': filepath,
                        'context': self._get_context(content, match)
                    }
                    
                    findings.append(finding)
                    self.found_flags.append(finding)
                    
                    print(f"\n🚩 FLAG FOUND IN FILE!")
                    print(f"   Flag: {match}")
                    print(f"   File: {filepath}")
        
        return findings
    
    def _get_context(self, text: str, match: str, window: int = 50) -> str:
        """Get surrounding context of flag."""
        idx = text.find(match)
        if idx == -1:
            return ""
        
        start = max(0, idx - window)
        end = min(len(text), idx + len(match) + window)
        
        context = text[start:end]
        return context.strip()
    
    def get_all_flags(self) -> List[Dict]:
        """Get all found flags."""
        return self.found_flags