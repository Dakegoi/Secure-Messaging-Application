"""Password validation utilities for secure messaging."""
import re
from typing import Tuple


def validate_password(password: str) -> Tuple[bool, str]:
    """
    Validate password complexity requirements.
    
    Requirements:
    - Minimum 8 characters
    - At least one letter (a-z or A-Z)
    - At least one number (0-9)
    - At least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)
    
    Returns:
        Tuple of (is_valid, error_message)
        If valid, error_message is empty string.
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[a-zA-Z]', password):
        return False, "Password must contain at least one letter"
    
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
        return False, "Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)"
    
    return True, ""

