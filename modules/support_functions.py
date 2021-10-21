"""
Support functions for main logic
"""
from typing import List


def read_file_to_lst(file_path: str) -> List[str]:
    """
    read file content to list
    """
    with open(file_path) as f:
        return f.read().splitlines()
