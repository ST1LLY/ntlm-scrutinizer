"""
Support functions for main logic
"""
from typing import List, Optional
import os


def read_file_to_lst(file_path: str) -> List[str]:
    """
    read file content to list
    """
    with open(file_path) as f:
        return f.read().splitlines()


def get_file_names_in_dir(dir_path: str) -> list:
    """
    Get a list of filenames from a dir

    Source:
        https://stackoverflow.com/a/3207973
    """
    return [f for f in os.listdir(dir_path) if os.path.isfile(os.path.join(dir_path, f))]


def try_find_file_in_dir(dir_path: str, sub_string: str) -> Optional[str]:
    """
    Trying to find the file in the dir and return full path for one

    Args:
        dir_path (str): full dir path for finding
        sub_string (str): string in filename

    Returns:
        str: full path to the found file
    """
    for file_name in get_file_names_in_dir(dir_path):
        if sub_string in file_name:
            return os.path.join(dir_path, file_name)

    return None
