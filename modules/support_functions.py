"""
Support functions for the main logic
"""
import logging
from logging.handlers import RotatingFileHandler

from colorlog import ColoredFormatter
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


def init_custome_logger(
    all_log_file_path: str,
    error_log_file_path: str,
    logging_level: str = 'DEBUG',
    console_format: str = '%(process)s %(thread)s: %(asctime)s - %(filename)s:%(lineno)d - %(funcName)s -%(log_color)s '
    '%(levelname)s %(reset)s - %(message)s',
    file_format: str = '%(process)s %(thread)s: %(asctime)s - %(filename)s:%(lineno)d - %(funcName)s - %(levelname)s - '
    '%(message)s',
) -> logging.Logger:
    """
    Creating custom logger
    """
    # Setting console output handler

    stream_formatter = ColoredFormatter(console_format)
    logging_level_num = 20 if logging_level == 'INFO' else 10
    max_bytes = 20 * 1024 * 1024  # 20MB максимальный размер лог файла
    backup_count = 10

    # Setting log file output handler
    file_handler = RotatingFileHandler(
        filename=all_log_file_path, mode='a', maxBytes=max_bytes, backupCount=backup_count, encoding='utf-8'
    )
    file_handler.setFormatter(logging.Formatter(fmt=file_format))
    file_handler.setLevel(logging_level_num)

    # Setting error log file output handler
    error_file_handler = RotatingFileHandler(
        filename=error_log_file_path, mode='a', maxBytes=max_bytes, backupCount=backup_count, encoding='utf-8'
    )
    error_file_handler.setFormatter(logging.Formatter(fmt=file_format))
    error_file_handler.setLevel(logging.WARNING)

    # Set ours handlers to root handler
    logging.basicConfig(level=logging_level_num)

    logger = logging.getLogger()
    # Changing the output format of root stream handler
    logger.handlers[0].setFormatter(stream_formatter)

    # logger.addHandler(stream_handler)
    logger.addHandler(file_handler)
    logger.addHandler(error_file_handler)
    return logger
