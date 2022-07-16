"""
Support functions for the main logic
"""
import configparser
import logging
import os
from logging.handlers import RotatingFileHandler
from typing import List, Optional
import uuid
from colorlog import ColoredFormatter


def read_file_to_lst(file_path: str) -> List[str]:
    """
    read file content to list
    """
    with open(file_path, encoding='utf-8') as file:
        return file.read().splitlines()


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
    console_format: str = '%(process)s %(thread)s: %(asctime)s - %(filename)s:%(lineno)d - %(funcName)s -%(log_color)s'
    ' %(levelname)s %(reset)s - %(message)s',
    file_format: str = '%(process)s %(thread)s: %(asctime)s - %(filename)s:%(lineno)d - %(funcName)s - %(levelname)s -'
    ' %(message)s',
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


def get_config(config_path: str, config_section: str) -> dict:
    """
    Getting a config section from a config file
    """
    config = configparser.RawConfigParser(comment_prefixes=('#',))
    config.read(config_path, encoding='utf-8')
    output_config = config[config_section]
    return dict(output_config)


def get_path_if_compiled(file_path: str) -> str:
    """
    Check if the file was compiled and return the full existing path .py(c)
    Args:
        file_path (str) The path to .py file

    Returns:
        str: The path with .py(c)
    """
    if os.path.exists(file_path):
        return file_path
    file_path_compiled = file_path + 'c'
    if os.path.exists(file_path_compiled):
        return file_path_compiled
    raise Exception(f'{file_path} or {file_path_compiled} do not exist!')


def generate_uuid() -> str:
    """
    Generate new uuid4
    """
    return str(uuid.uuid4())


def get_last_file_line(file_path: str) -> str:
    """
    Get last line of file

    https://stackoverflow.com/a/54278929/14642295
    Args:
        file_path (str): full path to file

    Returns:
        str: the last line of file
    """
    with open(file_path, 'rb') as file:
        try:  # catch OSError in case of a one line file
            file.seek(-2, os.SEEK_END)
            while file.read(1) != b'\n':
                file.seek(-2, os.SEEK_CUR)
        except OSError:
            file.seek(0)
        return file.readline().decode()


def delete_if_exists(file_path: str) -> None:
    """
    Delete the file if exists

    Args:
        file_path (str): full path to file

    Returns:
        None
    """
    if os.path.exists(file_path):
        os.remove(file_path)
