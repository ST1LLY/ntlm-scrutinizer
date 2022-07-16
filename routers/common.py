"""
The module contains common structures for routers

Author:
    Konstantin S. (https://github.com/ST1LLY)
"""
from uuid import UUID


def common_query_session_params(session_name: UUID) -> dict[str, UUID]:
    """
    The session param for requests
    """
    return {'session_name': session_name}
