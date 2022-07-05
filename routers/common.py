from uuid import UUID


def common_query_session_params(session_name: UUID) -> dict[str, UUID]:
    return {'session_name': session_name}
