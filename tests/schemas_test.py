from datetime import UTC, datetime

from core.entities import HostInfo, HostUser


def test_to_dict_serializes_user_last_login():
    host = HostInfo(
        users=[
            HostUser(
                username="bob",
                last_login=datetime(2024, 5, 1, 12, 0, 0, tzinfo=UTC),
            ),
            HostUser(username="alice"),
        ]
    )

    data = host.to_dict()

    assert data["users"][0]["last_login"] == "2024-05-01T12:00:00+00:00"
    assert data["users"][1]["last_login"] is None