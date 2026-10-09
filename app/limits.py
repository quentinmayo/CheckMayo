import hashlib
from datetime import timedelta

from sqlalchemy import delete

from app.db import RateWindow, Session, engine, now


def auth_limit(request):
    host = request.client.host if request.client else "unknown"
    signup = request.url.path.endswith("/signup")
    span = 3600 if signup else 60
    bucket = int(now().timestamp()) // span
    key = hashlib.sha256(host.encode()).hexdigest()[:32] + ":" + str(bucket) + (":signup" if signup else ":auth")
    from sqlalchemy.dialects.postgresql import insert as postgres_insert
    from sqlalchemy.dialects.sqlite import insert as sqlite_insert

    insert = sqlite_insert if engine.dialect.name == "sqlite" else postgres_insert
    with Session() as db:
        statement = insert(RateWindow).values(key=key, count=1, expires=now() + timedelta(seconds=span * 2))
        statement = statement.on_conflict_do_update(
            index_elements=["key"], set_={"count": RateWindow.count + 1}
        ).returning(RateWindow.count)
        count = db.scalar(statement)
        db.execute(delete(RateWindow).where(RateWindow.expires < now()))
        db.commit()
    return count <= (10 if signup else 30)
