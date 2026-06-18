import logging
from datetime import datetime, timezone

from sqlalchemy import create_engine, update
from sqlalchemy.orm import sessionmaker

from adapters.pfsense_adapter import PfSenseAdapter
from adapters.splunk_adapter import SplunkAdapter
from config import get_settings
from models.response_action import ResponseAction
from workers.celery_app import celery_app

log = logging.getLogger("zerotrustx.worker")


def _sync_sessionmaker():
    s = get_settings()
    engine = create_engine(s.DATABASE_URL_SYNC, pool_pre_ping=True, future=True)
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


def _update_action(action_id: str, **fields) -> None:
    Session = _sync_sessionmaker()
    with Session.begin() as session:
        session.execute(
            update(ResponseAction)
            .where(ResponseAction.id == action_id)
            .values(**fields)
        )


def _hec_audit(event: dict) -> None:
    try:
        SplunkAdapter().write_to_hec(event)
    except Exception as e:
        log.warning("HEC audit failed: %s", e)


@celery_app.task(bind=True, max_retries=3, name="workers.response_tasks.block_ip_task")
def block_ip_task(self, ip: str, incident_id: str, action_id: str, alias: str = None):
    try:
        adapter = PfSenseAdapter()
        result = adapter.add_to_alias(ip, alias)
        _update_action(
            action_id,
            status="executed",
            executed_at=datetime.now(timezone.utc),
            output=result,
            error_message=None,
            rollback_available=True,
        )
        _hec_audit({
            "action_type": "block_ip",
            "target": ip,
            "incident_id": incident_id,
            "status": "executed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        return {"success": True, "result": result}
    except Exception as e:
        err = str(e)
        _update_action(
            action_id,
            status="failed",
            error_message=err,
            rollback_available=False,
        )
        log.error("block_ip_task failed for %s: %s", ip, err)
        if self.request.retries < self.max_retries:
            raise self.retry(exc=e, countdown=30)
        return {"success": False, "error": err}


@celery_app.task(bind=True, name="workers.response_tasks.unblock_ip_task")
def unblock_ip_task(self, ip: str, action_id: str, alias: str = None):
    try:
        adapter = PfSenseAdapter()
        result = adapter.remove_from_alias(ip, alias)
        _update_action(
            action_id,
            status="reverted",
            reverted_at=datetime.now(timezone.utc),
            output=result,
            rollback_available=False,
        )
        _hec_audit({
            "action_type": "unblock_ip",
            "target": ip,
            "status": "reverted",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        return {"success": True, "result": result}
    except Exception as e:
        err = str(e)
        _update_action(action_id, status="failed", error_message=err)
        log.error("unblock_ip_task failed for %s: %s", ip, err)
        return {"success": False, "error": err}
