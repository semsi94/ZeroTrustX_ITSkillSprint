from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from api.deps import current_user_token
from api.splunk import SearchIn, execute_search, safe_search_response

router = APIRouter(prefix="/investigation", tags=["investigation"])
api_router = APIRouter(prefix="/api/investigation", tags=["investigation"])


@router.post("/splunk/search")
@api_router.post("/splunk/search")
async def splunk_search(body: SearchIn, user_token: dict = Depends(current_user_token)):
    if user_token.get("role") == "viewer":
        raise HTTPException(status_code=403, detail="Viewer cannot run investigations")
    try:
        return await execute_search(body)
    except Exception as e:
        return safe_search_response(error=str(e) or e.__class__.__name__)


@router.get("/events")
async def events(
    earliest: str = Query("-24h"),
    latest: str = Query("now"),
    src_ip: Optional[str] = None,
    dest_ip: Optional[str] = None,
    user: Optional[str] = None,
    host: Optional[str] = None,
    action: Optional[str] = None,
    status_code: Optional[str] = None,
    method: Optional[str] = None,
    path: Optional[str] = None,
    keyword: Optional[str] = None,
    index: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    user_token: dict = Depends(current_user_token),
):
    body = SearchIn(
        earliest=earliest,
        latest=latest,
        index=index,
        source_ip=src_ip,
        destination_ip=dest_ip,
        user=user,
        host=host,
        action=action,
        status_code=status_code,
        method=method,
        path=path,
        keyword=keyword,
        limit=limit,
    )
    return await splunk_search(body, user_token)
