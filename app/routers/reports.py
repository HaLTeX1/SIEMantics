# Bejelentkezeshez kotott riportok (pl. a szakdolgozat tablazatai) az app/reports mappabol.

import re
from pathlib import Path
from string import Template
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.db import get_session
from app.reports_data import BUILDERS

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
# Csak egyszeru nev, igy a mappabol nem lehet kilepni.
_NAME = re.compile(r"^[a-z0-9-]+$")

router = APIRouter(tags=["reports"])


@router.get("/reports/{name}", include_in_schema=False)
async def get_report(name: str, request: Request, session: AsyncSession = Depends(get_session)):
    try:
        await get_current_user(request, session)
    except HTTPException:
        # Bejelentkezes nelkul a login oldalra, onnan vissza ide.
        return RedirectResponse(f"/ui/login.html?next={quote(request.url.path)}", status_code=303)
    path = REPORTS_DIR / f"{name}.html"
    if not _NAME.fullmatch(name) or not path.is_file():
        raise HTTPException(status_code=404, detail="report not found")
    builder = BUILDERS.get(name)
    if builder is None:
        return FileResponse(path, media_type="text/html", headers={"Cache-Control": "no-store"})
    # Elo riport: a $nev helyorzok a dontesnaplobol szamolt ertekekkel.
    page = Template(path.read_text(encoding="utf-8")).safe_substitute(await builder(session))
    return HTMLResponse(page, headers={"Cache-Control": "no-store"})
