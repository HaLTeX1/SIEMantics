# Hatter feladat: az IRIS-ben lezart esetek kimenetelenek idonkenti atvetele.

import asyncio
import logging

from app.case_actions import sync_closed_cases
from app.db import async_session

logger = logging.getLogger("siemantics.iris_sync")


class CaseSyncer:
    def __init__(self) -> None:
        self._task: asyncio.Task | None = None

    def start(self, interval_seconds: int) -> None:
        if interval_seconds > 0:
            self._task = asyncio.create_task(self._run(interval_seconds))

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None

    async def _run(self, interval_seconds: int) -> None:
        while True:
            try:
                async with async_session() as session:
                    await sync_closed_cases(session)
            except Exception:
                # A ciklus eletben marad, a kovetkezo korben ujra probalja.
                logger.exception("IRIS case sync failed")
            await asyncio.sleep(interval_seconds)


case_syncer = CaseSyncer()
