from __future__ import annotations

import logging
import time
from typing import Iterable

from .sinks.filescan import FilescanError, FilescanQueueFull, FilescanSink
from .sources.base import Source
from .state import State
from .vault import EncryptedVault


log = logging.getLogger(__name__)


def _replay(
    state: State,
    vault: EncryptedVault,
    sink: FilescanSink,
    target: str,
    wait: bool,
    limit: int = 0,
    delay: float = 0,
) -> dict[str, int]:
    stats = {"fetched": 0, "uploaded": 0, "errors": 0, "deferred": 0, "missing": 0}

    # Scan vault directly for all samples not yet sent to target
    all_samples = vault.list_all()
    candidates = [
        (source, sha, filename)
        for source, sha, filename in all_samples
        if not state.seen(sha, target)
    ]

    if not candidates:
        log.info("[bold cyan]== replay ==[/bold cyan] nothing to replay to %s "
                 "(%d samples already uploaded)", target, len(all_samples))
        return stats

    if limit > 0:
        candidates = candidates[:limit]

    log.info("[bold cyan]== replay ==[/bold cyan] %d sample(s) to upload to %s "
             "(out of %d in vault, delay=%gs)", len(candidates), target, len(all_samples), delay)

    for i, (source, sha, filename) in enumerate(candidates):
        if delay > 0 and i > 0:
            log.debug("waiting %gs before next upload...", delay)
            time.sleep(delay)

        stats["fetched"] += 1
        try:
            name, data = vault.read(source, sha)
        except KeyError:
            log.warning("replay skip %s/%s: not in vault", source, sha[:12])
            stats["missing"] += 1
            continue
        except Exception as e:
            log.exception("replay vault read %s/%s failed: %s", source, sha[:12], e)
            stats["errors"] += 1
            continue
        try:
            flow_id = sink.upload(name, data)
        except FilescanQueueFull as e:
            log.error(
                "filescan queue full during replay, stopping. %s/%s deferred (%s)",
                source, sha[:12], e,
            )
            stats["deferred"] += 1
            return stats | {"_queue_full": 1}
        except FilescanError as e:
            log.warning("replay upload %s/%s failed: %s", source, sha[:12], e)
            state.mark(sha, source, target, flow_id=None,
                       status=f"upload_failed: {e}"[:200])
            stats["errors"] += 1
            continue
        except Exception as e:
            log.exception("replay upload %s crashed: %s", sha[:12], e)
            state.mark(sha, source, target, flow_id=None,
                       status=f"crash: {e}"[:200])
            stats["errors"] += 1
            continue

        state.mark(sha, source, target, flow_id=flow_id, status="uploaded")
        stats["uploaded"] += 1
        log.info("replayed %s/%s flow_id=%s", source, sha[:12], flow_id)

        if wait:
            try:
                sink.poll_report(flow_id)
                state.mark(sha, source, target, flow_id=flow_id,
                           status="report_ready")
            except FilescanError as e:
                log.warning("poll %s failed: %s", flow_id, e)
    return stats


def run_pipeline(
    sources: Iterable[Source],
    vault: EncryptedVault,
    state: State,
    sink: FilescanSink | None,
    target: str,
    limit: int,
    wait: bool,
    replay: bool = False,
    delay: float = 0,
) -> dict[str, dict[str, int]]:
    totals: dict[str, dict[str, int]] = {}
    queue_full_stop = False

    if replay and sink is not None:
        replay_stats = _replay(state, vault, sink, target, wait, limit=limit, delay=delay)
        if replay_stats.pop("_queue_full", 0):
            queue_full_stop = True
        totals["__replay__"] = replay_stats
        return totals

    for src in sources:
        stats = {"fetched": 0, "new": 0, "uploaded": 0, "errors": 0, "deferred": 0}
        totals[src.name] = stats
        if queue_full_stop:
            log.warning("[%s] skipped: filescan queue full earlier this run", src.name)
            continue
        log.info("[bold cyan]== %s ==[/bold cyan]", src.name)
        try:
            iterator = src.iter_new(limit)
        except Exception as e:
            log.exception("source %s init failed: %s", src.name, e)
            stats["errors"] += 1
            continue

        while True:
            try:
                sample = next(iterator)
            except StopIteration:
                break
            except Exception as e:
                # Network blip / API outage inside the source generator —
                # log and move to the next source instead of aborting the run.
                log.warning("[%s] iteration aborted: %s", src.name, e)
                stats["errors"] += 1
                break

            stats["fetched"] += 1
            sha = sample.sha256.lower()
            if state.seen(sha, target):
                log.debug("skip %s (already sent to %s)", sha, target)
                continue
            try:
                vault.add(src.name, sha, sample.filename, sample.content)
            except Exception as e:
                log.exception("vault add %s failed: %s", sha, e)
                stats["errors"] += 1
                continue
            stats["new"] += 1

            if sink is None:
                state.mark(sha, src.name, target, flow_id=None, status="vaulted")
                log.info("vaulted %s/%s", src.name, sha[:12])
                continue

            if delay > 0 and stats["uploaded"] > 0:
                log.debug("waiting %gs before next upload...", delay)
                time.sleep(delay)

            try:
                _, data = vault.read(src.name, sha)
                flow_id = sink.upload(sample.filename, data)
            except FilescanQueueFull as e:
                log.error(
                    "filescan queue full, stopping run. Sample %s left in vault, "
                    "will retry on next run. (%s)",
                    sha[:12], e,
                )
                stats["deferred"] += 1
                queue_full_stop = True
                break
            except FilescanError as e:
                log.warning("filescan upload %s failed: %s", sha, e)
                state.mark(sha, src.name, target, flow_id=None,
                           status=f"upload_failed: {e}"[:200])
                stats["errors"] += 1
                continue
            except Exception as e:
                log.exception("upload %s crashed: %s", sha, e)
                state.mark(sha, src.name, target, flow_id=None,
                           status=f"crash: {e}"[:200])
                stats["errors"] += 1
                continue

            state.mark(sha, src.name, target, flow_id=flow_id, status="uploaded")
            stats["uploaded"] += 1
            log.info("uploaded %s/%s flow_id=%s", src.name, sha[:12], flow_id)

            if wait:
                try:
                    sink.poll_report(flow_id)
                    state.mark(sha, src.name, target, flow_id=flow_id,
                               status="report_ready")
                except FilescanError as e:
                    log.warning("poll %s failed: %s", flow_id, e)

    return totals
