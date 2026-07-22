from __future__ import annotations

import argparse
import importlib
import logging
import signal
import sys
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler

from .config import Config, SOURCE_REGISTRY, DEFAULT_SOURCES, default_vault_path
from .pipeline import run_pipeline, request_shutdown
from .sinks.filescan import FilescanSink, STAGING_BASE_URL
from .state import State
from .state_sync import StateSync
from .vault import EncryptedVault, CloudSyncVaultError


console = Console()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="samples_push",
        description="Collect malware samples from free feeds and push to filescan.io",
    )
    p.add_argument(
        "--sources",
        default=",".join(DEFAULT_SOURCES),
        help=f"Comma-separated source ids. Default: {','.join(DEFAULT_SOURCES)}. "
        f"All available: {','.join(SOURCE_REGISTRY)}",
    )
    p.add_argument(
        "--skip-sources",
        default="",
        help="Comma-separated source ids to exclude from --sources (e.g. thezoo)",
    )
    p.add_argument("--limit", type=int, default=25, help="Max samples per source")
    p.add_argument(
        "--delay",
        type=float,
        default=60,
        help="Seconds to wait between uploads to avoid queue overflow (default: 60)",
    )
    p.add_argument(
        "--vault",
        default=str(default_vault_path()),
        help="Vault directory (refused if under any cloud-sync folder). "
        f"Default: {default_vault_path()}",
    )
    p.add_argument("--wait", action="store_true", help="Poll filescan reports after upload")
    p.add_argument("--dry-run", action="store_true", help="Download into vault but skip upload")
    p.add_argument(
        "--replay",
        action="store_true",
        help="Before fetching new samples, re-upload every vault sample that "
        "hasn't been sent to the current target (e.g. ship prod-uploaded "
        "samples to staging).",
    )
    cache_group = p.add_mutually_exclusive_group()
    cache_group.add_argument(
        "--stats",
        action="store_true",
        help="Show upload statistics dashboard (uploads by day, source, status)",
    )
    cache_group.add_argument(
        "--clear-cache",
        action="store_true",
        help="Clear all upload history and source cursors (will re-upload all samples on next run)",
    )
    cache_group.add_argument(
        "--clear-target",
        metavar="URL",
        help="Clear upload history for specific target URL (e.g. https://staging.filescan.io)",
    )
    cache_group.add_argument(
        "--clear-cursors",
        action="store_true",
        help="Clear source cursors only (will re-fetch from sources but keep upload history)",
    )
    p.add_argument(
        "--import-zip",
        metavar="DIR",
        help="Import and upload all zipped samples from directory (recursively)",
    )
    p.add_argument(
        "--zip-password",
        default="infected",
        help="Password for encrypted zip files (default: infected)",
    )
    p.add_argument(
        "--cookies",
        metavar="FILE",
        help="Path to cookies file (JSON or Netscape format). Takes precedence over API key. "
        "Export from browser: DevTools > Application > Cookies > Right-click > Copy as cURL",
    )
    p.add_argument(
        "--repair-vault",
        action="store_true",
        help="Repair zip files with unsupported compression methods (DEFLATE64, BZIP2, LZMA) — NEW",
    )
    env_group = p.add_mutually_exclusive_group()
    env_group.add_argument(
        "--staging",
        action="store_true",
        help=f"Send samples to {STAGING_BASE_URL} instead of production",
    )
    env_group.add_argument(
        "--filescan-url",
        default=None,
        help="Override filescan base URL (e.g. https://staging.filescan.io). "
        "Takes precedence over FILESCAN_BASE_URL env var.",
    )
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True, markup=True)],
    )


def _build_sources(requested: list[str], config: Config) -> list:
    sources = []
    for sid in requested:
        if sid not in SOURCE_REGISTRY:
            console.print(f"[yellow]Unknown source '{sid}', skipping[/yellow]")
            continue
        module_path, class_name, required_keys = SOURCE_REGISTRY[sid]
        if required_keys and not config.has_keys(required_keys):
            console.print(
                f"[yellow]Skipping '{sid}': missing env vars {required_keys}[/yellow]"
            )
            continue
        mod = importlib.import_module(module_path)
        cls = getattr(mod, class_name)
        sources.append(cls(config))
    return sources


def _handle_import_zip(args: argparse.Namespace, state: State, config: Config) -> int:
    """Import and upload zipped samples from a directory."""
    import zipfile
    import hashlib

    log = logging.getLogger("samples_push")

    try:
        import_dir = Path(args.import_zip)
        if not import_dir.is_dir():
            console.print(f"[red]Directory not found: {import_dir}[/red]")
            return 2

        # Determine target URL
        if args.filescan_url:
            base_url = args.filescan_url
        elif args.staging:
            base_url = STAGING_BASE_URL
        else:
            base_url = config.filescan_base_url

        api_key = config.key_for_target(base_url)
        if not api_key and not args.cookies:
            need = (
                "FILESCAN_STAGING_API_KEY (or FILESCAN_API_KEY as fallback)"
                if "staging.filescan.io" in base_url
                else "FILESCAN_API_KEY"
            )
            console.print(
                f"[red]No API key or cookies file for target {base_url}. "
                f"Provide either: Set {need} in .env or use --cookies FILE[/red]"
            )
            return 2

        try:
            sink = FilescanSink(
                api_key=api_key,
                base_url=base_url,
                cookies_file=args.cookies,
            )
        except ValueError as e:
            console.print(f"[red]Failed to initialize FilescanSink: {e}[/red]")
            return 2
        password = args.zip_password.encode() if args.zip_password else None

        # Find all zip files
        zip_files = list(import_dir.rglob("*.zip"))
        if not zip_files:
            console.print(f"[yellow]No .zip files found in {import_dir}[/yellow]")
            return 0

        console.print(f"[cyan]Found {len(zip_files)} zip file(s) to import[/cyan]")

        stats = {"processed": 0, "uploaded": 0, "errors": 0, "skipped": 0}

        for zip_path in zip_files:
            console.print(f"\n[bold]Processing: {zip_path.name}[/bold]")
            try:
                with zipfile.ZipFile(zip_path) as zf:
                    files = zf.namelist()
                    if not files:
                        console.print(f"[yellow]  Empty zip file, skipping[/yellow]")
                        stats["skipped"] += 1
                        continue

                    for filename in files:
                        stats["processed"] += 1
                        try:
                            content = zf.read(filename, pwd=password)
                        except (RuntimeError, KeyError) as e:
                            console.print(f"[yellow]  Failed to read {filename}: {e}[/yellow]")
                            stats["errors"] += 1
                            continue

                        sha256 = hashlib.sha256(content).hexdigest()

                        # Skip if already uploaded to this target
                        if state.seen(sha256, base_url):
                            console.print(f"  [dim][OK] {filename} (already uploaded)[/dim]")
                            stats["skipped"] += 1
                            continue

                        try:
                            flow_id = sink.upload(filename, content)
                            state.mark(sha256, "import_zip", base_url, flow_id, "uploaded")
                            console.print(f"  [green][OK] {filename} -> flow_id={flow_id}[/green]")
                            stats["uploaded"] += 1
                        except Exception as e:
                            console.print(f"  [red][ERROR] {filename}: {e}[/red]")
                            state.mark(sha256, "import_zip", base_url, None, f"error: {str(e)[:100]}")
                            stats["errors"] += 1

            except zipfile.BadZipFile:
                console.print(f"[red]  Invalid zip file[/red]")
                stats["errors"] += 1
            except Exception as e:
                console.print(f"[red]  Error processing zip: {e}[/red]")
                stats["errors"] += 1

        console.print(f"\n[bold cyan]Summary[/bold cyan]")
        console.print(f"  Processed: {stats['processed']}")
        console.print(f"  Uploaded:  {stats['uploaded']}")
        console.print(f"  Skipped:   {stats['skipped']}")
        console.print(f"  Errors:    {stats['errors']}")

        return 0 if stats["errors"] == 0 else 1

    except Exception as e:
        console.print(f"[red]Import failed: {e}[/red]")
        log.exception("Import zip error")
        return 1
    finally:
        state.close()


def _handle_vault_repair(args: argparse.Namespace, state: State, config: Config) -> int:
    """Repair zip files with unsupported compression methods."""
    import zipfile
    import shutil

    log = logging.getLogger("samples_push")

    UNSUPPORTED_METHODS = {9, 12, 14}  # DEFLATE64, BZIP2, LZMA
    COMPRESSION_NAMES = {
        0: "STORED",
        8: "DEFLATED (OK)",
        9: "DEFLATE64 (NOT SUPPORTED)",
        12: "BZIP2 (NOT SUPPORTED)",
        14: "LZMA (NOT SUPPORTED)",
    }

    try:
        vault_samples_dir = Path(args.vault) / "samples"
        if not vault_samples_dir.exists():
            console.print(f"[red]Vault samples directory not found: {vault_samples_dir}[/red]")
            return 2

        zip_files = list(vault_samples_dir.glob("*.zip"))
        if not zip_files:
            console.print(f"[yellow]No zip files found in {vault_samples_dir}[/yellow]")
            return 0

        console.print(f"[cyan]Checking {len(zip_files)} zip file(s) for compression issues...[/cyan]\n")

        repairs_needed = []
        repairs_done = 0

        for zip_path in zip_files:
            console.print(f"[bold]{zip_path.name}[/bold]")

            # Check compression methods
            has_unsupported = False
            try:
                import pyzipper
                # Try pyzipper first for encrypted zips
                try:
                    with pyzipper.AESZipFile(zip_path, "r") as zf:
                        zf.setpassword(b"infected")
                        methods = {}
                        for file in zf.infolist():
                            method = file.compress_type
                            if method not in methods:
                                methods[method] = 0
                            methods[method] += 1

                        for method, count in sorted(methods.items()):
                            name = COMPRESSION_NAMES.get(method, f"Unknown ({method})")
                            if method in UNSUPPORTED_METHODS:
                                console.print(f"  [red][UNSUPPORTED][/red] {name}: {count} files")
                                has_unsupported = True
                            else:
                                console.print(f"  [green][OK][/green] {name}: {count} files")
                except Exception:
                    # Fall back to standard zipfile
                    with zipfile.ZipFile(zip_path, "r") as zf:
                        methods = {}
                        for file in zf.infolist():
                            method = file.compress_type
                            if method not in methods:
                                methods[method] = 0
                            methods[method] += 1

                        for method, count in sorted(methods.items()):
                            name = COMPRESSION_NAMES.get(method, f"Unknown ({method})")
                            if method in UNSUPPORTED_METHODS:
                                console.print(f"  [red][UNSUPPORTED][/red] {name}: {count} files")
                                has_unsupported = True
                            else:
                                console.print(f"  [green][OK][/green] {name}: {count} files")

            except Exception as e:
                console.print(f"  [yellow]Error checking compression: {e}[/yellow]")
                has_unsupported = True

            if has_unsupported:
                repairs_needed.append(zip_path)
                console.print(f"  [red][NEEDS REPAIR][/red]\n")
            else:
                console.print(f"  [green][OK][/green]\n")

        if not repairs_needed:
            console.print("[green]All zip files are OK - no repairs needed[/green]")
            return 0

        console.print(f"[cyan]Repairing {len(repairs_needed)} file(s)...[/cyan]\n")

        for zip_path in repairs_needed:
            console.print(f"[bold]Repairing: {zip_path.name}[/bold]")

            try:
                from samples_push.sinks.filescan import FilescanSink as FS

                files_to_copy = []

                # Read from old zip
                try:
                    import pyzipper

                    with pyzipper.AESZipFile(zip_path, "r") as zf_old:
                        zf_old.setpassword(b"infected")
                        for name in zf_old.namelist():
                            try:
                                data = zf_old.read(name)
                                files_to_copy.append((name, data))
                                console.print(f"  [dim]Read: {name} ({len(data)} bytes)[/dim]")
                            except Exception as e:
                                console.print(f"  [yellow]Warning: Could not read {name}: {e}[/yellow]")

                except Exception as e:
                    console.print(f"  [yellow]Info: Trying without encryption...[/yellow]")
                    with zipfile.ZipFile(zip_path, "r") as zf_old:
                        for name in zf_old.namelist():
                            try:
                                data = zf_old.read(name)
                                files_to_copy.append((name, data))
                                console.print(f"  [dim]Read: {name} ({len(data)} bytes)[/dim]")
                            except Exception as e:
                                console.print(f"  [yellow]Warning: Could not read {name}: {e}[/yellow]")

                if not files_to_copy:
                    console.print(f"  [red]Failed: No files were successfully read[/red]\n")
                    continue

                # Write to temp zip with DEFLATE
                temp_path = zip_path.parent / f"{zip_path.stem}_temp.zip"
                import pyzipper

                with pyzipper.AESZipFile(
                    temp_path,
                    "w",
                    compression=pyzipper.ZIP_DEFLATED,
                    encryption=pyzipper.WZ_AES,
                ) as zf_new:
                    zf_new.setpassword(b"infected")
                    for name, data in files_to_copy:
                        zf_new.writestr(name, data)

                # Backup and replace
                backup_path = zip_path.parent / f"{zip_path.stem}_backup.zip"
                shutil.move(str(zip_path), str(backup_path))
                shutil.move(str(temp_path), str(zip_path))

                console.print(
                    f"  [green][SUCCESS][/green] Repaired ({len(files_to_copy)} files)\n"
                )
                repairs_done += 1

            except Exception as e:
                console.print(f"  [red]Error: {e}[/red]\n")
                log.exception("Vault repair error")

        console.print("[bold cyan]Repair Complete[/bold cyan]")
        console.print(f"  Repaired: {repairs_done}/{len(repairs_needed)}")

        if repairs_done > 0:
            console.print(
                "\n[yellow]Next step:[/yellow] Re-upload samples with:"
            )
            console.print("  [blue]python -m samples_push --replay --limit 100[/blue]")

        return 0 if repairs_done == len(repairs_needed) else 1

    except Exception as e:
        console.print(f"[red]Vault repair failed: {e}[/red]")
        log.exception("Vault repair error")
        return 1
    finally:
        state.close()


def _handle_stats(state: State, vault: "EncryptedVault") -> int:
    """Print upload statistics dashboard."""
    from collections import Counter
    from rich.panel import Panel
    from rich.table import Table
    from rich.columns import Columns

    try:
        total = state.count_processed()
        if total == 0:
            console.print("[yellow]No upload data yet.[/yellow]")
            return 0

        console.print(Panel(f"[bold]{total:,}[/bold] total samples processed", title="Upload Stats"))

        by_day_source = state.stats_by_day_source(days=14)
        if by_day_source:
            console.rule("Uploads by Day x Source (last 14 days)")

            all_sources = sorted({src for _, src, _ in by_day_source})
            grid: dict[str, dict[str, int]] = {}
            for day, src, count in by_day_source:
                grid.setdefault(day, {})[src] = count

            day_table = Table(show_header=True, show_edge=False, pad_edge=False)
            day_table.add_column("Date", style="cyan", no_wrap=True)
            for src in all_sources:
                day_table.add_column(src, justify="right")
            day_table.add_column("Total", justify="right", style="bold")

            source_totals = {src: 0 for src in all_sources}
            grand_total = 0
            for day in sorted(grid.keys(), reverse=True):
                row_counts = grid[day]
                row = [str(row_counts.get(src, "")) for src in all_sources]
                row_total = sum(row_counts.values())
                for src in all_sources:
                    source_totals[src] += row_counts.get(src, 0)
                grand_total += row_total
                day_table.add_row(day, *row, str(row_total))

            day_table.add_section()
            totals_row = [str(source_totals[src]) for src in all_sources]
            day_table.add_row("[bold]Total[/bold]", *totals_row, f"[bold]{grand_total}[/bold]")

            console.print(day_table)
            console.print()

        by_source = state.stats_by_source()
        by_status = state.stats_by_status()

        src_table = Table(title="By Source (all time)", show_header=True, show_edge=False)
        src_table.add_column("Source", style="cyan")
        src_table.add_column("Count", justify="right", style="bold")
        src_total = 0
        for source, count in by_source:
            src_table.add_row(source, f"{count:,}")
            src_total += count
        src_table.add_section()
        src_table.add_row("[bold]Total[/bold]", f"[bold]{src_total:,}[/bold]")

        status_table = Table(title="By Status", show_header=True, show_edge=False)
        status_table.add_column("Status", style="cyan")
        status_table.add_column("Count", justify="right", style="bold")
        status_total = 0
        for status, count in by_status:
            label = status[:40] if len(status) > 40 else status
            status_table.add_row(label, f"{count:,}")
            status_total += count
        status_table.add_section()
        status_table.add_row("[bold]Total[/bold]", f"[bold]{status_total:,}[/bold]")

        console.print(Columns([src_table, status_table], padding=(0, 4)))
        console.print()

        vault_items = vault.list_all_with_sizes()
        if vault_items:
            console.rule("Vault File Analysis")

            ext_counter: Counter[str] = Counter()
            sizes: list[int] = []
            for _, _, name, size in vault_items:
                ext = name.rsplit(".", 1)[1].lower() if "." in name else "(none)"
                ext_counter[ext] += 1
                sizes.append(size)

            type_table = Table(title="By File Type", show_header=True, show_edge=False)
            type_table.add_column("Extension", style="cyan")
            type_table.add_column("Count", justify="right", style="bold")
            for ext, count in ext_counter.most_common(15):
                type_table.add_row(f".{ext}" if ext != "(none)" else ext, f"{count:,}")
            type_table.add_section()
            type_table.add_row("[bold]Total[/bold]", f"[bold]{len(vault_items):,}[/bold]")

            size_table = Table(title="By Size Range", show_header=True, show_edge=False)
            size_table.add_column("Range", style="cyan")
            size_table.add_column("Count", justify="right", style="bold")
            ranges = [
                ("< 1 KB", 0, 1024),
                ("1-10 KB", 1024, 10240),
                ("10-100 KB", 10240, 102400),
                ("100 KB - 1 MB", 102400, 1048576),
                ("1-10 MB", 1048576, 10485760),
                ("> 10 MB", 10485760, float("inf")),
            ]
            for label, lo, hi in ranges:
                count = sum(1 for s in sizes if lo <= s < hi)
                if count > 0:
                    size_table.add_row(label, f"{count:,}")
            size_table.add_section()
            total_size_mb = sum(sizes) / 1048576
            size_table.add_row(
                "[bold]Total[/bold]",
                f"[bold]{len(sizes):,}[/bold] ({total_size_mb:.1f} MB)",
            )

            console.print(Columns([type_table, size_table], padding=(0, 4)))

        return 0
    finally:
        state.close()


def _handle_cache_clear(args: argparse.Namespace, state: State, config: Config) -> int:
    """Handle cache clearing commands."""
    try:
        if args.clear_cache:
            console.print("[yellow]Clearing all upload history and cursors...[/yellow]")
            processed_count = state.clear_all()
            cursor_count = state.clear_cursors()
            console.print(
                f"[green][OK][/green] Cleared {processed_count} upload records and {cursor_count} source cursors"
            )
            console.print("[bold]Next run will re-upload all samples and re-fetch from all sources[/bold]")
            return 0

        if args.clear_target:
            target_url = args.clear_target.rstrip("/")
            console.print(f"[yellow]Clearing upload history for target: {target_url}[/yellow]")
            count = state.clear_target(target_url)
            console.print(f"[green][OK][/green] Cleared {count} upload records for {target_url}")
            console.print(f"[bold]Next run will re-upload samples to {target_url}[/bold]")
            return 0

        if args.clear_cursors:
            console.print("[yellow]Clearing source cursors...[/yellow]")
            count = state.clear_cursors()
            console.print(f"[green][OK][/green] Cleared {count} source cursors")
            console.print("[bold]Next run will re-fetch from all sources[/bold]")
            return 0

    except Exception as e:
        console.print(f"[red]Error clearing cache: {e}[/red]")
        return 1
    finally:
        state.close()


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    _setup_logging(args.verbose)
    log = logging.getLogger("samples_push")

    config = Config.load()

    try:
        vault = EncryptedVault(Path(args.vault))
    except CloudSyncVaultError as e:
        console.print(f"[red]{e}[/red]")
        return 2

    state_db_path = vault.root / "state.db"
    sync: StateSync | None = None
    if config.state_repo_url:
        sync = StateSync(config.state_repo_url, state_db_path, config.state_repo_branch)
        try:
            sync.pull()
        except Exception as e:
            log.warning("state-sync pull failed: %s (continuing with local state)", e)

    state = State(state_db_path)

    if args.stats:
        return _handle_stats(state, vault)

    if args.clear_cache or args.clear_target or args.clear_cursors:
        return _handle_cache_clear(args, state, config)

    if args.import_zip:
        return _handle_import_zip(args, state, config)

    if args.repair_vault:
        return _handle_vault_repair(args, state, config)

    if args.filescan_url:
        base_url = args.filescan_url
    elif args.staging:
        base_url = STAGING_BASE_URL
    else:
        base_url = config.filescan_base_url

    api_key = config.key_for_target(base_url)
    if not args.dry_run:
        if not api_key and not args.cookies and not config.filescan_auth_token:
            need = (
                "FILESCAN_STAGING_API_KEY (or FILESCAN_API_KEY as fallback)"
                if "staging.filescan.io" in base_url
                else "FILESCAN_API_KEY or FILESCAN_AUTH_TOKEN"
            )
            console.print(
                f"[red]No authentication for target {base_url}. "
                f"Set {need} in .env (or pass --dry-run).[/red]"
            )
            return 2
        if (
            "staging.filescan.io" in base_url
            and not config.filescan_staging_api_key
            and not args.cookies
        ):
            console.print(
                "[yellow]FILESCAN_STAGING_API_KEY not set — falling back to "
                "FILESCAN_API_KEY for staging uploads. Staging usually "
                "requires its own key. Or use --cookies FILE for UI-based auth.[/yellow]"
            )

    if args.dry_run:
        sink = None
    else:
        try:
            sink = FilescanSink(
                api_key=api_key,
                base_url=base_url,
                cookies_file=args.cookies,
                auth_token=config.filescan_auth_token or None,
            )
        except ValueError as e:
            console.print(f"[red]Failed to initialize FilescanSink: {e}[/red]")
            state.close()
            return 2

    requested = [s.strip() for s in args.sources.split(",") if s.strip()]
    skipped = {s.strip() for s in args.skip_sources.split(",") if s.strip()}
    if skipped:
        requested = [s for s in requested if s not in skipped]
    sources = _build_sources(requested, config)
    if not sources:
        console.print("[red]No usable sources after filtering. Check API keys.[/red]")
        return 2

    log.info("Vault: %s", vault.root)
    log.info("Sources: %s", ", ".join(s.name for s in sources))
    if sink:
        log.info("Auth method: %s", sink.auth_method)
    log.info("Target: %s%s", base_url, " (DRY-RUN, no upload)" if args.dry_run else "")
    log.info(
        "Limit per source: %d  dry_run=%s  wait=%s  replay=%s  delay=%gs",
        args.limit, args.dry_run, args.wait, args.replay, args.delay,
    )
    if args.replay and args.dry_run:
        log.warning("--replay is a no-op under --dry-run (no sink to upload to)")

    def _handle_sigint(signum, frame):
        console.print("\n[yellow]Ctrl+C received — finishing current upload and stopping...[/yellow]")
        request_shutdown()

    signal.signal(signal.SIGINT, _handle_sigint)

    try:
        totals = run_pipeline(
            sources=sources,
            vault=vault,
            state=state,
            sink=sink,
            target=base_url,
            limit=args.limit,
            wait=args.wait,
            replay=args.replay,
            delay=args.delay,
        )
    finally:
        state.close()
        if sync:
            try:
                sync.push()
            except Exception as e:
                log.warning("state-sync push failed: %s", e)

    console.rule("Summary")
    for name, stats in totals.items():
        console.print(
            f"[bold]{name}[/bold]  fetched={stats['fetched']}  "
            f"new={stats.get('new', 0)}  uploaded={stats['uploaded']}  "
            f"deferred={stats.get('deferred', 0)}  errors={stats['errors']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
