"""
Real-time watcher for new/modified files. Uses watchdog if available.
"""

from pathlib import Path
from typing import Callable, List, Optional
import logging

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ImportError as exc:  # noqa: BLE001
    raise ImportError("Instaleaza watchdog pentru functia watch: pip install watchdog") from exc


def start_watch(
    paths: List[str],
    analyzer,
    recursive: bool = True,
    on_result: Optional[Callable] = None,
):
    """
    Porneste monitorizarea si blocheaza thread-ul curent (observer.join()).
    """
    observer = start_watch_async(paths, analyzer, recursive=recursive, on_result=on_result)
    try:
        observer.join()
    except KeyboardInterrupt:
        observer.stop()
    observer.stop()
    observer.join()


def start_watch_async(
    paths: List[str],
    analyzer,
    recursive: bool = True,
    on_result: Optional[Callable] = None,
):
    """
    Porneste monitorizarea fara sa blocheze thread-ul curent. Returneaza Observer-ul.
    """

    class Handler(FileSystemEventHandler):
        def on_created(self, event):
            if event.is_directory:
                return
            self._scan(event.src_path)

        def on_modified(self, event):
            if event.is_directory:
                return
            self._scan(event.src_path)

        def _scan(self, path: str):
            try:
                res = analyzer.analyze_file(path)
                if on_result:
                    on_result(res)
            except Exception as exc:  # noqa: BLE001
                logging.getLogger("watcher").warning("Eroare scanare %s: %s", path, exc)

    observer = Observer()
    handler = Handler()
    for p in paths:
        observer.schedule(handler, path=str(Path(p)), recursive=recursive)
    observer.start()
    return observer


def stop_watch(observer):
    """Opreste un observer returnat de start_watch_async."""
    try:
        observer.stop()
        observer.join(timeout=5)
    except Exception:
        pass
