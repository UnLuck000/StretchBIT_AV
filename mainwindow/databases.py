"""Базы и события работы: обновление баз, счётчики, запись о запуске. Часть главного окна: методы
MainWindow (gui.py)."""
import threading
import time

from PySide6.QtCore import QTimer, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QMessageBox, QSystemTrayIcon

from diag import features
from networkmonitor.ioc import load_ip_blocklist
from recovery import activity
from scanner import pool as scan_pool
from scanner.hashing import count_hashes
from scanner.yara_engine import count_rules
from ui import settings as cfg
import appinfo
import updater
from mainwindow.common import NETFEEDS_DIR, RULES_DIR, SIGNATURES, _dlog


class DatabasesMixin:
    """Атрибуты и сигналы — у MainWindow (gui.py)."""

    def start_activity(self):
        """Событие о запуске и очистка событий старше 90 дней (recovery/activity.py)."""
        activity.record("program", f"Программа запущена ({appinfo.VERSION})")
        activity.trim()

    # ---------- главная страница и настройки ----------
    def _database_stats(self) -> dict | None:
        """Счётчики баз. Считать их недёшево (тысячи файлов правил): в фоне и с кэшем;
        пока не посчитаны — None, по готовности главная обновится (db_stats_ready).
        В главном потоке подсчёт держал интерфейс ~2 с при входе в режим администратора."""
        if self._db_stats is None and not getattr(self, "_db_counting", False):
            self._db_counting = True

            def job():
                try:
                    hashes = count_hashes(SIGNATURES.parent)
                    rule_files, rules = count_rules(RULES_DIR)
                    md5 = sum(p.stat().st_size // 16
                              for p in (SIGNATURES.parent / "feeds").glob("*.md5.bin"))
                    stats = {"hashes": hashes + md5, "md5": md5, "rules": rules,
                             "rule_files": rule_files,
                             "c2": len(load_ip_blocklist(NETFEEDS_DIR))}
                except Exception as e:  # noqa: BLE001
                    _dlog.warning("Счётчики баз не посчитаны: %s", e)
                    stats = None
                finally:
                    self._db_counting = False
                if stats is not None:
                    self.db_stats_ready.emit(stats)

            threading.Thread(target=job, daemon=True, name="db-stats").start()
        return self._db_stats

    def _on_db_stats(self, stats: dict) -> None:
        self._db_stats = stats
        self.refresh_dashboard()

    def check_updates(self):
        QDesktopServices.openUrl(QUrl(appinfo.RELEASES_URL))

    def update_databases_manual(self):
        """Кнопка «Обновить» на главной: обновить базы сейчас. Со службой просим её (окно без
        прав не пишет в папку баз), без службы — качаем сами."""
        if self.service is not None:
            from service.client import ServiceError
            try:
                self.service.call("bases.update")
                self.add_event("Запрошено обновление баз (служба)")
            except ServiceError as e:
                self.statusBar().showMessage(f"Служба не начала обновление: {e}", 12000)
            return
        if not updater.can_update():
            self.add_event("Базы не обновлены: нет прав администратора "
                           "(папка баз закрыта от записи)", "warning")
            self.statusBar().showMessage("Обновление баз требует прав администратора", 8000)
            return
        self.update_databases(silent=False)

    def start_auto_update(self):
        """Автообновление баз: при запуске и затем каждые полчаса проверяется, прошли ли
        12 часов с последнего обновления (см. updater.update_due). Там же каждые 5 минут —
        новый выпуск программы (updatecheck.py)."""
        self.auto_update_timer.start()
        QTimer.singleShot(5000, self.auto_update_check)  # окно успевает открыться
        QTimer.singleShot(20000, self.check_release)
        self._release_timer = QTimer(self)
        self._release_timer.timeout.connect(self.check_release)
        self._release_timer.start(5 * 60 * 1000)

    # ---------- обновление программы ----------
    def check_release(self):
        if time.time() - cfg.get("update/last_check") < 5 * 60:
            return

        def job():
            import updatecheck
            try:
                release = updatecheck.latest()
                cfg.set_("update/last_check", time.time())
                self.release_found.emit(release, "")
            except Exception as e:  # noqa: BLE001 — нет сети, нет выпусков, лимит GitHub
                self.release_found.emit(None, str(e))

        threading.Thread(target=job, daemon=True, name="release-check").start()

    def _on_release_found(self, release, error: str):
        import updatecheck
        if release is None or not updatecheck.newer(release.version):
            return
        if cfg.get("update/skipped") == release.version:
            return
        if cfg.get("update/shown") == release.version:
            return  # эту версию уже обрабатывали — не докучать каждые 5 минут
        if self.isHidden():  # в трее: уведомление, окно изменений — когда откроют программу
            if getattr(getattr(self, "_pending_changelog", None), "version", None) == release.version:
                return  # не повторяем уведомление в этом сеансе; после рестарта предложим снова
            self._pending_changelog = release
            self._notify_update(release)
        else:               # окно открыто: сразу окно со списком изменений
            self._show_changelog(release)
        # скачивание и установка — только после согласия (кнопка «Обновить» в окне изменений)

    def _download_and_install(self, release):
        """Скачать установщик и запустить мастер Inno Setup (согласие на установку спрашивает
        он) — вызывается только после нажатия «Обновить». Запоминаем, было ли окно в трее, —
        после установки оно туда же и вернётся."""
        cfg.set_("update/pending", "1" if self.isHidden() else "0")
        activity.record("update", f"Обновление: {release.version}")

        def job():
            import updatecheck
            try:
                path = updatecheck.download(release)
                updatecheck.run_installer(path)
            except Exception as e:  # noqa: BLE001 — попробуем ещё раз при следующей проверке
                cfg.set_("update/shown", "")
                activity.record("update", f"Обновление не удалось: {e}")

        threading.Thread(target=job, daemon=True, name="release-download").start()

    def _show_changelog(self, release):
        """Окно со списком изменений новой версии (changelog с GitHub). Скачивание и
        установка начинаются только после нажатия «Обновить»."""
        from ui.changelog_window import ChangelogWindow
        win = getattr(self, "changelog_window", None)
        if win is not None and win.isVisible():
            win.close()
        win = ChangelogWindow(release.version, release.notes, self)
        win.update_requested.connect(lambda: self._download_and_install(release))
        self.changelog_window = win
        win.show()
        cfg.set_("update/shown", release.version)  # только действительно показанное окно
        win.raise_()
        win.activateWindow()

    def _notify_update(self, release):
        """Уведомление Windows о новой версии (без него — через значок в трее). Кнопка
        «Подробнее» открывает окно со списком изменений."""
        shown = self.notifier.show(
            "Обновление StretchBIT",
            f"Доступна новая версия StretchBIT {release.version}.",
            [("Подробнее", "open")],
            lambda argument: self.show_main() if argument in ("open", "") else None)
        if not shown and self.tray is not None:
            self.tray.showMessage(
                "Обновление StretchBIT",
                f"Доступна новая версия StretchBIT {release.version}.",
                QSystemTrayIcon.MessageIcon.Information, 12000)

    def auto_update_check(self):
        if getattr(self, "service", None) is not None:
            return  # базы обновляет служба (service/core.py): окно без прав — не может
        if self._updating or not updater.needs_update(cfg.get("db/last_update")):
            return
        if not updater.can_update():
            if not getattr(self, "_update_denied", False):  # сообщить один раз за запуск
                self._update_denied = True
                self.add_event("Базы не обновлены: программа запущена без прав "
                               "администратора (папка баз закрыта от записи)", "warning")
            return
        self.update_databases(silent=True)

    def update_databases(self, silent: bool = True):
        """Обновление баз. Вручную его не запускают: только автообновление (silent),
        без сообщения об успехе. silent=False оставлен для отладки из консоли."""
        if self._updating:
            return
        self._updating = True
        self._db_fraction = 0.0
        features.begin("db.update")
        self._update_silent = silent
        if not silent:
            self.statusBar().showMessage("Обновляю базы (хэши, правила YARA, адреса C2)...")
        self.refresh_dashboard()
        threading.Thread(target=self._update_job, args=(silent,), daemon=True).start()

    def _update_job(self, silent: bool):
        import contextlib
        import io

        buffer = io.StringIO()
        ok = False
        try:
            with contextlib.redirect_stdout(buffer):
                ok = updater.update_all(progress=self.update_progress.emit,
                                        fraction=self.update_fraction.emit)
        except Exception as e:
            buffer.write(f"Ошибка: {e}\n")
        # update_all возвращает True / "partial" / False. Окну "partial" — успех (часть
        # источников не ответила, но базы обновились): без bool() строка попала бы в
        # bool-сигнал как False, и частичное обновление показывалось бы «не удалось»
        self.update_finished.emit(buffer.getvalue(), bool(ok), silent)

    def _on_update_progress(self, text: str):
        if not self._update_silent:
            self.statusBar().showMessage(text)

    def _on_update_fraction(self, value: float):
        self._db_fraction = value
        self.dashboard.set_db_progress(value)

    def _on_update_finished(self, text: str, ok: bool, silent: bool):
        from analyzer.folderview import reset_bases
        from processmanager.memscan import reset_cache

        self._updating = False
        if ok:
            cfg.set_("db/last_update", time.time())
        reset_cache()  # правила для памяти и файлов перекомпилируются при следующей проверке
        reset_bases()
        scan_pool.reset()  # рабочие процессы проверки перезапустятся с новыми правилами
        for monitor in (self.monitor, self.net_monitor):
            if monitor is not None:
                monitor.reload_bases()
        self._db_stats = None
        self.refresh_dashboard()
        activity.record("update", "Базы обновлены" if ok else "Обновление баз не удалось")
        failed = [line.strip()[:220] for line in text.splitlines() if line.strip()]
        features.end_if_active("db.update", ok, error="" if ok else " | ".join(failed[-3:]))
        if ok:
            self.add_event("Базы сигнатур обновлены")
            self._update_retries = 0
        else:
            # частый случай — сеть перестраивается: обновление при запуске совпало с
            # подключением VPN (sing-box, WSAEACCES 10013 в журнале 11.11.2026); повтор через
            # 3 минуты, трижды, дальше — обычная проверка раз в полчаса
            self._update_retries = getattr(self, "_update_retries", 0) + 1
            if self._update_retries <= 3:
                QTimer.singleShot(3 * 60 * 1000, self.auto_update_check)
        if silent:  # автообновление: сообщение об успехе не показывается
            if not ok:
                self.statusBar().showMessage(
                    "Не удалось обновить базы: нет сети. Повторю позже", 8000)
            return
        self.statusBar().showMessage("Обновление баз завершено", 8000)
        QMessageBox.information(self, "Обновление баз", text.strip() or "Готово")
