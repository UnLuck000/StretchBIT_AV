"""Диспетчер режимов до создания GUI, настроек и пользовательской конфигурации."""
import sys


def dispatch(argv: list[str]) -> int | None:
    """Код завершения для служебного режима; None — продолжить пользовательский GUI."""
    if "--archive-host" in argv:
        from archive_runtime import main
        return main(argv)
    if "--archive-finalize" in argv:
        from archive_setup import elevated_main
        return elevated_main() if argv[1:] == ["--archive-finalize"] else 2
    if "--archive-setup" in argv:
        return 5  # Старый запуск helper из доступного на запись архива запрещён.
    if "--archive-resume" in argv:
        from archive_setup import resume
        code = resume(argv)
        if code is not None:
            return code
    if "--machine-tool" in argv:
        from launcher import machine_tool
        return machine_tool(argv)
    if "--scan-worker" in argv:
        from scanner.worker import main
        main()
        return 0
    if "--crash-report" in argv:
        from ui.crash_report import main
        return main()
    if "--watchdog" in argv:
        import selfguard
        try:
            selfguard.watch(int(argv[argv.index("--watchdog") + 1]),
                            restart=selfguard.NO_RESTART_ARG not in argv,
                            recover=selfguard.NO_RECOVERY_ARG not in argv)
        except (ValueError, IndexError):
            pass
        return 0
    if "--session-start" in argv:
        from service import editions
        if editions.passive():
            return 0
        from ui import settings as cfg
        argv.remove("--session-start")
        argv.append("--autostart" if cfg.autostart_gui_enabled() else "--recover-network")
    if "--recover-network" in argv:
        import selfguard
        try:
            report = selfguard.recover_network()
            if report:
                selfguard._note(f"автозапуск: сеть после VPN: {'; '.join(report)}")
        except Exception as e:  # noqa: BLE001 — восстановление не должно мешать входу
            selfguard._note(f"автозапуск: возврат сети не удался: {e}")
        return 0
    if "--accept-installed-legal" in argv:
        from diag import consent
        try:
            revision = argv[argv.index("--accept-installed-legal") + 1]
            return 0 if consent.accept_from_installer(revision) else 1
        except (IndexError, OSError):
            return 1
    if "--set-autostart" in argv:
        import userdata
        from ui import settings as cfg
        try:
            on = argv[argv.index("--set-autostart") + 1] == "on"
            userdata.protect_config()
            cfg.set_("startup/autostart", on)
            cfg.set_autostart(True)
            return 0
        except IndexError:
            return 2
        except OSError:
            return 1
    if any(arg.startswith("--service") for arg in argv[1:]):
        if sys.stdout is None or sys.stderr is None:
            import datadirs
            datadirs.LOGS.mkdir(parents=True, exist_ok=True)
            stream = open(datadirs.LOGS / "service-stdout.log", "a", encoding="utf-8", buffering=1)
            sys.stdout = sys.stdout or stream
            sys.stderr = sys.stderr or stream
        from service.main import entry
        return entry(argv[1:])
    if not any(arg in argv for arg in ("--tool", "--undo", "--uninstall")):
        from archive_setup import ensure
        return ensure(argv)
    return None
