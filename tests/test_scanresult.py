"""Итоги быстрой и полной проверки (ui/scanresult.py) и окна на маленьком экране
(ui/screenfit.py)."""
import pytest
from PySide6.QtWidgets import QApplication, QDialog

from scanner import fullscan
from ui import scanresult, screenfit


@pytest.fixture
def qapp():
    return QApplication.instance() or QApplication([])


def _stats(**kw) -> fullscan.Stats:
    stats = fullscan.Stats(started=1000.0, finished=1190.0)
    for key, value in kw.items():
        setattr(stats, key, value)
    return stats


def test_summary_lines_by_stage():
    quick = _stats(stages=[fullscan.STAGE_AUTORUNS, fullscan.STAGE_FILES], autoruns=140,
                   checked=5321, skipped=10, skipped_bytes=2048, roots=[r"C:\Windows"])
    lines = scanresult.summary_lines("quick", quick)
    assert lines[0] == "Автозапуск: записей — 140"
    assert lines[1].startswith("Файлы: проверено — 5 321")
    assert lines[2] == r"Папки: C:\Windows"
    full = _stats(stages=[fullscan.STAGE_USB, fullscan.STAGE_DRIVERS, fullscan.STAGE_BCD],
                  usb=0, drivers=412, stage_errors=["Политики и блокировки: нет доступа"])
    lines = scanresult.summary_lines("full", full)
    assert "съёмных нет" in lines[0] and "412" in lines[1]
    assert lines[-1] == "Не выполнено — Политики и блокировки: нет доступа"


def test_verdict_and_duration():
    assert scanresult.verdict(_stats())[1] == "Угроз не найдено"
    assert scanresult.verdict(_stats(suspicious=2))[1] == "Угроз нет, подозрительного: 2"
    assert scanresult.verdict(_stats(threats=1, suspicious=3))[1] == \
        "Найдено угроз: 1, подозрительного: 3"
    assert scanresult.duration(190) == "3 мин 10 с"


def test_windows_are_separate_for_quick_and_full(qapp):
    findings = [{"path": "", "level": "suspicious", "text": "драйвер x.sys", "stage": "Драйверы"},
                {"path": "", "level": "threat", "text": "BCD: testsigning", "stage": "Загрузка"}]
    quick = scanresult.show("quick", _stats(stages=[fullscan.STAGE_AUTORUNS]), [], False)
    full = scanresult.show("full", _stats(threats=1, suspicious=1), findings, True)
    try:
        assert quick.windowTitle() == "Итоги быстрой проверки"
        assert full.windowTitle() == "Итоги полной проверки"
        assert quick.isVisible() and full.isVisible()
        assert full.table.rowCount() == 2 and full.table.item(0, 0).text() == "Угроза"
        assert "остановлена" in full.banner.text()
        assert quick.table.isHidden() and not full.quarantine_btn.isVisibleTo(full)
        again = scanresult.show("full", _stats(), [], False)   # заменяет своё окно
        assert scanresult._open["full"] is again and scanresult._open["quick"] is quick
        again.close()
    finally:
        for window in list(scanresult._open.values()):
            window.close()
        qapp.processEvents()


def test_scale_factor():
    assert screenfit.scale_factor(1920, 1080) == 1.0
    assert screenfit.scale_factor(2560, 1440) == 1.0
    assert screenfit.scale_factor(1366, 768) == 0.8          # не мельче MIN_FACTOR
    assert screenfit.scale_factor(1600, 900) == 0.83
    assert screenfit.scale_factor(1536, 864) == 0.8          # Full HD при масштабе 125%
    assert screenfit.scale_factor(0, 0) == 1.0


def test_apply_scale_respects_user(monkeypatch):
    monkeypatch.setattr(screenfit, "screen_size", lambda: (1366, 768))
    monkeypatch.delenv(screenfit.ENV_SCALE, raising=False)
    monkeypatch.delenv("QT_SCALE_FACTOR", raising=False)
    assert screenfit.apply_scale() == 0.8
    import os
    assert os.environ["QT_SCALE_FACTOR"] == "0.8"
    monkeypatch.setenv("QT_SCALE_FACTOR", "1.5")                # задан пользователем
    assert screenfit.apply_scale() == 1.0 and os.environ["QT_SCALE_FACTOR"] == "1.5"
    monkeypatch.setenv(screenfit.ENV_SCALE, "1")                # свой множитель программы
    assert screenfit.apply_scale() == 1.0


def test_fit_window_not_bigger_than_screen(qapp):
    dialog = QDialog()
    dialog.setMinimumSize(6000, 4000)
    dialog.resize(6000, 4000)
    area = (dialog.screen() or QApplication.primaryScreen()).availableGeometry()
    assert screenfit.fit_window(dialog)
    assert dialog.width() <= area.width() - screenfit.FRAME_W
    assert dialog.height() <= area.height() - screenfit.FRAME_H
    fixed = QDialog()
    fixed.setFixedSize(300, 5000)                                # как fit_height
    screenfit.fit_window(fixed)
    assert fixed.maximumHeight() <= area.height() and fixed.width() == 300
    small = QDialog()
    small.resize(400, 300)
    small.move(area.left() + 10, area.top() + 10)
    assert not screenfit.fit_window(small)                       # и так помещается
