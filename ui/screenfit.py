"""Окна программы на экране меньше Full HD (15.11.2026, ноутбук 1366×768).

Окна и их кнопки рассчитаны на 1920×1080 (VPN — не меньше 1200×760, диспетчер процессов —
1860×720), и на 1366×768 часть окон выходила за край экрана. Два шага:

1. apply_scale() — ДО создания QApplication: экран меньше REFERENCE (в логических точках,
   то есть с учётом масштаба Windows 125%/150%) → переменная QT_SCALE_FACTOR =
   min(ширина/1920, высота/1080), не меньше MIN_FACTOR. Qt уменьшает всё вместе: окна,
   шрифты, кнопки, отступы, значки. 1366×768 → 0,8. Если QT_SCALE_FACTOR уже задан
   пользователем — не трогаем; STRETCHBIT_UI_SCALE=1 (или другое число) задаёт свой.
2. install(app) — фильтр событий: окно при показе не больше рабочей области своего экрана
   (без панели задач): уменьшаются размер, минимальный и фиксированный размер, окно
   сдвигается внутрь экрана. Подстраховка для окон, которые и после шага 1 крупнее экрана.
"""
import os
import sys

from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QWidget

REFERENCE = (1920, 1080)
MIN_FACTOR = 0.8          # мельче шрифт уже трудно читать
ENV_SCALE = "STRETCHBIT_UI_SCALE"
FRAME_W, FRAME_H = 16, 48  # рамка и заголовок окна Windows (снаружи размера окна Qt)
QT_MAX = 16777215          # QWIDGETSIZE_MAX: размер не ограничен


def scale_factor(width: float, height: float) -> float:
    """Множитель для экрана width×height логических точек (1.0 — не уменьшать)."""
    if width <= 0 or height <= 0:
        return 1.0
    factor = min(width / REFERENCE[0], height / REFERENCE[1], 1.0)
    return round(max(MIN_FACTOR, factor), 2)


def screen_size() -> tuple[float, float]:
    """Основной экран в логических точках (физические / масштаб Windows). До QApplication:
    у процесса без поддержки DPI GetSystemMetrics уже отдаёт логические точки, а
    GetDpiForSystem — 96; у поддерживающего — физические и настоящий DPI. Формула одна."""
    if sys.platform != "win32":
        return 0.0, 0.0
    import ctypes
    user32 = ctypes.windll.user32
    width, height = user32.GetSystemMetrics(0), user32.GetSystemMetrics(1)
    try:
        dpi = user32.GetDpiForSystem() or 96
    except AttributeError:  # Windows до 10 1607
        dpi = 96
    return width * 96 / dpi, height * 96 / dpi


def apply_scale() -> float:
    """Задать QT_SCALE_FACTOR (вызывать до QApplication). Возвращает множитель."""
    own = os.environ.get(ENV_SCALE, "").strip().replace(",", ".")
    if own:
        try:
            factor = min(2.0, max(0.5, float(own)))
        except ValueError:
            factor = 1.0
    elif os.environ.get("QT_SCALE_FACTOR"):
        return 1.0  # задан пользователем — его выбор
    else:
        factor = scale_factor(*screen_size())
    if factor != 1.0:
        os.environ["QT_SCALE_FACTOR"] = f"{factor:g}"
    return factor


def fit_window(widget: QWidget) -> bool:
    """Окно не больше рабочей области экрана и целиком на нём. True — что-то изменено."""
    screen = widget.screen() or QGuiApplication.primaryScreen()
    if screen is None:
        return False
    area = screen.availableGeometry()
    max_w, max_h = area.width() - FRAME_W, area.height() - FRAME_H
    if max_w <= 200 or max_h <= 150:
        return False
    changed = False
    if widget.minimumWidth() > max_w or widget.minimumHeight() > max_h:
        widget.setMinimumSize(min(widget.minimumWidth(), max_w),
                              min(widget.minimumHeight(), max_h))
        changed = True
    # фиксированный размер (окна инструментов: fit_height) — тоже не больше экрана
    if max_w < widget.maximumWidth() < QT_MAX:
        widget.setMaximumWidth(max_w)
        changed = True
    if max_h < widget.maximumHeight() < QT_MAX:
        widget.setMaximumHeight(max_h)
        changed = True
    if widget.width() > max_w or widget.height() > max_h:
        widget.resize(min(widget.width(), max_w), min(widget.height(), max_h))
        changed = True
    if widget.isMaximized() or widget.isFullScreen():
        return changed
    frame = widget.frameGeometry()
    x = min(max(frame.x(), area.left()), area.right() - widget.width() - FRAME_W + 1)
    y = min(max(frame.y(), area.top()), area.bottom() - widget.height() - FRAME_H + 1)
    if (x, y) != (frame.x(), frame.y()):
        widget.move(max(x, area.left()), max(y, area.top()))
        changed = True
    return changed


def _on_show(widget) -> None:
    """Каждое окно (не меню и не подсказка) при показе подгоняется под экран."""
    try:
        fit_window(widget)
    except RuntimeError:  # окно удаляется
        pass


def install(app) -> None:
    from ui import apphooks  # общий фильтр приложения (ui/apphooks.py)
    apphooks.on_show(_on_show)
