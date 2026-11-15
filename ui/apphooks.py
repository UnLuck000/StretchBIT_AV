"""Один фильтр событий на всё приложение вместо нескольких (15.11.2026).

Фильтр приложения получает КАЖДОЕ событие Qt (перерисовки, движения мыши, таймеры), и у
каждого фильтра на Python `event.type()` превращался в перечисление Python (enum.__call__ —
код на Python). Фильтров было четыре: журнал действий (diag/uiaudit), заголовок окна под
тему (ui/theme), подгонка окна под экран (ui/screenfit), панель тестирования
(diag/testpanel) — на Celeron смена темы шла 6,4 с, окна с таблицами дёргались. Теперь тип
события определяется один раз:
• on_show(callback) — callback(widget) при показе окна верхнего уровня (не меню и не
  подсказки);
• on_event(callback) — callback(watched, event, kind) для всех событий (журнал действий).
"""
from PySide6.QtCore import QEvent, QObject, Qt
from PySide6.QtWidgets import QApplication, QWidget

SHOW = QEvent.Type.Show
WINDOW_TYPES = (Qt.WindowType.Window, Qt.WindowType.Dialog)


class _Hooks(QObject):
    def __init__(self, app):
        super().__init__(app)
        self.show: list = []
        self.any: list = []

    def eventFilter(self, watched, event):
        try:
            kind = event.type()
            for callback in self.any:
                callback(watched, event, kind)
            if kind == SHOW and self.show and isinstance(watched, QWidget) \
                    and watched.isWindow() and watched.windowType() in WINDOW_TYPES:
                for callback in self.show:
                    callback(watched)
        except Exception:  # noqa: S110 — служебные обработчики не должны ломать события окон
            pass
        return False


_hooks: _Hooks | None = None


def _install() -> _Hooks:
    global _hooks
    if _hooks is None:
        app = QApplication.instance()
        _hooks = _Hooks(app)
        app.installEventFilter(_hooks)
    return _hooks


def on_show(callback) -> None:
    hooks = _install()
    if callback not in hooks.show:
        hooks.show.append(callback)


def on_event(callback) -> None:
    hooks = _install()
    if callback not in hooks.any:
        hooks.any.append(callback)
