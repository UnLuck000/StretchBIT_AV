"""Вкладки редактора профиля маршрутизации (vpn/routingwindow.RoutingEditor), 15.11.2026.

«Домены и геометки» (DomainsTab): сверху — outbound по умолчанию (куда идёт всё, что не попало
в правила: «Туннель» или «Напрямую»), ниже в ряд — столбцы «Напрямую», «Туннель»,
«Блокировать», «Обход WARP» (RuleColumn). В столбце свои строки (правятся) и под ними
полупрозрачные встроенные — то, что включено на «Основном» (российские сайты, QUIC, реклама,
WARP): свои строки главнее, и встроенные просто сдвигаются ниже, когда пишешь своё.

«Дополнительно» (AdvancedTab): слева список правил с галочками (включено) и кнопками, справа —
выбранное правило: название, действие, условия (каждое — строкой: «Домены», «Адреса», «Порт»...
с крестиком; «+ Условие» добавляет недостающее), предупреждения и предпросмотр — правило
так, как его получит Xray. Правка — сразу в профиль окна (сохраняет «Сохранить» редактора).
"""
import json

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QFormLayout, QFrame, QHBoxLayout, QLabel, QLineEdit, QListWidget,
    QListWidgetItem, QPlainTextEdit, QPushButton, QScrollArea, QSplitter, QToolButton,
    QVBoxLayout, QWidget,
)

from vpn import routing

SYNTAX = ("По одному на строку. Домен: example.com (с поддоменами), full:example.com (точно), "
          "keyword:слово, regexp:выражение, geosite:категория, ext:файл.dat:метка. Адрес: "
          "1.2.3.4, 10.0.0.0/8, geoip:страна. # — комментарий.")
COLUMN_HINTS = {
    "rules_direct": "Мимо VPN.",
    "rules_proxy": "Через VPN.",
    "rules_block": "Соединение отклоняется. Главнее остальных столбцов.",
    "rules_nowarp": "Через VPN, но мимо WARP (при цепочке «VPN → WARP»).",
}


def _hint(text: str) -> QLabel:
    label = QLabel(text)
    label.setWordWrap(True)
    # placeholder-text, а не mid: mid — цвет теней рамок, в тёмных темах он почти
    # сливается с фоном (текст подсказок был не виден), в светлой — почти белый
    label.setStyleSheet("color: palette(placeholder-text);")
    return label


def _faded(widget: QWidget, alpha: int = 120) -> str:
    """Цвет текста темы, полупрозрачный — для встроенных строк."""
    color = QColor(widget.palette().color(QPalette.ColorRole.Text))
    return f"rgba({color.red()}, {color.green()}, {color.blue()}, {alpha})"


# ---------------- «Домены и геометки» ----------------
class _GrowingEdit(QPlainTextEdit):
    """Поле своих строк: высота — по числу строк (встроенные под ним сдвигаются)."""

    def __init__(self):
        super().__init__()
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self.setPlaceholderText("свои строки...")
        self.document().documentLayout().documentSizeChanged.connect(lambda _s: self._fit())
        self._fit()

    def _fit(self) -> None:
        lines = max(1, int(self.document().size().height()))
        margins = self.contentsMargins()
        self.setFixedHeight(lines * self.fontMetrics().lineSpacing() + 2 * int(
            self.document().documentMargin()) + margins.top() + margins.bottom() + 4)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._fit()  # ширина поменялась — перенос строк тоже


class _ColumnBody(QWidget):
    """Поле столбца: щелчок по пустому месту под строками ставит курсор в конец своих."""

    edit = None

    def mousePressEvent(self, event):
        if self.edit is not None:
            self.edit.setFocus()
            self.edit.moveCursor(self.edit.textCursor().MoveOperation.End)
        super().mousePressEvent(event)


class RuleColumn(QFrame):
    """Столбец «Напрямую» / «Туннель» / ...: свои строки и под ними встроенные (серым)."""

    changed = Signal()

    def __init__(self, key: str, title: str):
        super().__init__()
        self.key = key
        self.setObjectName("ruleColumn")
        self.setFrameShape(QFrame.Shape.StyledPanel)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(4)
        head = QLabel(title)
        head.setStyleSheet("font-weight: 600;")
        layout.addWidget(head)
        hint = _hint(COLUMN_HINTS.get(key, ""))
        hint.setMinimumHeight(2 * hint.fontMetrics().lineSpacing() + 4)  # столбцы — вровень
        hint.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(hint)
        body = _ColumnBody()
        body.setObjectName("ruleColumnBody")
        body.setStyleSheet("#ruleColumnBody { background: palette(base); }")
        bl = QVBoxLayout(body)
        bl.setContentsMargins(0, 0, 0, 0)
        bl.setSpacing(0)
        self.edit = _GrowingEdit()
        self.edit.setStyleSheet("QPlainTextEdit { background: palette(base); }")
        self.edit.textChanged.connect(self.changed.emit)
        body.edit = self.edit
        bl.addWidget(self.edit)
        self.builtin = QLabel()
        self.builtin.setWordWrap(True)
        self.builtin.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.builtin.setContentsMargins(6, 2, 6, 6)
        self.builtin.setToolTip("Встроенные правила — включаются и выключаются на вкладке "
                                "«Основное»; свои строки выше главнее их")
        self.builtin.setStyleSheet(f"color: {_faded(self)}; background: palette(base);")
        bl.addWidget(self.builtin)
        bl.addStretch()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(body)
        layout.addWidget(scroll, 1)

    def lines(self) -> list[str]:
        return [s for s in self.edit.toPlainText().splitlines() if s.strip()]

    def set_lines(self, lines: list[str]) -> None:
        self.edit.setPlainText("\n".join(lines))

    def set_builtin(self, lines: list[str]) -> None:
        self.builtin.setText("\n".join(lines))
        self.builtin.setVisible(bool(lines))


class DomainsTab(QWidget):
    """Вкладка «Домены и геометки»: outbound по умолчанию и четыре столбца правил."""

    changed = Signal()

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        row = QHBoxLayout()
        row.addWidget(QLabel("Outbound по умолчанию:"))
        self.default = QComboBox()
        for key, text in routing.DEFAULT_OUTBOUNDS.items():
            self.default.addItem(text, key)
        self.default.setToolTip("Куда идёт всё, что не попало ни в одно правило")
        self.default.currentIndexChanged.connect(lambda _i: self.changed.emit())
        row.addWidget(self.default)
        row.addStretch()
        layout.addLayout(row)
        layout.addWidget(_hint(SYNTAX + " Полупрозрачные строки — встроенные правила "
                                        "(«Основное»); свои строки главнее."))
        columns = QHBoxLayout()
        self.columns: dict[str, RuleColumn] = {}
        for key, title in routing.RULE_LISTS.items():
            column = RuleColumn(key, title)
            column.changed.connect(self.changed.emit)
            columns.addWidget(column, 1)
            self.columns[key] = column
        layout.addLayout(columns, 1)

    def load(self, p: routing.RoutingProfile) -> None:
        self.default.blockSignals(True)
        self.default.setCurrentIndex(max(0, self.default.findData(p.default_outbound)))
        self.default.blockSignals(False)
        for key, column in self.columns.items():
            column.set_lines(getattr(p, key))

    def collect(self, p: routing.RoutingProfile) -> None:
        p.default_outbound = self.default.currentData() or "proxy"
        for key, column in self.columns.items():
            setattr(p, key, column.lines())

    def set_builtin(self, lines: dict[str, list[str]]) -> None:
        for key, column in self.columns.items():
            column.set_builtin(lines.get(key, []))


# ---------------- «Дополнительно» ----------------
# условия из Throne (sing-box) с маппингом в Xray: (ключ в правиле, название, вид, подсказка)
# названия — как в Throne; ключи ip/source — старые (ip_cidr/source_ip_cidr в Xray собираются
# в ip/source, domain_suffix/keyword/regex — в домен с префиксом), ip_version → ip ::/0 или
# 0.0.0.0/0, *_is_private → geoip:private (у источника — частные сети CIDR).
ATTRS = (
    ("ip_version", "ip_version", "choice", "только IPv4 или только IPv6"),
    ("network", "network", "network", ""),
    ("protocol", "protocol", "protocol", ""),
    ("inbound", "inbound", "inbound", ""),
    ("outbound", "outbound", "outbound", ""),
    ("domain", "domain", "text", "example.com (домен и поддомены)\nfull:example.com (точно)\n"
                                "keyword:слово\nregexp:\\.ru$\ngeosite:youtube\n"
                                "ext:файл.dat:метка"),
    ("domain_suffix", "domain_suffix", "text", "example.com — домен и все поддомены"),
    ("domain_keyword", "domain_keyword", "text", "подстрока в домене"),
    ("domain_regex", "domain_regex", "text", "регулярное выражение"),
    ("ip", "ip_cidr", "text", "1.2.3.4\n10.0.0.0/8\ngeoip:ru\next:файл.dat:метка"),
    ("ip_is_private", "ip_is_private", "bool", ""),
    ("source", "source_ip_cidr", "text", "192.168.1.10\n192.168.1.0/24"),
    ("source_ip_is_private", "source_ip_is_private", "bool", ""),
    ("port", "port", "line", "443 или 1000-2000,8080"),
    ("source_port", "source_port", "line", "например 50000-60000"),
)
MATCH_KEYS = tuple(k for k, *_ in ATTRS if k != "outbound")  # условия совпадения трафика
ATTR_TOOLTIPS = {                                            # для условий без плейсхолдера
    "ip_version": "Только IPv4 или только IPv6 (в Xray — ip ::/0 и 0.0.0.0/0)",
    "network": "TCP, UDP или обе",
    "protocol": "Протокол: http, tls, quic, bittorrent",
    "inbound": "Входящее, к которому пришёл трафик (TUN, прокси...)",
    "outbound": "Цель правила: proxy (туннель), direct, block, vpn (мимо WARP)",
    "ip_is_private": "Адрес назначения — частный (локальный) IP",
    "source_ip_is_private": "Адрес источника — частный (локальный) IP",
}
# параметры действия sing-box (route-options и reject) — НЕ условия: они меняют, КАК
# трафик передаётся дальше. Работают ТОЛЬКО в режиме TUN: там sing-box стоит перед Xray;
# при системном прокси трафик идёт сразу в Xray, sing-box не участвует. В Xray аналогов
# нет — на правило Xray они не влияют. method/no_drop — параметры действия reject
# (блокировка), применяются только при outbound = block. Не вошли (нет в sing-box 1.14):
# override_destination (поле удалено) и strategy (поле действия resolve, а в нашей цепочке
# домены разрешает Xray).
SBOX_ATTRS = (
    ("override_address", "override_address", "line",
     "IP или домен — подмена адреса назначения до передачи в Xray"),
    ("override_port", "override_port", "line", "число 1–65535"),
    ("tls_fragment", "tls_fragment", "bool", ""),
    ("tls_fragment_fallback_delay", "tls_fragment_fallback_delay", "line",
     "например «500ms» — задержка, когда авто-определение не сработало"),
    ("tls_record_fragment", "tls_record_fragment", "bool", ""),
    ("tls_spoof", "tls_spoof", "line", "домен — подменный SNI перед настоящим ClientHello"),
    ("tls_spoof_method", "tls_spoof_method", "choice", ""),
    ("method", "method", "choice", ""),          # method действия reject (outbound = block)
    ("no_drop", "no_drop", "bool", ""),
)
ALL_ATTRS = (*ATTRS, *SBOX_ATTRS)
ATTR_KINDS = {key: kind for key, _t, kind, _p in ALL_ATTRS}
# варианты для полей-выборов: ключ → пары (значение, подпись)
CHOICES = {
    "ip_version": (("4", "4"), ("6", "6")),
    "tls_spoof_method": tuple((m, m) for m in routing.SPOOF_METHODS),
    "method": (("default", "default (RST / ICMP)"), ("drop", "drop (молча)")),
}
ATTR_TOOLTIPS.update({
    "tls_fragment": "Разбивать TLS ClientHello на части — против простой фильтрации "
                    "по содержимому пакетов",
    "tls_record_fragment": "Разбивать рукопожатие TLS на несколько TLS-записей",
    "tls_spoof": "Подделанный ClientHello с этим SNI перед настоящим (нужны права "
                 "администратора — служба работает с ними)",
    "tls_spoof_method": "Как подделанный сегмент будет отброшен реальным сервером",
    "method": "Как отклонять соединения (при блокировке): default — RST/ICMP, "
              "drop — молча терять",
    "no_drop": "Не переключать отклонение на «молча» при частых срабатываниях "
               "(50 за 30 секунд)",
    "override_address": "Подмена адреса назначения до передачи в Xray: правила Xray "
                        "сработают уже на новый адрес",
    "override_port": "Подмена порта назначения до передачи в Xray",
    "tls_fragment_fallback_delay": "Задержка ожидания для фрагментации, когда "
                                   "авто-определение не сработало (по умолчанию 500ms)",
})


class ConditionRow(QFrame):
    """Одно условие правила: название, поле и крестик."""

    changed = Signal()
    removed = Signal(str)

    def __init__(self, key: str, value):
        super().__init__()
        self.key = key
        _key, title, kind, placeholder = next(a for a in ALL_ATTRS if a[0] == key)
        self.kind = kind
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        label = QLabel(title + ":")  # название условия — как в Throne
        label.setMinimumWidth(150)
        label.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(label)
        if kind == "text":
            self.field = QPlainTextEdit("\n".join(value or []))
            self.field.setPlaceholderText(placeholder)
            self.field.setMaximumHeight(96)
            self.field.textChanged.connect(self.changed.emit)
        elif kind == "line":
            self.field = QLineEdit(str(value or ""))
            self.field.setPlaceholderText(placeholder)
            self.field.textChanged.connect(lambda _t: self.changed.emit())
        elif kind == "choice":
            # ip_version: 4 или 6 (как в Throne); у параметров sing-box — свои списки
            self.field = QComboBox()
            for opt, text in CHOICES[key]:
                self.field.addItem(text, opt)
            self.field.setCurrentIndex(max(0, self.field.findData(
                value if value in [o for o, _t in CHOICES[key]] else CHOICES[key][0][0])))
            self.field.currentIndexChanged.connect(lambda _i: self.changed.emit())
        elif kind == "bool":
            self.field = QCheckBox()  # ip_is_private / source_ip_is_private
            self.field.setChecked(bool(value))
            self.field.toggled.connect(lambda _on: self.changed.emit())
        elif kind == "network":
            self.field = QComboBox()
            for net, text in routing.NETWORKS.items():
                if net:
                    self.field.addItem(text, net)
            self.field.setCurrentIndex(max(0, self.field.findData(value or "tcp")))
            self.field.currentIndexChanged.connect(lambda _i: self.changed.emit())
        elif kind == "outbound":
            # цель правила как условие: proxy/direct/block/vpn — как в JSON Xray
            self.field = QComboBox()
            for opt in routing.OUTBOUNDS:
                self.field.addItem(opt, opt)
            self.field.setCurrentIndex(max(0, self.field.findData(
                value if value in routing.OUTBOUNDS else "proxy")))
            self.field.currentIndexChanged.connect(lambda _i: self.changed.emit())
        else:
            self.field = QWidget()
            boxes = QHBoxLayout(self.field)
            boxes.setContentsMargins(0, 0, 0, 0)
            options = (routing.INBOUNDS.items() if kind == "inbound"
                       else ((p, p) for p in routing.PROTOCOLS))
            self.boxes = {}
            for opt, text in options:
                box = QCheckBox(text)
                box.setChecked(opt in (value or []))
                box.toggled.connect(lambda _on: self.changed.emit())
                boxes.addWidget(box)
                self.boxes[opt] = box
            boxes.addStretch()
        layout.addWidget(self.field, 1)
        close = QToolButton()
        close.setText("✕")
        close.setToolTip("Убрать условие")
        close.clicked.connect(lambda: self.removed.emit(self.key))
        layout.addWidget(close, 0, Qt.AlignmentFlag.AlignTop)

    def value(self):
        if self.kind == "text":
            return [s.strip() for s in self.field.toPlainText().splitlines() if s.strip()]
        if self.kind == "line":
            return self.field.text().strip()
        if self.kind in ("network", "outbound", "choice"):
            return self.field.currentData()
        if self.kind == "bool":
            return self.field.isChecked()
        return [k for k, box in self.boxes.items() if box.isChecked()]


class AdvancedTab(QWidget):
    """Вкладка «Дополнительно»: список правил и редактор выбранного."""

    changed = Signal()

    def __init__(self, warp_on=lambda: False):
        super().__init__()
        self.warp_on = warp_on
        self.rules: list[dict] = []
        self.rows: dict[str, ConditionRow] = {}
        self._loading = False
        layout = QVBoxLayout(self)
        layout.addWidget(_hint(
            "Правила с условиями: срабатывает, когда выполнены ВСЕ условия правила. Правила "
            "проверяются раньше столбцов «Домены и геометки», сверху вниз; первое подошедшее "
            "решает."))
        split = QSplitter()
        # слева — список
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        self.list = QListWidget()
        self.list.currentRowChanged.connect(self._select)
        self.list.itemChanged.connect(self._checked)
        ll.addWidget(self.list, 1)
        buttons = QHBoxLayout()
        for text, slot, tip in (("Создать", self._create, "Новое правило"),
                                ("Копия", self._copy, "Копия выбранного правила"),
                                ("↑", lambda: self._move(-1), "Выше (проверяется раньше)"),
                                ("↓", lambda: self._move(1), "Ниже"),
                                ("Удалить", self._delete, ""),
                                ("JSON...", self._json, "Все правила одним списком JSON")):
            button = QPushButton(text)
            button.setToolTip(tip)
            button.clicked.connect(slot)
            buttons.addWidget(button)
        ll.addLayout(buttons)
        # добавление условий — слева, как в Throne: список чекбоксов; отметка добавляет
        # условие в редактор справа, снятие — убирает (значение очищается)
        ll.addWidget(QLabel("Условия (отметь, чтобы добавить):"))
        self.attr_area = QScrollArea()
        self.attr_area.setWidgetResizable(True)
        self.attr_area.setFrameShape(QFrame.Shape.NoFrame)
        attrs_panel = QWidget()
        al = QVBoxLayout(attrs_panel)
        al.setContentsMargins(0, 0, 0, 0)
        al.setSpacing(2)
        self.attr_boxes: dict[str, QCheckBox] = {}
        for key, title, _kind, placeholder in ATTRS:
            box = QCheckBox(title)
            box.setToolTip(placeholder or ATTR_TOOLTIPS.get(key, ""))
            box.toggled.connect(lambda on, k=key: self._toggle_attr(k, on))
            al.addWidget(box)
            self.attr_boxes[key] = box
        # параметры действия sing-box: та же панель, отдельная группа; работают только в TUN
        note = QLabel("Параметры действия (sing-box, только TUN):")
        note.setToolTip("При системном прокси трафик идёт сразу в Xray — sing-box не "
                        "участвует, и эти параметры не действуют")
        al.addWidget(note)
        for key, title, _kind, placeholder in SBOX_ATTRS:
            box = QCheckBox(title)
            box.setToolTip(placeholder or ATTR_TOOLTIPS.get(key, ""))
            box.toggled.connect(lambda on, k=key: self._toggle_attr(k, on))
            al.addWidget(box)
            self.attr_boxes[key] = box
        al.addStretch()
        self.attr_area.setWidget(attrs_panel)
        ll.addWidget(self.attr_area, 1)
        split.addWidget(left)
        # справа — правило
        self.editor = QWidget()
        el = QVBoxLayout(self.editor)
        el.setContentsMargins(8, 0, 0, 0)
        form = QFormLayout()
        self.name = QLineEdit()
        self.name.setPlaceholderText("необязательно")
        self.name.textChanged.connect(lambda _t: self._edited())
        form.addRow("Название:", self.name)
        el.addLayout(form)
        head = QHBoxLayout()
        head.addWidget(QLabel("Условия (все должны выполняться):"))
        head.addStretch()
        el.addLayout(head)
        self.conditions = QVBoxLayout()
        self.conditions.setSpacing(6)
        el.addLayout(self.conditions)
        self.warning = QLabel()
        self.warning.setWordWrap(True)
        el.addWidget(self.warning)
        el.addWidget(QLabel("Предпросмотр — правило для Xray (режим TUN):"))
        self.preview = QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setStyleSheet("font-family: Consolas, monospace;")
        self.preview.setMinimumHeight(120)
        el.addWidget(self.preview, 1)
        split.addWidget(self.editor)
        split.setStretchFactor(1, 2)
        split.setSizes([300, 640])
        layout.addWidget(split, 1)
        self.editor.setEnabled(False)

    # --- список ---
    def load(self, rules: list[dict]) -> None:
        self.rules = [routing.normalize_rule(r) for r in rules]
        self._fill(0 if self.rules else -1)

    def collect(self) -> list[dict]:
        return [routing.normalize_rule(r) for r in self.rules]

    def _title(self, i: int) -> str:
        r = self.rules[i]
        name = r["name"] or f"Правило {i + 1}"
        return f"{name} → {r['outbound']}"

    def _fill(self, select: int) -> None:
        self.list.blockSignals(True)
        self.list.clear()
        for i, r in enumerate(self.rules):
            item = QListWidgetItem(self._title(i))
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked if r["enabled"] else Qt.CheckState.Unchecked)
            item.setToolTip(routing.rule_text(r))
            self.list.addItem(item)
        self.list.blockSignals(False)
        if 0 <= select < len(self.rules):
            self.list.setCurrentRow(select)
        else:
            self._select(-1)

    def _row(self) -> int:
        row = self.list.currentRow()
        return row if 0 <= row < len(self.rules) else -1

    def _checked(self, item: QListWidgetItem) -> None:
        row = self.list.row(item)
        if 0 <= row < len(self.rules):
            self.rules[row]["enabled"] = item.checkState() == Qt.CheckState.Checked
            self.changed.emit()

    def _create(self) -> None:
        self.rules.append(routing.normalize_rule({"outbound": "direct"}))
        self._fill(len(self.rules) - 1)
        self.changed.emit()
        self.name.setFocus()

    def _copy(self) -> None:
        row = self._row()
        if row < 0:
            return
        copy = dict(self.rules[row], name=(self.rules[row]["name"] or f"Правило {row + 1}")
                    + " (копия)")
        self.rules.insert(row + 1, routing.normalize_rule(copy))
        self._fill(row + 1)
        self.changed.emit()

    def _move(self, step: int) -> None:
        row = self._row()
        target = row + step
        if row < 0 or not 0 <= target < len(self.rules):
            return
        self.rules[row], self.rules[target] = self.rules[target], self.rules[row]
        self._fill(target)
        self.changed.emit()

    def _delete(self) -> None:
        row = self._row()
        if row < 0:
            return
        del self.rules[row]
        self._fill(min(row, len(self.rules) - 1))
        self.changed.emit()

    def _json(self) -> None:
        from PySide6.QtWidgets import QDialog

        from vpn.routingwindow import JsonRulesDialog
        dialog = JsonRulesDialog(self.window(), self.collect())
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.rules = dialog.result
            self._fill(0 if self.rules else -1)
            self.changed.emit()

    # --- правило ---
    def _select(self, row: int) -> None:
        self._loading = True
        try:
            for key in list(self.rows):
                self._drop_row(key)
            self.editor.setEnabled(row >= 0 and row < len(self.rules))
            if not self.editor.isEnabled():
                self.name.clear()
                self.preview.clear()
                self.warning.clear()
                return
            r = self.rules[row]
            self.name.setText(r["name"])
            for key, _title, _kind, _ph in ATTRS:
                # outbound — цель правила, есть всегда; остальные — по наличию значения
                if key == "outbound" or r.get(key):
                    self._add_row(key, r[key])
            for key, _title, _kind, _ph in SBOX_ATTRS:
                if r.get(key):                       # параметры действия — как есть
                    self._add_row(key, r[key])
        finally:
            self._loading = False
        # чекбоксы слева отражают набор условий выбранного правила
        for key, box in self.attr_boxes.items():
            box.blockSignals(True)
            box.setChecked(key in self.rows)
            box.setEnabled(self._row() >= 0)
            box.blockSignals(False)
        self._show_state()

    def _toggle_attr(self, key: str, on: bool) -> None:
        row = self._row()
        if row < 0 or self._loading:
            return
        if on and key not in self.rows:
            if key == "outbound":            # outbound сразу показывает цель правила
                value = self.rules[row]["outbound"]
            elif key in CHOICES:             # выбор — первое значение списка
                value = CHOICES[key][0][0]
            elif ATTR_KINDS[key] == "bool":
                value = True
            else:
                value = ""
            self._add_row(key, value)
            self.rows[key].field.setFocus()
        elif not on:
            self._drop_row(key)   # снятие отметки — условие убрано, значение очистится
        self._edited()

    def _add_row(self, key: str, value) -> None:
        row = ConditionRow(key, value)
        row.changed.connect(self._edited)
        row.removed.connect(self._remove_condition)
        self.rows[key] = row
        self.conditions.addWidget(row)

    def _drop_row(self, key: str) -> None:
        row = self.rows.pop(key, None)
        if row is not None:
            self.conditions.removeWidget(row)
            row.hide()  # сразу: до отложенного удаления строка рисовалась поверх новой
            row.setParent(None)
            row.deleteLater()

    def _remove_condition(self, key: str) -> None:
        self._drop_row(key)
        box = self.attr_boxes.get(key)
        if box is not None:           # чекбокс слева снимается вместе с чипсом
            box.blockSignals(True)
            box.setChecked(False)
            box.blockSignals(False)
        self._edited()

    def _edited(self) -> None:
        row = self._row()
        if self._loading or row < 0:
            return
        values = {"name": self.name.text(), "enabled": self.rules[row]["enabled"]}
        for key, condition in self.rows.items():
            values[key] = condition.value()
        # нет outbound среди строк (чипс снят) — normalize_rule вернёт «proxy»
        self.rules[row] = routing.normalize_rule(values)
        item = self.list.item(row)
        if item is not None:
            item.setText(self._title(row))
            item.setToolTip(routing.rule_text(self.rules[row]))
        self._show_state()
        self.changed.emit()

    def _show_state(self) -> None:
        row = self._row()
        if row < 0:
            return
        r = self.rules[row]
        problems = routing.rule_problems(r)
        conditions = [k for k in MATCH_KEYS if r.get(k)]
        notes = []
        if problems:
            notes.append("<span style='color:#c0392b'>" + "<br>".join(problems) + "</span>")
        if not conditions:
            notes.append("<span style='color:#d68910'>Условий нет — правило сработает для "
                         "всего трафика. Отметь условие слева.</span>")
        if r["outbound"] == "vpn" and not self.warp_on():
            notes.append("<span style='color:#d68910'>WARP в профиле выключен: «Обход WARP» "
                         "работает как «Туннель».</span>")
        if r.get("source") or r.get("source_port"):
            notes.append("<span style='color:#d68910'>Адрес и порт источника в режиме TUN не "
                         "работают: весь трафик приходит в Xray с 127.0.0.1.</span>")
        if any(r.get(k) for k in routing.SBOX_OPTIONS) or r.get("method") or r.get("no_drop"):
            notes.append("<span style='color:#d68910'>Параметры действия sing-box работают "
                         "только в режиме TUN: системный прокси идёт сразу в Xray, sing-box "
                         "не участвует.</span>")
        self.warning.setText("<br>".join(notes))
        self.warning.setVisible(bool(notes))
        from vpn import xray, singbox
        converted = xray.advanced_rule(dict(r, enabled=True), "tun")
        text = ("Входящего этого правила нет в режиме TUN — в нём правило не действует."
                if converted is None else
                json.dumps(converted, ensure_ascii=False, indent=2))
        sb_rule = singbox.sbox_rule(r)
        if sb_rule is not None:
            text += ("\n\n— правило для sing-box (TUN; параметры действия применяются до "
                     "передачи в Xray):\n"
                     + json.dumps(sb_rule, ensure_ascii=False, indent=2))
        self.preview.setPlainText(text)
