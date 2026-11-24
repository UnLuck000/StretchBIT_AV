"""HTTP(S) к публичным адресам: IP проверяется при соединении, без второго DNS-запроса.

Прокси окружения выключены: иначе проверялся бы адрес прокси, а не назначения.
Используется только загрузкой по ссылке и подписками, не ядрами VPN.
"""
import http.client
import ipaddress
import socket
import urllib.parse
import urllib.request


def public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        return ip.is_global and not (ip.is_multicast or ip.is_reserved)
    except ValueError:
        return False


def blocked_url(url: str, https_only: bool = False) -> str:
    try:
        parts = urllib.parse.urlsplit(url)
        host = (parts.hostname or "").lower().rstrip(".")
        if parts.scheme.lower() not in (("https",) if https_only else ("http", "https")):
            return "недопустимая схема"
        if not host or parts.username is not None or "\\" in parts.netloc or "%" in host:
            return "недопустимое имя сервера"
        if host == "localhost" or host.endswith((".local", ".localhost")):
            return "локальный адрес"
        _ = parts.port  # проверяет диапазон порта
        try:
            ipaddress.ip_address(host)
        except ValueError:
            try:
                # Winsock принимает также 127.1, 0177.0.0.1, 0x7f000001, 2130706433.
                host = socket.inet_ntoa(socket.inet_aton(host))
            except OSError:
                return ""  # DNS проверяется непосредственно перед socket.connect
        if not public_ip(host):
            return "локальный или непубличный адрес"
    except ValueError:
        return "недопустимый адрес"
    return ""


def public_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None,
                      *, all_errors=False):
    """Один DNS lookup; соединяемся только с проверенным числовым sockaddr."""
    host, port = address
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not infos or any(not public_ip(info[4][0]) for info in infos):
        raise OSError("сервер разрешается в локальный или непубличный адрес")
    error = None
    for family, kind, proto, _name, sockaddr in infos:
        sock = socket.socket(family, kind, proto)
        try:
            if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                sock.settimeout(timeout)
            if source_address:
                sock.bind(source_address)
            sock.connect(sockaddr)  # уже числовой адрес, DNS повторно не вызывается
            if not public_ip(sock.getpeername()[0]):
                raise OSError("непубличный адрес соединения")
            return sock
        except OSError as exc:
            error = exc
            sock.close()
    raise error or OSError("не удалось соединиться с сервером")


class _HTTPConnection(http.client.HTTPConnection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = public_connection


class _HTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = public_connection


class _HTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_HTTPConnection, req)


class _HTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_HTTPSConnection, req, context=self._context)


def opener(redirect_handler):
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}), redirect_handler, _HTTPHandler(), _HTTPSHandler())
