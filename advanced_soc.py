import re
import time
import functools
import ipaddress
from typing import Callable, Any, Optional


def audit_logger(func: Callable[..., Any]) -> Callable[..., Any]:
    """
    """

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        start_time = time.time()

        try:
            result = func(*args, **kwargs)
            elapsed = time.time() - start_time

            if result is True:
                print(
                    f"[AUDIT] Обнаружена угроза в {func.__name__} "
                    f"(время выполнения: {elapsed:.4f} сек.)"
                )
            elif isinstance(result, SecurityEvent):
                print(
                    f"[AUDIT] Событие ИБ: {result} "
                    f"(время выполнения: {elapsed:.4f} сек.)"
                )
            else:
                print(
                    f"[AUDIT] Функция {func.__name__} завершена "
                    f"(время выполнения: {elapsed:.4f} сек.)"
                )

            return result

        except Exception as error:
            elapsed = time.time() - start_time
            print(
                f"[AUDIT] Ошибка в {func.__name__}: {error} "
                f"(время выполнения: {elapsed:.4f} сек.)"
            )
            return False

    return wrapper


class SecurityEvent:
    """
    Класс события безопасности ИБ.
    """

    def __init__(
        self,
        timestamp: str,
        source_ip: str,
        event_type: str,
        severity: int = 1,
    ) -> None:
        self.timestamp = timestamp
        self.source_ip = source_ip
        self.event_type = event_type
        self.severity = severity

    @property
    def severity(self) -> int:
        return self._severity

    @severity.setter
    def severity(self, value: int) -> None:
        # TODO: Проверить, что значение от 1 до 5
        # (иначе вызывать ValueError)
        if not 1 <= value <= 5:
            raise ValueError("Severity должна быть от 1 до 5")
        self._severity = value

    @property
    def is_critical(self) -> bool:
        """Возвращает True, если уровень угрозы >= 4."""
        # TODO: Проверить критичность
        return self.severity >= 4

    @classmethod
    def from_syslog(cls, raw_line: str) -> "SecurityEvent":
        """
        Фабричный метод: создает объект из строки syslog.
        """
        timestamp_match = re.search(
            r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})",
            raw_line,
        )
        event_type_match = re.search(
            r"\[([^]]+)\]",
            raw_line,
        )
        ip_match = re.search(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            raw_line,
        )

        if timestamp_match is None:
            raise ValueError("Не удалось найти timestamp")
        if event_type_match is None:
            raise ValueError("Не удалось найти event_type")
        if ip_match is None:
            raise ValueError("Не удалось найти IP-адрес")

        timestamp = timestamp_match.group(1)
        event_type = event_type_match.group(1)
        source_ip = ip_match.group(0)
        lower_line = raw_line.lower()

        if "sqli" in lower_line or "sql injection" in lower_line:
            severity = 5
        elif "failed login" in lower_line:
            severity = 3
        elif "failed password" in lower_line:
            severity = 3
        elif "attack" in lower_line or "intrusion" in lower_line:
            severity = 5
        elif "warning" in lower_line:
            severity = 2
        else:
            severity = 1

        return cls(timestamp, source_ip, event_type, severity)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SecurityEvent":
        """
        Фабричный метод: создает объект из словаря.
        """
        # TODO: Создать объект из словаря data
        return cls(
            timestamp=str(data["timestamp"]),
            source_ip=str(data["source_ip"]),
            event_type=str(data["event_type"]),
            severity=int(data.get("severity", 1)),
        )

    def __repr__(self) -> str:
        return (
            f"SecurityEvent(ip='{self.source_ip}', "
            f"type='{self.event_type}', severity={self.severity})"
        )


class IPUtils:
    """
    Класс-утилита для работы с IP-адресами.
    """

    @staticmethod
    def is_private(ip: str) -> bool:
        """
        Проверяет, является ли IP частным
        (10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.x.x.x).
        """
        # TODO: Проверить приватность IP-адреса
        try:
            address = ipaddress.ip_address(ip)
            return address.is_private or address.is_loopback
        except ValueError:
            return False

    @staticmethod
    def mask_ip(ip: str) -> str:
        """
        Маскирует последний октет IP-адреса.
        Пример: '192.168.1.50' -> '192.168.1.***'
        """
        parts = ip.split(".")
        if len(parts) != 4:
            raise ValueError("Ожидается IPv4-адрес")
        return ".".join(parts[:3]) + ".***"


class BlacklistManager:
    """
    Менеджер заблокированных IP-адресов.
    """

    def __init__(self, initial_ips: Optional[list[str]] = None) -> None:
        self._blocked_ips = (
            set(initial_ips) if initial_ips else set()
        )

    def add_ip(self, ip: str) -> None:
        # TODO: Добавить IP в множество
        self._blocked_ips.add(ip)

    def remove_ip(self, ip: str) -> None:
        # TODO: Удалить IP из множества
        self._blocked_ips.discard(ip)

    def __contains__(self, ip: str) -> bool:
        # TODO: Поддержка оператора in
        return ip in self._blocked_ips

    def __len__(self) -> int:
        # TODO: Поддержка len()
        return len(self._blocked_ips)

    def __repr__(self) -> str:
        return (
            f"BlacklistManager("
            f"blocked_count={len(self._blocked_ips)})"
        )
