import functools
import ipaddress
import re
import time
from typing import Any, Callable, Optional


def audit_logger(func: Callable[..., Any]) -> Callable[..., Any]:
    """Декоратор для аудита функций ИБ-анализа."""
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            duration = time.time() - start_time
            if result:
                print(f"[AUDIT] Event or threat detected in {func.__name__} (execution time: {duration:.4f}s)")
            return result
        except Exception as e:
            duration = time.time() - start_time
            print(f"[AUDIT] Error in {func.__name__}: {e} (execution time: {duration:.4f}s)")
            return None

    return wrapper


class SecurityEvent:
    """Класс события безопасности ИБ."""

    def __init__(
        self,
        timestamp: str,
        source_ip: str,
        event_type: str,
        severity: int = 1
    ) -> None:
        self.timestamp = timestamp
        self.source_ip = source_ip
        self.event_type = event_type
        self._severity = 1
        self.severity = severity  # Проходит через сеттер с валидацией

    @property
    def severity(self) -> int:
        """Возвращает уровень угрозы."""
        return self._severity

    @severity.setter
    def severity(self, value: int) -> None:
        """Валидация диапазона severity (от 1 до 5)."""
        if not isinstance(value, int) or not (1 <= value <= 5):
            raise ValueError("Severity must be an integer between 1 and 5.")
        self._severity = value

    @property
    def is_critical(self) -> bool:
        """Возвращает True, если уровень угрозы >= 4."""
        return self.severity >= 4

    @classmethod
    def from_syslog(cls, raw_line: str) -> "SecurityEvent":
        """Фабричный метод для парсинга syslog-строки."""
        pattern = r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+(.*?)\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})$"
        match = re.match(pattern, raw_line.strip())

        if not match:
            raise ValueError(f"Invalid syslog format: {raw_line}")

        # Распаковка строго ПОСЛЕ проверки if not match
        timestamp, event_type, message, source_ip = match.groups()

        lower_msg = message.lower()
        if "sqli" in lower_msg or "attack" in lower_msg or "critical" in lower_msg:
            severity = 5
        elif "failed" in lower_msg or "error" in lower_msg or "warning" in lower_msg:
            severity = 3
        else:
            severity = 1

        return cls(
            timestamp=timestamp,
            source_ip=source_ip,
            event_type=event_type,
            severity=severity
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SecurityEvent":
        """Фабричный метод: соотносит словарь с объектом."""
        return cls(
            timestamp=data["timestamp"],
            source_ip=data["source_ip"],
            event_type=data["event_type"],
            severity=data.get("severity", 1)
        )

    def __repr__(self) -> str:
        return (
            f"SecurityEvent(ip='{self.source_ip}', "
            f"type='{self.event_type}', "
            f"severity={self.severity})"
        )


class IPUtils:
    """Класс-утилита для работы с IP-адресами."""

    @staticmethod
    def is_private(ip: str) -> bool:
        """Проверяет, является ли IP частным (приватным)."""
        try:
            ip_object = ipaddress.ip_address(ip)
            return ip_object.is_private or ip_object.is_loopback
        except ValueError:
            return False

    @staticmethod
    def mask_ip(ip: str) -> str:
        """Маскирует последний октет IP-адреса."""
        parts = ip.split(".")
        if len(parts) == 4:
            parts[3] = "***"
            return ".".join(parts)
        return ip


class BlacklistManager:
    """Менеджер заблокированных IP-адресов."""

    def __init__(self, initial_ips: Optional[list[str]] = None) -> None:
        self._blocked_ips: set[str] = set(initial_ips) if initial_ips else set()

    def add_ip(self, ip: str) -> None:
        """Добавить IP в множество."""
        self._blocked_ips.add(ip)

    def remove_ip(self, ip: str) -> None:
        """Удалить IP из множества."""
        self._blocked_ips.discard(ip)

    def __contains__(self, ip: str) -> bool:
        """Поддержка оператора in."""
        return ip in self._blocked_ips

    def __len__(self) -> int:
        """Поддержка len()."""
        return len(self._blocked_ips)

    def __repr__(self) -> str:
        return f"BlacklistManager(blocked_count={len(self._blocked_ips)})"