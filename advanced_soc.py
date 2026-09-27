import functools
from typing import Callable, Any, Optional


def audit_logger(func: Callable[..., Any]) -> Callable[..., Any]:
    """Декоратор: перехватывает ошибки, возвращает False при сбое."""
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except Exception:
            return False
    return wrapper


class SecurityEvent:
    """Событие безопасности."""

    def __init__(self, timestamp: str, source_ip: str, event_type: str, severity: int = 1) -> None:
        self.timestamp = timestamp
        self.source_ip = source_ip
        self.event_type = event_type
        self.severity = severity

    @property
    def severity(self) -> int:
        return self._severity

    @severity.setter
    def severity(self, value: int) -> None:
        if not 1 <= value <= 5:
            raise ValueError("severity должна быть от 1 до 5")
        self._severity = value

    @property
    def is_critical(self) -> bool:
        return self.severity >= 4

    @classmethod
    def from_syslog(cls, raw_line: str) -> "SecurityEvent":
        """Создаёт событие из строки syslog."""
        ts = raw_line.split("]")[0]
        ts = ts.split("[")[0].strip()
        etype = raw_line[raw_line.index("[") + 1:raw_line.index("]")]
        ip = raw_line.split()[-1]
        sev = 5 if "attack" in raw_line.lower() else 3
        return cls(ts, ip, etype, sev)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SecurityEvent":
        """Создаёт событие из словаря."""
        return cls(data["timestamp"], data["source_ip"], data["event_type"], data.get("severity", 1))

    def __repr__(self) -> str:
        return f"SecurityEvent(ip='{self.source_ip}', type='{self.event_type}', severity={self.severity})"


class IPUtils:
    """Утилиты для IP-адресов."""

    @staticmethod
    def is_private(ip: str) -> bool:
        """Проверяет, является ли IP частным."""
        o = ip.split(".")
        a, b = int(o[0]), int(o[1])
        return a == 10 or a == 172 and 16 <= b <= 31 or a == 192 and b == 168 or a == 127

    @staticmethod
    def mask_ip(ip: str) -> str:
        """Маскирует последний октет: 192.168.1.50 -> 192.168.1.***"""
        parts = ip.split(".")
        parts[-1] = "***"
        return ".".join(parts)


class BlacklistManager:
    """Менеджер чёрного списка IP."""

    def __init__(self, initial_ips: Optional[list[str]] = None) -> None:
        self._blocked_ips: set[str] = set(initial_ips) if initial_ips else set()

    def add_ip(self, ip: str) -> None:
        self._blocked_ips.add(ip)

    def remove_ip(self, ip: str) -> None:
        self._blocked_ips.discard(ip)

    def __contains__(self, ip: str) -> bool:
        return ip in self._blocked_ips

    def __len__(self) -> int:
        return len(self._blocked_ips)

    def __repr__(self) -> str:
        return f"BlacklistManager(blocked_count={len(self._blocked_ips)})"
