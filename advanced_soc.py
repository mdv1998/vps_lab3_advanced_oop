import re
import time
import functools
from typing import Callable, Any, Optional


def audit_logger(func: Callable[..., Any]) -> Callable[..., Any]:
    """Декоратор аудита функций ИБ-анализа."""
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        start = time.time()
        try:
            result = func(*args, **kwargs)
            elapsed = time.time() - start
            if result is True:
                print(f"[AUDIT] {func.__name__}: угроза обнаружена (за {elapsed:.4f} с)")
            else:
                print(f"[AUDIT] {func.__name__}: выполнено за {elapsed:.4f} с")
            return result
        except Exception as exc:
            print(f"[AUDIT] {func.__name__}: ошибка {type(exc).__name__}: {exc}")
            return False
    return wrapper


class SecurityEvent:
    """Класс события безопасности."""

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
            raise ValueError("Severity must be between 1 and 5")
        self._severity = value

    @property
    def is_critical(self) -> bool:
        return self.severity >= 4

    @classmethod
    def from_syslog(cls, raw_line: str) -> "SecurityEvent":
        # timestamp — первые два токена: "2026-09-13 12:00:00"
        parts = raw_line.split()
        timestamp = f"{parts[0]} {parts[1]}"

        # event_type — внутри [ ]
        m_type = re.search(r"\[(\w+)\]", raw_line)
        event_type = m_type.group(1) if m_type else "UNKNOWN"

        # IP — после "from "
        m_ip = re.search(r"from\s+((?:\d{1,3}\.){3}\d{1,3})", raw_line)
        source_ip = m_ip.group(1) if m_ip else "0.0.0.0"

        # severity
        low = raw_line.lower()
        if "sqli" in low or "attack payload" in low:
            severity = 5
        elif "failed login" in low or "failed password" in low:
            severity = 3
        else:
            severity = 1

        return cls(timestamp, source_ip, event_type, severity)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SecurityEvent":
        return cls(
            timestamp=data["timestamp"],
            source_ip=data["source_ip"],
            event_type=data["event_type"],
            severity=data.get("severity", 1),
        )

    def __repr__(self) -> str:
        return f"SecurityEvent(ip='{self.source_ip}', type='{self.event_type}', severity={self.severity})"


class IPUtils:
    """Утилиты для работы с IP-адресами."""

    @staticmethod
    def is_private(ip: str) -> bool:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            a, b, c, d = (int(p) for p in parts)
        except ValueError:
            return False

        if a == 10:
            return True
        if a == 172 and 16 <= b <= 31:
            return True
        if a == 192 and b == 168:
            return True
        if a == 127:
            return True
        return False

    @staticmethod
    def mask_ip(ip: str) -> str:
        parts = ip.split(".")
        if len(parts) != 4:
            return ip
        return f"{parts[0]}.{parts[1]}.{parts[2]}.***"


class BlacklistManager:
    """Менеджер заблокированных IP."""

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