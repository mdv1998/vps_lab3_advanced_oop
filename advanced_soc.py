import re
import time
import functools
from typing import Callable, Any, Optional

def audit_logger(func: Callable[..., Any]) -> Callable[..., Any]:

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        start_time = time.perf_counter()

        try:
            result = func(*args, **kwargs)

            elapsed = time.perf_counter() - start_time

            if result is True or isinstance(result, SecurityEvent):
                print(
                    f"[AUDIT] Обнаружено событие/угроза "
                    f"функцией {func.__name__}"
                )

            print(
                f"[AUDIT] {func.__name__} выполнена "
                f"за {elapsed:.6f} сек."
            )

            return result

        except Exception as exc:
            elapsed = time.perf_counter() - start_time

            print(
                f"[AUDIT][ERROR] {func.__name__}: {exc}"
            )

            print(
                f"[AUDIT] {func.__name__} завершилась "
                f"за {elapsed:.6f} сек."
            )

            return False

    return wrapper


class SecurityEvent:
    """
    Класс события безопасности ИБ.
    """
    def __init__(self,timestamp: str,source_ip: str,event_type: str,severity: int = 1,) -> None:
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
            raise ValueError(
                "severity должен быть от 1 до 5"
            )

        self._severity = value

    @property
    def is_critical(self) -> bool:
        """
        Возвращает True, если уровень угрозы >= 4.
        """

        return self.severity >= 4

    @classmethod
    def from_syslog(cls, raw_line: str) -> "SecurityEvent":
        """
        Создает объект SecurityEvent из строки syslog.
        """

        pattern = (
            r"^(\d{4}-\d{2}-\d{2} "
            r"\d{2}:\d{2}:\d{2})\s+"
            r"\[([^\]]+)\].*?"
            r"(?:from\s+)?"
            r"(\d{1,3}(?:\.\d{1,3}){3})\s*$"
        )

        match = re.search(
            pattern,
            raw_line,
            re.IGNORECASE
        )

        if match is None:
            raise ValueError(
                "Некорректная строка syslog"
            )

        timestamp = match.group(1)
        event_type = match.group(2)
        source_ip = match.group(3)

        text = raw_line.lower()

        if (
            "sqli" in text
            or "sql injection" in text
            or "attack" in text
        ):
            severity = 5

        elif (
            "failed login" in text
            or "failed password" in text
        ):
            severity = 3

        else:
            severity = 1

        return cls(
            timestamp,
            source_ip,
            event_type,
            severity
        )

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any]
    ) -> "SecurityEvent":

        return cls(
            timestamp=str(data["timestamp"]),
            source_ip=str(data["source_ip"]),
            event_type=str(data["event_type"]),
            severity=int(data.get("severity", 1)),
        )
    def __repr__(self) -> str:
        return (
            f"SecurityEvent("
            f"ip='{self.source_ip}', "
            f"type='{self.event_type}', "
            f"severity={self.severity})"
        )

class IPUtils:
    """
    Класс-утилита для работы с IP-адресами.
    """
    @staticmethod
    def is_private(ip: str) -> bool:

        parts = ip.split(".")

        if len(parts) != 4:
            return False
        try:
            octets = [
                int(part)
                for part in parts
            ]
        except ValueError:
            return False
        if any(
            octet < 0 or octet > 255
            for octet in octets
        ):
            return False
        first = octets[0]
        second = octets[1]
        return (
            first == 10
            or (
                first == 172
                and 16 <= second <= 31
            )
            or (
                first == 192
                and second == 168
            )
            or first == 127
        )

    @staticmethod
    def mask_ip(ip: str) -> str:

        parts = ip.split(".")

        if len(parts) != 4:
            raise ValueError(
                "Некорректный IPv4-адрес"
            )

        return ".".join(
            parts[:3] + ["***"]
        )

class BlacklistManager:
    """
    Менеджер заблокированных IP-адресов.
    """
    def __init__(self,initial_ips: Optional[list[str]] = None) -> None:
        self._blocked_ips: set[str] = (set(initial_ips) if initial_ips else set())

    def add_ip(self, ip: str) -> None:
        self._blocked_ips.add(ip)

    def remove_ip(self, ip: str) -> None:
        self._blocked_ips.discard(ip)

    def __contains__(self, ip: str) -> bool:
        return ip in self._blocked_ips

    def __len__(self) -> int:
        return len(self._blocked_ips)

    def __repr__(self) -> str:
        return (
            f"BlacklistManager("
            f"blocked_count="
            f"{len(self._blocked_ips)})"
        )