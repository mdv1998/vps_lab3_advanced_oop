import re
import time
import functools
from typing import Callable, Any, Optional


def audit_logger(func: Callable[..., Any]) -> Callable[..., Any]:
    """
    Декоратор для аудита функций ИБ-анализа.

    Замеряет время выполнения функции,
    выводит информацию о результате и
    перехватывает ошибки.
    """

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        start_time = time.time()

        try:
            result = func(*args, **kwargs)

            elapsed = time.time() - start_time

            if result is True:
                print(
                    f"[AUDIT] Обнаружена угроза. "
                    f"Функция: {func.__name__}, "
                    f"время: {elapsed:.6f} сек."
                )

            return result

        except Exception as error:
            elapsed = time.time() - start_time

            print(
                f"[AUDIT] Ошибка в функции {func.__name__}: "
                f"{error}. Время: {elapsed:.6f} сек."
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
        severity: int = 1
    ) -> None:
        self.timestamp = timestamp
        self.source_ip = source_ip
        self.event_type = event_type
        self.severity = severity

    @property
    def severity(self) -> int:
        """Возвращает уровень опасности события."""
        return self._severity

    @severity.setter
    def severity(self, value: int) -> None:
        """Устанавливает severity от 1 до 5."""
        if not 1 <= value <= 5:
            raise ValueError("Severity должна быть от 1 до 5")

        self._severity = value

    @property
    def is_critical(self) -> bool:
        """Возвращает True, если уровень угрозы >= 4."""
        return self.severity >= 4

    @classmethod
    def from_syslog(cls, raw_line: str) -> "SecurityEvent":
        """
        Создает объект SecurityEvent из строки syslog.

        Пример:
        2026-09-13 12:00:00 [SSH] Failed login from 192.168.1.50
        """

        timestamp_match = re.search(
            r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})",
            raw_line
        )

        event_type_match = re.search(
            r"\[([^\]]+)\]",
            raw_line
        )

        ip_match = re.search(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            raw_line
        )

        if not timestamp_match:
            raise ValueError("Не удалось найти timestamp")

        if not event_type_match:
            raise ValueError("Не удалось найти event_type")

        if not ip_match:
            raise ValueError("Не удалось найти IP-адрес")

        timestamp = timestamp_match.group(1)
        event_type = event_type_match.group(1)
        source_ip = ip_match.group(0)

        # Определяем severity по содержимому события.
        lower_line = raw_line.lower()

        if "sqli" in lower_line or "sql injection" in lower_line:
            severity = 5
        elif "failed login" in lower_line:
            severity = 3
        elif "attack" in lower_line:
            severity = 5
        elif "error" in lower_line:
            severity = 2
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
        """
        Создает объект SecurityEvent из словаря.
        """

        return cls(
            timestamp=data["timestamp"],
            source_ip=data["source_ip"],
            event_type=data["event_type"],
            severity=data.get("severity", 1)
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
        """
        Проверяет, является ли IP частным.

        Поддерживаются:
        10.x.x.x
        172.16-31.x.x
        192.168.x.x
        127.x.x.x
        """

        parts = ip.split(".")

        if len(parts) != 4:
            return False

        try:
            numbers = [int(part) for part in parts]
        except ValueError:
            return False

        if any(number < 0 or number > 255 for number in numbers):
            return False

        first = numbers[0]
        second = numbers[1]

        if first == 10:
            return True

        if first == 172 and 16 <= second <= 31:
            return True

        if first == 192 and second == 168:
            return True

        if first == 127:
            return True

        return False

    @staticmethod
    def mask_ip(ip: str) -> str:
        """
        Маскирует последний октет IP-адреса.

        192.168.1.50 -> 192.168.1.***
        """

        parts = ip.split(".")

        if len(parts) != 4:
            raise ValueError("Некорректный IP-адрес")

        return ".".join(parts[:3] + ["***"])


class BlacklistManager:
    """
    Менеджер заблокированных IP-адресов.
    """

    def __init__(self, initial_ips: Optional[list[str]] = None) -> None:
        self._blocked_ips: set[str] = (
            set(initial_ips) if initial_ips else set()
        )

    def add_ip(self, ip: str) -> None:
        """Добавляет IP в чёрный список."""
        self._blocked_ips.add(ip)

    def remove_ip(self, ip: str) -> None:
        """Удаляет IP из чёрного списка."""
        self._blocked_ips.discard(ip)

    def __contains__(self, ip: str) -> bool:
        """Позволяет использовать оператор in."""
        return ip in self._blocked_ips

    def __len__(self) -> int:
        """Возвращает количество заблокированных IP."""
        return len(self._blocked_ips)

    def __repr__(self) -> str:
        return (
            f"BlacklistManager("
            f"blocked_count={len(self._blocked_ips)})"
        )