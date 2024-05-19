import logging
from typing import Callable, Optional, Type, TypeVar

from pypush.apns import protocol

T1 = TypeVar("T1")
T2 = TypeVar("T2")
Filter = Callable[[T1], Optional[T2]]

# Chain with proper types so that subsequent filters only need to take output type of previous filter
T_IN = TypeVar("T_IN", bound=protocol.Command)
T_MIDDLE = TypeVar("T_MIDDLE", bound=protocol.Command)
T_OUT = TypeVar("T_OUT", bound=protocol.Command)


def chain(first: Filter[T_IN, T_MIDDLE], second: Filter[T_MIDDLE, T_OUT]):
    def filter(command: T_IN) -> Optional[T_OUT]:
        logging.debug(f"Filtering {command} with {first} and {second}")
        filtered = first(command)
        if filtered is None:
            return None
        return second(filtered)

    return filter


T = TypeVar("T", bound=protocol.Command)


def cmd(type: Type[T]) -> Filter[protocol.Command, T]:
    def filter(command: protocol.Command) -> Optional[T]:
        if isinstance(command, type):
            return command
        return None

    return filter


def ALL(c):
    return c


def NONE(_):
    return None
