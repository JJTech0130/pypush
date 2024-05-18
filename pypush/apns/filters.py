from pypush.apns import protocol
from typing import TypeVar, Optional, Type, Callable

# def chain(*filters):
#     def filter(command: protocol.Command) -> Optional[protocol.Command]:
#         for f in filters:
#             command = f(command)
#             if command is None:
#                 return None
#         return command
#     return filter

T1 = TypeVar("T1")
T2 = TypeVar("T2")
Filter = Callable[[T1], Optional[T2]]
# typing.Callable[[protocol.Command], typing.Optional[T]]

# Chain with proper types so that subsequent filters only need to take output type of previous filter
T_IN = TypeVar("T_IN", bound=protocol.Command)
T_MIDDLE = TypeVar("T_MIDDLE", bound=protocol.Command)
T_OUT = TypeVar("T_OUT", bound=protocol.Command)


def chain(first: Filter[T_IN, T_MIDDLE], second: Filter[T_MIDDLE, T_OUT]):
    def filter(command: T_IN) -> Optional[T_OUT]:
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
