"""Minimal local PEP 561 stubs for ``pystray``.

Upstream pystray ships without type hints and there is no
``types-pystray`` on PyPI. The stubs here cover the surface
``one_link.tray`` actually uses — Icon + Menu + MenuItem — plus
their lifecycle methods (``run``, ``stop``, settable ``icon`` and
``menu`` attributes). Extend as the tray module grows.
"""

from typing import Any, Callable, ClassVar, Iterable, Optional


class MenuItem:
    text: str
    action: Optional[Callable[..., Any]]
    default: bool

    def __init__(
        self,
        text: str,
        action: Optional[Callable[..., Any]] = ...,
        default: bool = ...,
        *,
        checked: Optional[Callable[[Any], bool]] = ...,
        radio: bool = ...,
        enabled: bool = ...,
        visible: bool = ...,
    ) -> None: ...


class Menu:
    SEPARATOR: ClassVar["MenuItem"]

    def __init__(self, *items: MenuItem) -> None: ...

    def __iter__(self) -> Iterable[MenuItem]: ...


class Icon:
    icon: Any  # PIL.Image.Image at runtime
    menu: Optional[Menu]
    title: Optional[str]
    visible: bool

    def __init__(
        self,
        name: str,
        icon: Any = ...,
        title: Optional[str] = ...,
        menu: Optional[Menu] = ...,
    ) -> None: ...

    def run(self) -> None: ...

    def stop(self) -> None: ...

    def notify(self, message: str, title: Optional[str] = ...) -> None: ...

    def update_menu(self) -> None: ...
