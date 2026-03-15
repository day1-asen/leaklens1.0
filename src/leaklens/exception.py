"""Exceptions raised by LeakLens."""


class LeakLensException(Exception):
    """Global exception raised by LeakLens"""

    pass


class AsyncPoolException(LeakLensException):
    """Exception raised by coroutine module"""

    pass


class HandlerException(LeakLensException):
    """Exception raised by handlers module"""

    pass


class CrawlerException(LeakLensException):
    """Exception raised by crawler module"""

    pass


class FacadeException(LeakLensException):
    """Exception raised by facade classes"""

    pass

class FileScannerException(LeakLensException):
    """Exception raised by file scanner"""
    pass

