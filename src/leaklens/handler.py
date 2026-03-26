"""Handler module for extracting data from HTML pages and other text files crawled from website"""

import queue
import re
import sys
import typing
from typing import Protocol, Union

from bs4 import BeautifulSoup, NavigableString, Tag

from leaklens.entity import Secret
from leaklens.exception import HandlerException

# 测试数据黑名单
TEST_DATA_BLACKLIST = {
    # 邮箱
    'email': [
        'test@example.com', 'user@example.com', 'admin@example.com', 
        'test@test.com', 'user@test.com', 'admin@test.com',
        'example@example.com', 'demo@example.com', 'sample@example.com',
        'mail@mail.ru'
    ],
    # 邮箱后缀
    'email_suffix': [
        '@example.com', '@mail.ru'
    ],
    # 电话
    'phone': [
        '1234567890', '0123456789', '1111111111',
        '2222222222', '3333333333', '4444444444',
        '5555555555', '6666666666', '7777777777',
        '8888888888', '9999999999'
    ],
    # 身份证号
    'idcard': [
        '110101199001011234', '110101199001011235',
        '110101199001011236', '110101199001011237',
        '110101199001011238', '110101199001011239'
    ],
    # IP地址
    'ip': [
        '127.0.0.1', '0.0.0.0', '192.168.1.1',
        '192.168.0.1', '10.0.0.1', '172.16.0.1'
    ]
}

# 检查是否为测试数据
def is_test_data(secret_type: str, secret_data: str) -> bool:
    """检查敏感信息是否为测试数据"""
    # 转换为小写进行比较
    secret_data_lower = secret_data.lower()
    
    # 检查邮箱
    if 'email' in secret_type.lower():
        # 检查完整邮箱
        for test_email in TEST_DATA_BLACKLIST['email']:
            if test_email.lower() in secret_data_lower:
                return True
        # 检查邮箱后缀
        for suffix in TEST_DATA_BLACKLIST['email_suffix']:
            if suffix.lower() in secret_data_lower:
                return True
    
    # 检查电话
    if 'phone' in secret_type.lower():
        for test_phone in TEST_DATA_BLACKLIST['phone']:
            if test_phone in secret_data:
                return True
    
    # 检查身份证号
    if 'id' in secret_type.lower() or 'card' in secret_type.lower():
        for test_id in TEST_DATA_BLACKLIST['idcard']:
            if test_id in secret_data:
                return True
    
    # 检查IP地址
    if 'ip' in secret_type.lower():
        for test_ip in TEST_DATA_BLACKLIST['ip']:
            if test_ip in secret_data:
                return True
    
    return False

# T = typing.TypeVar("T")
# IterableAsyncOrSync: typing.TypeAlias = typing.Iterable[T] | typing.AsyncIterable[T]
BSResult = Union[Tag, NavigableString, None]


class Handler(Protocol):
    """Base class for different types of handlers"""

    def handle(self, text: str) -> typing.Iterable[Secret]: ...


class ReRegexHandler(Handler):
    """ Regex handler using the `re` module, simple but have lowest performance."""

    def __init__(self, rules: typing.Dict[str, str], flags: int = 0, use_groups: bool = False) -> None:
        """

        :param rules: rules dictionary with keys indicating type and values indicating the regex
        :param use_groups: extract content from regex groups but not the whole match
        """
        self.types = list(rules.keys())
        regexes = list(rules.values())
        self.regexes: typing.List[re.Pattern] = list()
        for regex in regexes:
            self.regexes.append(re.compile(regex, flags=flags | re.IGNORECASE))
        self.use_groups = use_groups

    def handle(self, text: str) -> typing.Iterable[Secret]:
        """Extract secret data"""
        result_list: typing.List[Secret] = list()
        for index, regex in enumerate(self.regexes):
            if self.use_groups:
                matches = regex.findall(text)
                for match in matches:
                    if match is not None:
                        secret_data = match if type(match) is not tuple else match[0]
                        secret_type = self.types[index]
                        # 检查是否为测试数据
                        if not is_test_data(secret_type, secret_data):
                            secret = Secret(type=secret_type, data=secret_data)
                            result_list.append(secret)
            else:
                match = regex.search(text)
                if match is not None:
                    secret_data = match.group(0)
                    secret_type = self.types[index]
                    # 检查是否为测试数据
                    if not is_test_data(secret_type, secret_data):
                        secret = Secret(type=secret_type, data=secret_data)
                        result_list.append(secret)

        return result_list


if not sys.platform.startswith("win"):
    # hyperscan does not support windows
    try:
        import hyperscan
    except ImportError:
        hyperscan = None


    class HyperscanRegexHandler(Handler):
        """Regex handler using `hyperscan` module"""

        def __init__(
            self, rules: typing.Dict[str, str], lazy_init: bool = False, hs_flag: int = 0
        ):
            """

            :param rules: regex rules dictionary with keys indicating type and values indicating the regex
            :param lazy_init: True for deferring the initialization to actively call the init() method, otherwise initialize immediately
            :param hs_flag: hyperscan flag perform to every expressions
            """
            # self.output_queue: queue.Queue[Secret] = queue.Queue()
            self.rules = rules
            self._init: bool = False
            self._hs_flag: int = (
                hs_flag | hyperscan.HS_FLAG_SOM_LEFTMOST | hyperscan.HS_FLAG_CASELESS
            )
            self._db: typing.Optional[hyperscan.Database] = None
            self.patterns: typing.Dict[int, bytes] = dict()  # pattern id => regex in bytes
            self.types: typing.Dict[int, str] = dict()  # pattern id => type
            if not lazy_init:
                self.init()

        def init(self):
            """Initialize the hyperscan database."""
            self._db = hyperscan.Database()
            flags: typing.List[int] = [self._hs_flag for _ in range(len(self.rules))]
            for index, type_str in enumerate(self.rules):
                regex = self.rules.get(type_str)
                self.patterns[index] = regex.encode("utf-8")
                self.types[index] = type_str

            self._db.compile(
                expressions=list(self.patterns.values()),
                ids=list(self.patterns.keys()),
                elements=len(self.patterns),
                flags=flags,
            )

            self._init = True

        def handle(self, text: str) -> typing.Iterable[Secret]:
            """Extract secret data via the pre-compiled hyperscan database

            This method is IO-bound.
            """
            if not self._init:
                raise HandlerException("Hyperscan database is not initialized")

            results: typing.List[Secret] = list()

            def on_match(
                id: int,
                froms: int,
                to: int,
                flags: int,
                context: typing.Optional[typing.Any] = None,
            ) -> typing.Optional[bool]:
                match = text[froms:to]
                type = self.types.get(id)
                # 检查是否为测试数据
                if not is_test_data(type, match):
                    results.append(Secret(type, data=match))
                return None

            self._db.scan(
                text.encode("utf8"), match_event_handler=on_match
            )  # block call until all regex operation finish
            return results


class BSHandler(Handler):
    """BeautifulSoup handler that filter html elements on demand"""

    def __init__(
        self, filter_func: typing.Callable[[BeautifulSoup], typing.List[BSResult]]
    ) -> None:
        self.filter = filter_func

    def handle(self, text: str) -> typing.Iterable[Secret]:
        """Extract secret data via filter

        :type text: str
        :param text: should be in html format
        """
        soup = BeautifulSoup(text, "html.parser")
        result: typing.List[BSResult] = self.filter(soup)
        results: typing.List[Secret] = list()
        if result is not None:
            secret = Secret(type="HTML Element", data=result)
            results.append(secret)
        return results


def get_regex_handler(rules: typing.Dict[str, str], type_: str = "", *args, **kwargs) -> Handler:
    """Return regex handler on current platform"""
    if len(type_) == 0:
        is_hyperscan = False
        try:
            import hyperscan
            is_hyperscan = True
        except ImportError:
            is_hyperscan = False
        if sys.platform.startswith("win") or not is_hyperscan:
            return ReRegexHandler(rules, *args, **kwargs)
        else:
            return HyperscanRegexHandler(rules, *args, **kwargs)
    else:
        if type_ == "regex":
            return ReRegexHandler(rules, *args, **kwargs)
        elif type_ == "hyperscan":
            return HyperscanRegexHandler(rules, *args, **kwargs)
        else:
            return ReRegexHandler(rules, *args, **kwargs)

