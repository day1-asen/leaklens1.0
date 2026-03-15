"""The facade interfaces to integrate crawler, filter, and handler"""

import asyncio
import functools
import logging
import queue
import re
import threading
import traceback
import typing
from typing import Set
from urllib.parse import urlparse

import aiocache
import aiohttp
import anyio
import dynaconf
import httpx
from aiohttp import ClientResponse
from httpx import AsyncClient

from leaklens.coroutinue import AsyncPoolCollector, AsyncTask
from leaklens.entity import URL, Secret, URLNode
from leaklens.filter import URLFilter
from leaklens.handler import Handler
from leaklens.urlparser import URLParser
from leaklens.api_discovery import APIEndpointDiscovery
from leaklens.auth_detector import AuthDetector
from leaklens.idor_detector import IDORDetector
from leaklens.jwt_detector import JWTAuthBypassDetector
from aiocache.serializers import PickleSerializer

from .config import settings
from .exception import CrawlerException
from .util import Range, get_response_title

logger = logging.getLogger(__name__)


class Crawler:
    """Crawler interface"""

    def __init__(
        self,
        start_urls: typing.List[str],
        # client: aiohttp.ClientSession,
        url_filter: URLFilter,
        parser: URLParser,
        handler: Handler,
        # allowed_status: typing.List[Range] = None,
        max_page_num: int = 0,
        max_depth: int = 3,
        num_workers: int = 100,
        proxy: str = None,
        headers: dict = None,
        verbose: bool = False,
        timeout: float = 5,
        debug: bool = False,
        follow_redirects: bool = False,
        dangerous_paths: typing.List[str] = None,
        validate: bool = False,
        api_detection: bool = True,
        auth_detection: bool = False,
        idor_detection: bool = False,
        jwt_detection: bool = False,
        auth_token: str = None
    ):
        """

        :param start_urls: urls to start crawl from
        # :param client: aiohttp client
        :param url_filter: determine whether a url should be crawled
        :param parser: extract child url nodes from html
        :param handler: how to deal with the crawl result
        # :param allowed_status: filter response status. None for no filter
        :param max_page_num: max number of urls to crawl, 0 for no limit
        :param max_depth: max url depth, should greater than 0
        :param num_workers: worker number of the async pool
        :param proxy: http proxy
        :param verbose: whether to print exception detail
        :param timeout: timeout for aiohttp request
        :param dangerous_paths: dangerous paths to evade
        :param api_detection: whether to enable API endpoint detection
        :param auth_detection: whether to enable authentication detection
        :param idor_detection: whether to enable IDOR detection
        :param jwt_detection: whether to enable JWT authentication bypass detection
        :param auth_token: authentication token for detection
        """
        self.dangerous_paths = dangerous_paths
        self.proxy = proxy
        self.start_urls = start_urls
        # self.client = client
        self.filter = url_filter
        self.parser = parser
        self.handler = handler
        self.max_page_num = max_page_num
        self.max_depth = max_depth
        self.num_workers = min(num_workers, 50)  # 限制最大并发数
        self.verbose = verbose
        self.timeout = min(timeout, 10)  # 限制最大超时时间
        self.headers = headers
        self.debug = debug
        if self.debug:
            logger.setLevel(logging.DEBUG)
        self.follow_redirects = follow_redirects
        self._validate = validate
        self.api_detection_enabled = api_detection
        self.auth_detection_enabled = auth_detection
        self.idor_detection_enabled = idor_detection
        self.jwt_detection_enabled = jwt_detection
        self.auth_token = auth_token

        # 优化缓存设置
        self.cache = aiocache.Cache(aiocache.Cache.MEMORY, ttl=300)
        self.serializer = PickleSerializer()

        self.visited_urls: Set[URLNode] = set()
        self.found_urls: Set[URLNode] = set()  # newly found urls
        self.working_queue: queue.Queue[URLNode] = queue.Queue()  # BP queue
        self.url_dict: typing.Dict[URLNode, typing.Set[URLNode]] = (
            dict()
        )  # url and all of its children url
        self.js_dict: typing.Dict[URLNode, typing.Set[URLNode]] = (
            dict()
        )  # url and all of its children js
        self.total_page: int = 0  # total number of pages found, include error pages
        self.url_secrets: typing.Dict[URLNode, typing.Set[Secret]] = (
            dict()
        )  # url and secrets found from it
        self.api_endpoints: typing.List[Dict] = []  # discovered API endpoints
        self.auth_results: typing.List[Dict] = []  # auth detection results
        self.idor_results: typing.List[Dict] = []  # IDOR detection results
        self.jwt_results: typing.List[Dict] = []  # JWT detection results
        self.api_discovery = APIEndpointDiscovery()
        self.auth_detector = AuthDetector()
        self.idor_detector = IDORDetector()
        self.jwt_detector = JWTAuthBypassDetector()
        self._event_loop = asyncio.new_event_loop()
        
        # 优化HTTP客户端配置
        limits = httpx.Limits(max_connections=100, max_keepalive_connections=20)
        self.client: httpx.AsyncClient = AsyncClient(
            verify=False, 
            proxies=self.proxy, 
            limits=limits,
            timeout=httpx.Timeout(self.timeout),
            follow_redirects=self.follow_redirects
        )
        
        self.close = threading.Event()  # whether the crawler is closed
        self.close.clear()
        
        # 优化线程池配置
        self.pool: AsyncPoolCollector = AsyncPoolCollector.create_pool(
            num_workers=self.num_workers, 
            queue_capacity=1000,  # 添加队列容量限制
            event_loop=self._event_loop
        )

    def start(self):
        """Start event loop"""
        try:
            self._event_loop.run_until_complete(self.main_task())
        except asyncio.CancelledError:
            pass  # ignore

    def close_all(self):
        """Close crawler, cancel all tasks"""
        try:
            self._event_loop.run_until_complete(self.clean())
        except asyncio.CancelledError:
            pass  # ignore

    async def main_task(self):
        """A wrapper"""
        try:
            await asyncio.gather(self.run(), self.consumer())
        except asyncio.CancelledError:
            return

    async def run(self):
        """Start the crawler"""
        try:

            # initialize with start_urls
            for url in self.start_urls:
                url_obj = urlparse(url)
                url_node = URLNode(url=url, url_object=url_obj, depth=0, parent=None)
                # self.found_urls.add(url_node)
                if self.filter.doFilter(url_node.url_object):
                    logger.debug(f"Target: {url}")
                    self.visited_urls.add(url_node)
                    self.working_queue.put(url_node)

            while True:
                if self.max_page_num > 0 and self.total_page >= self.max_page_num:
                    break
                if (
                    self.working_queue.empty()
                    and self.pool.is_finish
                    and self.pool.done_queue.empty()
                ):
                    break

                try:
                    url_node = self.working_queue.get_nowait()
                except queue.Empty:
                    await asyncio.sleep(0.1)
                    continue
                if self.max_depth <= 0 or url_node.depth <= self.max_depth:
                    task = AsyncTask(self.process_one, url_node)
                    await self.pool.submit(task)
                logger.debug(
                    f"Total:{self.total_page}, Found:{len(self.found_urls)}, Depth:{url_node.depth}, Visited:{len(self.visited_urls)}, Secrets:{sum([len(secrets) for secrets in self.url_secrets.values()])}"
                )
            logger.debug(f"Crawler finished.")
            
            # 执行API端点检测
            if self.api_detection_enabled:
                logger.info(f"API endpoint detection completed: {len(self.api_endpoints)} endpoints found")
            
            # 执行鉴权状态检测
            if self.auth_detection_enabled:
                await self.detect_auth_status()
                logger.info(f"Authentication detection completed: {len(self.auth_results)} results")
            
            # 执行IDOR越权测试
            if self.idor_detection_enabled:
                logger.info(f"Starting IDOR detection with {len(self.api_endpoints)} API endpoints")
                await self.detect_idor_vulnerabilities()
                logger.info(f"IDOR detection completed: {len(self.idor_results)} vulnerabilities found")
            
            # 执行JWT鉴权绕过检测
            if self.jwt_detection_enabled:
                logger.info(f"Starting JWT detection with {len(self.api_endpoints)} API endpoints")
                await self.detect_jwt_bypass()
                logger.info(f"JWT detection completed: {len(self.jwt_results)} vulnerabilities found")
        except asyncio.CancelledError:
            # raise CrawlerException(f"Crawler cancelled.")
            pass
        except Exception as e:
            raise CrawlerException("Unexpected Exception") from e
        finally:
            await self.clean()

    def start_validate(self):
        """Start validate"""
        if not self._validate:
            return
        logger.debug(f"Start validate...")
        self._event_loop = asyncio.new_event_loop()
        self.client = AsyncClient(verify=False, proxies=self.proxy)
        try:
            self._event_loop.run_until_complete(self.validate())
        except asyncio.CancelledError:
            pass  # ignore

    async def validate(self):
        """Validate the status of results that are marked as unknown"""

        async def fetch_task(url_node: URLNode) -> None:
            res = await self.fetch(url_node.url)
            logger.debug(f"Validate {url_node.url}: {res.status_code if res is not None else 'Unknown'}")
            url_node.response_status = str(res.status_code) if res is not None else url_node.response_status

        task_list: list[asyncio.Future] = list()

        for base, urls in self.url_dict.items():
            if not str(base.response_status).isdigit():
                task_list.append(asyncio.create_task(fetch_task(base)))
            for url in urls:
                if not str(url.response_status).isdigit():
                    task_list.append(asyncio.create_task(fetch_task(url)))

        for base, urls in self.js_dict.items():
            if not str(base.response_status).isdigit():
                task_list.append(asyncio.create_task(fetch_task(base)))

            for url in urls:
                if not str(url.response_status).isdigit():
                    task_list.append(asyncio.create_task(fetch_task(base)))
        for future in asyncio.as_completed(task_list):
            await future

    def is_evade(self, url: URLNode) -> bool:
        """Check whether url should be evaded"""
        if self.dangerous_paths is not None:
            path = url.url_object.path
            if len(
                [path for p in self.dangerous_paths if re.search(f"/?{p}", path.strip(), re.IGNORECASE)]
            ) > 0:
                return True
        return False

    async def process_one(self, url_node: URLNode):
        """Fetch, extract url children and execute handler on result"""
        if self.max_page_num > 0 and self.total_page >= self.max_page_num:
            return
        if self.is_evade(url_node):
            logger.debug(f"Evading {url_node}")
            return
        logger.debug(f"Processing {url_node.url}")
        self.total_page += 1
        response = await self.fetch(url_node.url)
        if response is not None:  # and response.status == 200
            url_node.response_status = str(response.status_code)
            url_node.title = get_response_title(response)
            try:
                url_node.content_length = int(response.headers.get('content-length'))
            except Exception:
                pass
            url_node.content_type = response.headers.get('content-type')
            response_text: str = response.text
            # try:
            #     response_text: str = await response.text(
            #         encoding="utf8", errors="ignore"
            #     )
            # except TimeoutError:
            #     logger.error(f"Timeout while reading response from {url_node.url}")
            #     return
            # call handler and urlparser
            # extract secrets TODO: nonblocking extract
            await self.extract_secrets(url_node, response_text)
            # extract API endpoints
            await self.extract_api_endpoints(url_node, response_text)
            # extract links TODO: nonblocking extract
            await self.extract_links_and_extend(url_node, response, response_text)
        else:
            # no extend on this branch
            logger.debug(f"No extend on {url_node.url}")
            return
        logger.debug(f"Finished processing {url_node.url}")

    async def extract_secrets(self, url_node: URLNode, response_text: str):
        """Extract secrets from response and store them in self.url_secrets"""
        logger.debug(f"Extracting secret from {url_node.url}")

        secrets = self.handler.handle(response_text)
        if secrets is not None:
            self.url_secrets[url_node] = set(secrets)
        logger.debug(f"Extract secret of number {len(list(secrets))} from {url_node}")

    async def extract_api_endpoints(self, url_node: URLNode, response_text: str):
        """Extract API endpoints from response and store them in self.api_endpoints"""
        if not self.api_detection_enabled and not self.idor_detection_enabled and not self.jwt_detection_enabled:
            return
        
        # 避免重复检测
        if hasattr(url_node, 'api_extracted') and url_node.api_extracted:
            return
        
        url_node.api_extracted = True
        logger.debug(f"Extracting API endpoints from {url_node.url}")

        # 从HTML内容中发现API端点
        html_endpoints = self.api_discovery.discover_from_crawler(url_node.url, response_text)
        self.api_endpoints.extend(html_endpoints)

        # 从Swagger文档中发现API端点（只在需要时进行）
        if self.api_discovery.swagger_cache:
            pass  # 已经检查过Swagger，跳过
        else:
            swagger_endpoints = self.api_discovery.discover_from_swagger(url_node.url)
            self.api_endpoints.extend(swagger_endpoints)

        logger.debug(f"Extracted {len(html_endpoints) + len(swagger_endpoints) if 'swagger_endpoints' in locals() else len(html_endpoints)} API endpoints from {url_node}")

    async def detect_auth_status(self):
        """对发现的API端点进行鉴权状态检测"""
        if not self.auth_detection_enabled or not self.api_endpoints:
            return

        logger.debug(f"Starting authentication detection for {len(self.api_endpoints)} API endpoints")

        # 去重，避免重复检测
        seen_urls = set()
        unique_endpoints = []
        for endpoint in self.api_endpoints:
            if endpoint['url'] not in seen_urls:
                seen_urls.add(endpoint['url'])
                unique_endpoints.append(endpoint)

        # 对每个端点进行鉴权检测
        for endpoint in unique_endpoints:
            try:
                auth_result = self.auth_detector.detect_auth_requirement(endpoint, self.auth_token)
                self.auth_results.append(auth_result)
                logger.debug(f"Auth detection for {endpoint['url']}: {auth_result['requires_auth']}")
            except Exception as e:
                logger.error(f"Error during auth detection for {endpoint['url']}: {e}")
                continue

        logger.debug(f"Completed authentication detection for {len(self.auth_results)} API endpoints")

    async def detect_idor_vulnerabilities(self):
        """对发现的API端点进行IDOR越权测试"""
        if not self.idor_detection_enabled or not self.api_endpoints:
            return

        logger.info(f"Starting IDOR detection for {len(self.api_endpoints)} API endpoints")

        # 去重，避免重复检测
        seen_urls = set()
        unique_endpoints = []
        for endpoint in self.api_endpoints:
            if endpoint['url'] not in seen_urls:
                seen_urls.add(endpoint['url'])
                unique_endpoints.append(endpoint)

        # 对每个端点进行IDOR测试
        for endpoint in unique_endpoints:
            try:
                idor_results = self.idor_detector.test_idor(endpoint, self.auth_token)
                self.idor_results.extend(idor_results)
                logger.info(f"IDOR detection for {endpoint['url']}: {len(idor_results)} vulnerabilities found")
            except Exception as e:
                logger.error(f"Error during IDOR detection for {endpoint['url']}: {e}")
                continue

        logger.info(f"Completed IDOR detection for {len(self.idor_results)} vulnerabilities")

    async def detect_jwt_bypass(self):
        """对发现的API端点进行JWT鉴权绕过检测"""
        if not self.jwt_detection_enabled or not self.api_endpoints:
            return

        logger.info(f"Starting JWT detection for {len(self.api_endpoints)} API endpoints")

        # 去重，避免重复检测
        seen_urls = set()
        unique_endpoints = []
        for endpoint in self.api_endpoints:
            if endpoint['url'] not in seen_urls:
                seen_urls.add(endpoint['url'])
                unique_endpoints.append(endpoint)

        # 对每个端点进行JWT测试
        for endpoint in unique_endpoints:
            try:
                jwt_results = self.jwt_detector.detect_jwt_bypass(endpoint, self.auth_token)
                self.jwt_results.extend(jwt_results)
                logger.info(f"JWT detection for {endpoint['url']}: {len(jwt_results)} vulnerabilities found")
            except Exception as e:
                logger.error(f"Error during JWT detection for {endpoint['url']}: {e}")
                continue

        logger.info(f"Completed JWT detection for {len(self.jwt_results)} vulnerabilities")

    def is_extend(self, response: httpx.Response) -> bool:
        """Determine if extract links from a url node"""
        is_text_like = False
        is_html = False
        try:
            content_type = response.headers['content-type']
        except KeyError:
            content_type = ""
        if content_type.startswith("text"):
            is_text_like = True
            if content_type.strip().startswith("text/html"):
                is_html = True
        elif content_type.startswith("application"):
            if content_type.endswith(
                "octet-stream"
            ) or content_type.endswith("pdf"):
                is_text_like = False
            else:
                is_text_like = True

        # if not is_text_like or not is_html:  # or not is_html just process html TODO: whether extend or not
        #     return False
        # if response.status_code != 200:  # just process normal response
        #     return False
        return True

    def is_append_js(self, url_node: URLNode) -> bool:
        """Determine whether append url to js result or not"""
        if url_node.url_object.path.endswith(".js") or url_node.url_object.path.endswith(
            ".js.map") or url_node.url_object.path.__contains__(".js?"):
            return True
        return False

    def is_append_url(self, url_node: URLNode) -> bool:
        """Determine whether append url to url result or not"""
        return True

    async def extract_links_and_extend(
        self, url_node: URLNode, response: httpx.Response, response_text: str
    ):
        """Extract links from response and extend the task queue in demand
        This function only works if the response is text-like, but regardless of whether it is html or not.
        Extract and extend `url_node` only if `response` is text-like.
        """
        if not self.is_extend(response):
            return

        # 检查是否为JavaScript文件，如果是则提取API端点
        if (self.api_detection_enabled or self.idor_detection_enabled or self.jwt_detection_enabled) and self.is_append_js(url_node):
            logger.debug(f"Processing JavaScript file: {url_node.url}")
            js_endpoints = self.api_discovery.discover_from_js(url_node.url, response_text)
            if js_endpoints:
                self.api_endpoints.extend(js_endpoints)
                logger.debug(f"Extracted {len(js_endpoints)} API endpoints from JavaScript file {url_node}")

        if self.max_depth <= 0 or url_node.depth + 1 <= self.max_depth:
            # avoid enqueue urls with excessive depth
            # for non-html response, just record, no visit
            is_extending = True
        else:
            is_extending = False

        logger.debug(f"Extracting links from {url_node.url}")
        url_children: typing.Set[URLNode] = self.parser.extract_urls(url_node, response_text)

        # 优化：批量处理子URL
        new_children = []
        js_children = []
        url_children_set = []

        for child in url_children:
            if child is not None and child not in self.visited_urls:
                self.found_urls.add(child)
                if is_extending and self.filter.doFilter(child.url_object):
                    new_children.append(child)
                    self.visited_urls.add(child)
                if self.is_append_js(child):
                    js_children.append(child)
                elif self.is_append_url(child):
                    url_children_set.append(child)
                logger.debug(f"New link found: {child.url} from {url_node.url}")

        # 批量添加到队列
        for child in new_children:
            self.working_queue.put(child)

        # 批量添加到字典
        if js_children:
            if url_node not in self.js_dict:
                self.js_dict[url_node] = set()
            self.js_dict[url_node].update(js_children)

        if url_children_set:
            if url_node not in self.url_dict:
                self.url_dict[url_node] = set()
            self.url_dict[url_node].update(url_children_set)

    # @aiocache.cached(ttl=5, key="http", namespace="fetch", serializer=PickleSerializer())
    async def fetch(self, url: str) -> httpx.Response:
        """Wrapper for sending http request
        If exception occurs, return None
        """
        cached_response = await self.cache.get(url)
        if cached_response is not None:
            logger.debug(f"Cache Match: {url}")
            return self.serializer.loads(cached_response)
        logger.debug(f"Fetching {url}")
        response = None
        try:
            # response = await self.client.get(
            #     url,
            #     allow_redirects=self.follow_redirects,
            #     headers=self.headers,
            #     proxy=self.proxy,
            #     verify_ssl=False,
            #     timeout=self.timeout,
            # )
            response = await self.client.get(
                url,
                headers=self.headers,
                follow_redirects=self.follow_redirects,
                timeout=self.timeout,
            )
            logger.debug(f"Fetch {url}, status: {response.status_code}")
            await self.cache.set(url, self.serializer.dumps(response), ttl=60)

        except TimeoutError:
            logger.error(f"Timeout while fetching {url}")
        except httpx.ConnectError as e:
            logger.error(f"Connection error for {url}: {e}")
        except anyio.ClosedResourceError as e:
            logger.error(f"Closing resource for {url}: {e}")
        except httpx.InvalidURL as e:
            logger.error(f"Invalid URL for {url}: {e}")
        except httpx.TimeoutException as e:
            logger.error(f"Timeout while fetching {url} ")
        except httpx.ReadError as e:
            logger.debug(f"Read error for {url}: {e}")  # trigger when keyboard interrupt
        except KeyboardInterrupt:
            pass  # ignore
        except Exception as e:
            logger.error(f"Unexpected error: {e.__class__}:{e} while fetching {url}")
        return response

    async def clean(self):
        """Close pool, cancel tasks, close http client session"""
        try:
            await self.client.aclose()
        except:
            pass  # ignore
        try:
            await self.pool.close()
        except:
            pass  # ignore
        if not self.close.is_set():
            self.close.set()
        logger.debug(f"Closing")

    async def consumer(self):
        """Consume the result of pool"""
        async for future in self.pool.iter():
            if future.done():
                logger.debug(f"Done task for {future}")
                result = future.result()
                if future.exception() is not None:
                    try:
                        raise CrawlerException(
                            future.exception()
                        ) from future.exception()
                    except Exception as e:
                        if self.verbose:
                            logger.error(e)
                            logger.error(traceback.format_exc())
                        else:
                            logger.error(e)
                if self.close.is_set():
                    logger.debug(f"Closing Consumer")
                    return

