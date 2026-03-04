from fastapi import FastAPI, Request, HTTPException
from starlette.responses import Response
from typing import Literal, Dict
from pydantic import BaseModel
import requests_go as requests
from requests_go.tls_config import TLS_CHROME_LATEST
from compression import zstd
from requests.cookies import RequestsCookieJar
import os
import logging
import time
from datetime import datetime, timezone

session = requests.Session()
session.tls_config = TLS_CHROME_LATEST
session.headers = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
    "Connection": "keep-alive",
    "cache-control": "max-age=0",
    "dnt": "1",
    "upgrade-insecure-requests": "1",
    "sec-fetch-site": "none",
    "sec-fetch-mode": "navigate",
    "sec-fetch-user": "?1",
    "sec-fetch-dest": "document",
    "sec-ch-ua": '"Not(A:Brand";v="8", "Chromium";v="142"',
    "sec-ch-ua-mobile": "?0",
    "Sec-ch-ua-platform": '"Linux"',
    "origin": "https://www.linovelib.com",
    "referer": "https://www.linovelib.com/",
}

session.proxies = {
    "http": os.getenv("HTTP_PROXY", ""),
    "https": os.getenv("HTTPS_PROXY", ""),
}

flaresolverr_url = os.getenv("FLARESOLVERR_URL", "http://localhost:8191/v1")

cookie_cache = RequestsCookieJar()

flaresolverr_session_initialized = False


def fetch_cf_clearance():
    global flaresolverr_session_initialized, cookie_cache, flaresolverr_url
    if not flaresolverr_session_initialized:
        session_list_res = requests.post(
            flaresolverr_url,
            json={
                "cmd": "sessions.list",
            },
        )
        session_list: list = session_list_res.json()["sessions"]
        if "ldsa_session" not in session_list:
            requests.post(
                flaresolverr_url,
                json={"cmd": "sessions.create", "session": "ldsa_session"},
            )
        else:
            flaresolverr_session_initialized = True
    res = requests.post(
        flaresolverr_url,
        json={
            "cmd": "request.get",
            "url": "https://www.linovelib.com/S6",
            "maxTimeout": 60000,
            "session": "ldsa_session",
        },
    )
    resObj = res.json()
    if resObj["status"] == "ok":
        cookies = resObj["solution"]["cookies"]
        for cookie in cookies:
            if cookie["name"] == "cf_clearance":
                cookie_cache.set(cookie["name"], cookie["value"])
    else:
        raise Exception("Failed to solve Cloudflare challenge")


session.get("https://www.linovelib.com/")


class MakeRequestModel(BaseModel):
    url: str
    method: Literal["GET", "POST"] = "GET"
    data: str | None = None
    cookies: Dict[str, str] | None = None


class MakeRequestResponseModel(BaseModel):
    content: str


app = FastAPI()

# 设置基础日志配置
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("access")


@app.middleware("http")
async def combined_log_format(request: Request, call_next):
    # 记录开始时间（用于计算处理时长，可选）
    start_time = time.time()

    response = await call_next(request)

    # --- 修复时间格式的部分 ---
    # 获取本地时间，并自动附加时区信息（如 +0800）
    now = datetime.now().astimezone()
    # 格式化为 Apache 标准：[22/Jan/2026:10:00:00 +0800]
    timestamp = now.strftime("%d/%b/%Y:%H:%M:%S %z")
    # -----------------------

    client_host = request.client.host if request.client else "-"
    method = request.method
    uri = request.url.path
    if request.url.query:
        uri += f"?{request.url.query}"

    protocol = f"HTTP/{request.scope.get('http_version', '1.1')}"
    status_code = response.status_code
    res_size = response.headers.get("content-length", "0")
    referer = request.headers.get("referer", "-")
    user_agent = request.headers.get("user-agent", "-")

    log_message = (
        f"{client_host} - - [{timestamp}] "
        f'"{method} {uri} {protocol}" {status_code} {res_size} '
        f'"{referer}" "{user_agent}"'
    )

    logger.info(log_message)
    return response


def response_is_textual(content_type: str) -> bool:
    textual_types = [
        "text/",
        "application/json",
        "application/xml",
        "application/xhtml+xml",
    ]
    return any(content_type.startswith(t) for t in textual_types)


def _do_request(req: MakeRequestModel) -> requests.Response:
    global cookie_cache
    if req.cookies:
        for key, value in req.cookies.items():
            cookie_cache.set(key, value)

    if req.method == "GET":
        res = session.get(req.url, cookies=cookie_cache)
        if res.status_code == 403:
            fetch_cf_clearance()
            res = session.get(req.url, cookies=cookie_cache)
    else:
        data = req.data or ""
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(data)),
        }
        res = session.post(req.url, data=data, cookies=cookie_cache, headers=headers)
        if res.status_code == 403:
            fetch_cf_clearance()
            res = session.post(
                req.url, data=data, cookies=cookie_cache, headers=headers
            )

    return res


@app.post("/request")
async def create_request(request: MakeRequestModel) -> MakeRequestResponseModel:
    res = _do_request(request)

    if response_is_textual(res.headers.get("Content-Type", "")):
        if res.headers.get("Content-Encoding") == "zstd":
            decompressed_content = zstd.decompress(res.content).decode("utf-8")
            return MakeRequestResponseModel(content=decompressed_content)
        else:
            return MakeRequestResponseModel(content=res.content.decode("utf-8"))

    raise HTTPException(
        status_code=500,
        detail="Non-textual response is not supported in /request, use /request-binary",
    )


@app.post("/request-binary")
async def create_request_binary(request: MakeRequestModel) -> Response:
    try:
        res = _do_request(request)
        original_content_type = res.headers.get(
            "Content-Type", "application/octet-stream"
        )

        if res.headers.get("Content-Encoding") == "zstd":
            raw_content = zstd.decompress(res.content)
        else:
            raw_content = res.content

        return Response(
            content=raw_content,
            media_type=original_content_type,
            headers={"X-Original-Content-Type": original_content_type},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"/request-binary failed: {str(e)}")
