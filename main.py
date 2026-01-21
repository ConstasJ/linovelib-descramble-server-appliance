from fastapi import FastAPI
from typing import Literal, Dict
from pydantic import BaseModel
import requests_go as requests
from requests_go.tls_config import TLS_CHROME_LATEST
from compression import zstd
from requests.cookies import RequestsCookieJar
import os

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
    "http": "http://127.0.0.1:9000",
    "https": "http://127.0.0.1:9000",
}

flaresolverr_url = os.getenv("FLARESOLVERR_URL", "http://localhost:8191/v1")

cookie_cache = RequestsCookieJar()

flaresolverr_session_initialized = False

def fetch_cf_clearance():
    global flaresolverr_session_initialized, cookie_cache, flaresolverr_url
    if not flaresolverr_session_initialized:
        session_list_res = requests.post(flaresolverr_url, json={
            "cmd": "sessions.list",
        })
        session_list: list = session_list_res.json()["sessions"]
        if "ldsa_session" not in session_list:
            requests.post(flaresolverr_url, json={
                "cmd": "sessions.create",
                "session": "ldsa_session"
            })
        else:
            flaresolverr_session_initialized = True
    res = requests.post(flaresolverr_url, json={
        "cmd": "request.get",
        "url": "https://www.linovelib.com/S6",
        "maxTimeout": 60000,
        "session": "ldsa_session"
    })
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

@app.post("/request")
async def create_request(request: MakeRequestModel) -> MakeRequestResponseModel: 
    global cookie_cache
    if request.cookies:
        for key, value in request.cookies.items():
            cookie_cache.set(key, value)
    if request.method == "GET":
        res = session.get(request.url, cookies=cookie_cache)
        if res.status_code == 403:
            fetch_cf_clearance()
            res = session.get(request.url, cookies=cookie_cache)
    else:
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(request.data))
        }
        res = session.post(request.url, data=request.data, cookies=cookie_cache, headers=headers)
        if res.status_code == 403:
            fetch_cf_clearance()
            res = session.post(request.url, data=request.data, cookies=cookie_cache, headers=headers)
    if res.headers.get("Content-Encoding") == "zstd":
        decompressed_content = zstd.decompress(res.content).decode("utf-8")
        return MakeRequestResponseModel(content=decompressed_content)
    else:
        return MakeRequestResponseModel(content=res.content.decode("utf-8"))