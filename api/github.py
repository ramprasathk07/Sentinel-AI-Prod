"""
GitHub App API Client

Handles JWT minting, installation tokens, fetching PR diffs, and posting
comments back to the GitHub PR.
"""

import hmac
import time
import asyncio
from typing import Optional, Dict
from collections import deque

import httpx
import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from core.config import settings
from utils.logger import logger


class RateLimitExceeded(Exception):
    """Raised when GitHub API rate limit bucket is exhausted."""
    pass


class RateLimiter:
    """A simple token bucket / sliding window rate limiter (50 req/min)."""
    def __init__(self, max_requests: int = 50, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.request_timestamps = deque()
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = time.time()
            # Remove timestamps older than the window
            while self.request_timestamps and now - self.request_timestamps[0] > self.window_seconds:
                self.request_timestamps.popleft()
            
            if len(self.request_timestamps) >= self.max_requests:
                logger.warning(f"Rate limit exceeded: {self.max_requests} reqs in {self.window_seconds}s")
                raise RateLimitExceeded("GitHub API rate limit budget exhausted.")
                
            self.request_timestamps.append(now)

# Global rate limiter (50 requests per minute)
github_rate_limiter = RateLimiter(max_requests=50, window_seconds=60)


def verify_signature(payload_body: bytes, signature_header: str) -> bool:
    """Verify the X-Hub-Signature-256 header sent by GitHub."""
    if not signature_header or not settings.GITHUB_WEBHOOK_SECRET:
        return False
        
    expected_signature = "sha256=" + hmac.new(
        settings.GITHUB_WEBHOOK_SECRET.encode("utf-8"),
        payload_body,
        digestmod="sha256"
    ).hexdigest()
    
    return hmac.compare_digest(expected_signature, signature_header)


def generate_jwt() -> str:
    """Mint a short-lived JWT using the GitHub App's private key."""
    if not settings.GITHUB_PRIVATE_KEY_PATH or not settings.GITHUB_APP_ID:
        raise ValueError("GitHub App configuration missing.")
        
    with open(settings.GITHUB_PRIVATE_KEY_PATH, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )
        
    now = int(time.time())
    payload = {
        "iat": now - 60,
        "exp": now + (10 * 60), # 10 minutes max
        "iss": settings.GITHUB_APP_ID,
    }
    
    encoded_jwt = jwt.encode(payload, private_key, algorithm="RS256")
    return encoded_jwt


async def get_installation_token(installation_id: int) -> str:
    """Exchange the JWT for an installation access token."""
    await github_rate_limiter.acquire()
    app_jwt = generate_jwt()
    headers = {
        "Authorization": f"Bearer {app_jwt}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    async with httpx.AsyncClient(timeout=10.0) as client:
        url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
        resp = await client.post(url, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        return data["token"]


async def fetch_pr_diff(repo_full_name: str, pr_number: int, token: str) -> Optional[str]:
    """Fetch the raw diff of the pull request."""
    await github_rate_limiter.acquire()
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3.diff"
    }
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        url = f"https://api.github.com/repos/{repo_full_name}/pulls/{pr_number}"
        resp = await client.get(url, headers=headers)
        if resp.status_code == 200:
            return resp.text
        logger.error(f"Failed to fetch PR diff: {resp.status_code}")
        return None


async def get_lockfiles(repo_full_name: str, ref: str, token: str) -> Dict[str, str]:
    """
    Fetch content of common lockfiles from the repository at a specific ref (commit/branch).
    Returns a dict mapping filename -> content.
    """
    lockfile_names = ["package-lock.json", "requirements.txt", "Cargo.lock", "go.sum"]
    found_files = {}
    
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3.raw"
    }
    
    async with httpx.AsyncClient(timeout=10.0) as client:
        for filename in lockfile_names:
            await github_rate_limiter.acquire()
            url = f"https://api.github.com/repos/{repo_full_name}/contents/{filename}?ref={ref}"
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                found_files[filename] = resp.text
            elif resp.status_code == 404:
                continue # Lockfile not present
            else:
                logger.warning(f"Failed to fetch {filename}: {resp.status_code}")
                
    return found_files


async def post_pr_comment(repo_full_name: str, pr_number: int, comment_body: str, token: str) -> bool:
    """Post a structured comment back to the GitHub PR."""
    await github_rate_limiter.acquire()
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    payload = {"body": comment_body}
    
    async with httpx.AsyncClient(timeout=20.0) as client:
        url = f"https://api.github.com/repos/{repo_full_name}/issues/{pr_number}/comments"
        resp = await client.post(url, headers=headers, json=payload)
        if resp.status_code == 201:
            logger.info(f"Successfully posted comment on PR #{pr_number}")
            return True
        logger.error(f"Failed to post comment: {resp.status_code} - {resp.text}")
        return False


async def list_pr_comments(repo_full_name: str, pr_number: int, token: str) -> list:
    """List all issue comments on a PR. Returns list of {id, body, user}."""
    await github_rate_limiter.acquire()
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }
    async with httpx.AsyncClient(timeout=15.0) as client:
        url = f"https://api.github.com/repos/{repo_full_name}/issues/{pr_number}/comments"
        resp = await client.get(url, headers=headers, params={"per_page": 100})
        if resp.status_code == 200:
            return resp.json()
        logger.error(f"list_pr_comments failed: {resp.status_code}")
        return []


async def update_pr_comment(repo_full_name: str, comment_id: int, body: str, token: str) -> bool:
    """Update an existing issue comment body."""
    await github_rate_limiter.acquire()
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }
    async with httpx.AsyncClient(timeout=15.0) as client:
        url = f"https://api.github.com/repos/{repo_full_name}/issues/comments/{comment_id}"
        resp = await client.patch(url, headers=headers, json={"body": body})
        if resp.status_code == 200:
            logger.info(f"Updated comment {comment_id} on {repo_full_name}")
            return True
        logger.error(f"update_pr_comment failed: {resp.status_code} {resp.text[:200]}")
        return False


async def upsert_pr_comment(
    repo_full_name: str,
    pr_number: int,
    body: str,
    marker: str,
    token: str,
) -> bool:
    """
    Update an existing comment containing `marker`, or create a new one.

    `marker` is a hidden HTML comment like `<!-- sentinel-ai:scan-id=XYZ -->`.
    Returns True on success.
    """
    comments = await list_pr_comments(repo_full_name, pr_number, token)
    for c in comments:
        if marker in (c.get("body") or ""):
            return await update_pr_comment(repo_full_name, c["id"], body, token)
    return await post_pr_comment(repo_full_name, pr_number, body, token)
