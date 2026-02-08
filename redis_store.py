import json
from typing import List

import redis
from redis.exceptions import ConnectionError as RedisConnectionError

from config import REDIS_URL
from schemas import MessageContent
from memory import add_message as mem_add_message
from memory import get_history as mem_get_history
from memory import conversations as mem_conversations

_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)


def _key(session_id: str) -> str:
    return f"honeypot:history:{session_id}"

def _callback_key(session_id: str) -> str:
    return f"honeypot:callback_sent:{session_id}"


def get_history(session_id: str) -> List[MessageContent]:
    try:
        items = _client.lrange(_key(session_id), 0, -1)
        result: List[MessageContent] = []
        for raw in items:
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                continue
            try:
                result.append(MessageContent(**payload))
            except Exception:
                continue
        return result
    except RedisConnectionError:
        # Fallback to in-memory store if Redis is unavailable
        result: List[MessageContent] = []
        for msg in mem_get_history(session_id):
            if isinstance(msg, MessageContent):
                result.append(msg)
            elif isinstance(msg, dict):
                try:
                    result.append(MessageContent(**msg))
                except Exception:
                    continue
            else:
                result.append(MessageContent(sender="user", text=str(msg), timestamp=0))
        return result


def append_message(session_id: str, message: MessageContent) -> None:
    try:
        _client.rpush(_key(session_id), json.dumps(message.model_dump()))
    except RedisConnectionError:
        mem_add_message(session_id, message)


def set_history(session_id: str, messages: List[MessageContent]) -> None:
    try:
        key = _key(session_id)
        pipeline = _client.pipeline()
        pipeline.delete(key)
        if messages:
            pipeline.rpush(key, *[json.dumps(m.model_dump()) for m in messages])
        pipeline.execute()
    except RedisConnectionError:
        # Replace in-memory history
        mem_conversations[session_id]["history"] = list(messages)

def mark_callback_sent(session_id: str) -> bool:
    """
    Returns True if we just marked it, False if it was already marked.
    """
    try:
        return _client.setnx(_callback_key(session_id), "1")
    except RedisConnectionError:
        convo = mem_conversations[session_id]
        if convo.get("callback_sent"):
            return False
        convo["callback_sent"] = True
        return True

def callback_already_sent(session_id: str) -> bool:
    try:
        return _client.exists(_callback_key(session_id)) == 1
    except RedisConnectionError:
        return bool(mem_conversations[session_id].get("callback_sent"))

def redis_available() -> bool:
    try:
        return _client.ping()
    except RedisConnectionError:
        return False
