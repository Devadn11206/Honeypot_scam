import json
from typing import List

try:
    import redis  # type: ignore
    from redis.exceptions import ConnectionError as RedisConnectionError  # type: ignore
except Exception:  # pragma: no cover
    redis = None

    class RedisConnectionError(Exception):
        pass

from config import REDIS_URL
from schemas import MessageContent
from memory import add_message as mem_add_message
from memory import get_history as mem_get_history
from memory import conversations as mem_conversations

_client = (
    redis.Redis.from_url(REDIS_URL, decode_responses=True) if redis is not None else None
)


def _key(session_id: str) -> str:
    return f"honeypot:history:{session_id}"

def _callback_key(session_id: str) -> str:
    return f"honeypot:callback_sent:{session_id}"


def get_history(session_id: str) -> List[MessageContent]:
    if _client is None:
        items: List[MessageContent] = []
        for msg in mem_get_history(session_id):
            if isinstance(msg, MessageContent):
                items.append(msg)
            elif isinstance(msg, dict):
                try:
                    items.append(MessageContent(**msg))
                except Exception:
                    continue
            else:
                items.append(MessageContent(sender="user", text=str(msg), timestamp=0))
        return items
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
    if _client is None:
        mem_add_message(session_id, message)
        return
    try:
        _client.rpush(_key(session_id), json.dumps(message.model_dump()))
    except RedisConnectionError:
        mem_add_message(session_id, message)


def set_history(session_id: str, messages: List[MessageContent]) -> None:
    if _client is None:
        mem_conversations[session_id]["history"] = list(messages)
        return
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
    if _client is None:
        convo = mem_conversations[session_id]
        if convo.get("callback_sent"):
            return False
        convo["callback_sent"] = True
        return True
    try:
        return bool(_client.setnx(_callback_key(session_id), "1"))
    except RedisConnectionError:
        convo = mem_conversations[session_id]
        if convo.get("callback_sent"):
            return False
        convo["callback_sent"] = True
        return True

def callback_already_sent(session_id: str) -> bool:
    if _client is None:
        return bool(mem_conversations[session_id].get("callback_sent"))
    try:
        return _client.exists(_callback_key(session_id)) == 1
    except RedisConnectionError:
        return bool(mem_conversations[session_id].get("callback_sent"))

def redis_available() -> bool:
    if _client is None:
        return False
    try:
        return _client.ping()
    except RedisConnectionError:
        return False
