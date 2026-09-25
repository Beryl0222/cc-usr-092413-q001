"""追加式事件账本。

所有业务事实都以不可变事件写入 JSONL 账本，重放得到当前状态。
内容删除、账号改名、授权撤回都只能追加新事件，不能覆盖或删除旧事件，
因此责任链始终可还原。
"""

import json
import os
import threading
import uuid
from contextlib import contextmanager


def new_id(prefix):
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class EventStore:
    """线程安全的追加式账本；path 为 None 时仅驻留内存（测试用）。"""

    def __init__(self, path=None):
        self.path = path
        self._lock = threading.RLock()
        self._listeners = []
        self.events = []
        if path:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as handle:
                    for line in handle:
                        line = line.strip()
                        if line:
                            self.events.append(json.loads(line))

    def subscribe(self, listener):
        with self._lock:
            self._listeners.append(listener)

    @contextmanager
    def transaction(self):
        """串行化"读取投影→决定→追加事件"的业务临界区。

        合并与回调并发时只能形成一个可解释顺序：后进入者一定看到先进入者
        已落账的合并结果，从而把事实写到唯一主案件。可重入（RLock），
        因此临界区内调用 append/事务嵌套都是安全的。
        """
        self._lock.acquire()
        try:
            yield
        finally:
            self._lock.release()

    def append(self, event_type, payload, event_id=None):
        """追加事件。event_id 已存在时返回既有事件（账本层幂等）。"""
        with self._lock:
            if event_id:
                for existing in self.events:
                    if existing["event_id"] == event_id:
                        return existing, True
            event = {
                "event_id": event_id or new_id("evt"),
                "seq": len(self.events) + 1,
                "type": event_type,
                "payload": payload,
            }
            self.events.append(event)
            if self.path:
                with open(self.path, "a", encoding="utf-8") as handle:
                    handle.write(json.dumps(event, ensure_ascii=False) + "\n")
            for listener in list(self._listeners):
                listener(event)
            return event, False

    def append_many(self, items):
        """原子批量追加：一次加锁、一次文件写入、随后统一触发投影。

        items 为 (event_type, payload) 序列。用于"一次回调=多条事实"的提交，
        保证业务上要么全部可见、要么都不可见，不产生部分写入。
        """
        with self._lock:
            built = [{
                "event_id": new_id("evt"),
                "seq": len(self.events) + index + 1,
                "type": event_type,
                "payload": payload,
            } for index, (event_type, payload) in enumerate(items)]
            self.events.extend(built)
            if self.path:
                with open(self.path, "a", encoding="utf-8") as handle:
                    handle.write("".join(json.dumps(e, ensure_ascii=False) + "\n" for e in built))
            for event in built:
                for listener in list(self._listeners):
                    listener(event)
            return built

    def replay(self):
        with self._lock:
            return list(self.events)
