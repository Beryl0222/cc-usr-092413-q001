"""网络侵害事件受理与协同处置的业务核心。

设计要点：
- 所有事实以不可变事件落账（见 store.py），删除、改名、补充、撤回只追加记录；
- 普通批评只登记线索、不立事件；直接人身威胁自动按值班规则升级且只通知一次；
- 聚类只产生合并建议，须保护专员人工确认；
- 报案/平台投诉/公开澄清按职责分离提交、分角色复核，禁止自复核；
- 平台回调按 callback_id 幂等：重复回调返回首次结果，同键不同内容保留首次结果
  并明确报冲突；命中已合并子案件时一律归并到唯一主案件，事实原子记入主链并
  保留原始命中来源，旧子案件不再发生业务变更，也绝不另立案件；
- 申诉期间限制敏感材料扩散并阻断对外动作；授权撤回不抹除责任链。
"""

import hashlib
import json
import threading
from datetime import datetime, timezone, timedelta

from domain import load_config
from store import EventStore, new_id

CST = timezone(timedelta(hours=8))

# 仅供联调的威胁线索提示词：最终等级仍以提交人填报、保护专员确认为准
_THREAT_HINTS = ("弄死", "杀死", "砍死", "打死", "别想走", "等着", "上门", "堵你", "炸死", "废了你")
_CRITICISM_HINTS = ("发挥", "状态", "战术", "换人", "表现", "踢得", "输球")


def now_iso():
    return datetime.now(CST).isoformat(timespec="seconds")


def content_hash(raw_excerpt):
    return hashlib.sha256((raw_excerpt or "").encode("utf-8")).hexdigest()


def callback_fingerprint(payload):
    """回调内容指纹：同一 callback_id 再次到达时用于识别内容是否变化。"""
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def suggest_severity(text):
    """联调用启发式：根据文本给严重度建议，不替代人工判定。"""
    if not text:
        return None
    if any(hint in text for hint in _THREAT_HINTS):
        return "direct_threat"
    if any(hint in text for hint in _CRITICISM_HINTS):
        return "criticism"
    return "abuse"


class AppError(ValueError):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def _require(actor, allowed_roles):
    if not actor or "role" not in actor:
        raise AppError("缺少操作人信息 actor(name, role)")
    if actor["role"] not in allowed_roles:
        raise AppError(f"角色 {actor['role']} 无权执行该操作，允许角色：{'、'.join(allowed_roles)}", 403)


class SafeguardingApp:
    SUBMIT_ROLES = ("当事人代理", "俱乐部保护专员")

    def __init__(self, config=None, store_path=None):
        self.config = config or load_config()
        self.store = EventStore(store_path)
        self.reports = {}            # report_no -> 线索记录
        self.incidents = {}          # incident_id -> 事件投影
        self.actions = {}            # action_id -> 动作记录
        self.suggestions = {}        # suggestion_id -> 合并建议
        self.callbacks = {}          # callback_id -> 首次处理结果
        self.notifications = []      # 通知外发箱（抽象渠道）
        self._suggestion_keys = set()
        # 串行化合并、关闭与平台回调：并发时只形成一个可解释顺序
        self._lock = threading.RLock()
        self._replay()
        self.store.subscribe(self._apply)

    # ------------------------------------------------------------------ 重放
    def _replay(self):
        for event in self.store.replay():
            self._apply(event)

    def _append(self, event_type, payload, event_id=None):
        event, _duplicate = self.store.append(event_type, payload, event_id=event_id)
        return event

    def _apply(self, event):
        handler = getattr(self, f"_on_{event['type']}", None)
        if handler:
            handler(event["payload"])

    # ---------------------------------------------------------- 线索报送/立案
    def submit_report(self, payload, actor):
        _require(actor, self.SUBMIT_ROLES)
        severity = payload.get("severity")
        if not self.config.is_valid_severity(severity):
            raise AppError(f"未知严重度：{severity}")
        platform = payload.get("platform")
        if platform and platform not in self.config.platforms:
            raise AppError(f"未知平台：{platform}")
        if not payload.get("content_url"):
            raise AppError("线索必须包含受控引用 content_url")
        victim = payload.get("victim_code")
        if not victim:
            raise AppError("线索必须包含受侵害当事人 victim_code")

        report_no = new_id("rpt")
        raw = payload.get("raw_excerpt") or ""
        sha = content_hash(raw)
        scopes = payload.get("授权范围")
        if scopes is None:
            scopes = self.config.default_scopes
        unknown_scopes = set(scopes) - set(self.config.scopes)
        if unknown_scopes:
            raise AppError(f"未知授权范围：{sorted(unknown_scopes)}")

        report = {
            "report_no": report_no,
            "submitted_by": actor.get("name"),
            "submitter_role": actor["role"],
            "victim_code": victim,
            "platform": platform,
            "content_url": payload["content_url"],
            "content_sha256": sha,
            "severity": severity,
            "linked_accounts": payload.get("linked_accounts", []),
            "receipts": payload.get("receipts", []),
            "received_at": now_iso(),
            "decision": None,
            "incident_id": None,
        }
        self._append("report_received", {
            "report_no": report_no,
            "submitted_by": actor.get("name"),
            "submitter_role": actor["role"],
            "victim_code": victim,
            "platform": platform,
            "content_url": payload["content_url"],
            "content_sha256": sha,
            "severity": severity,
            "linked_accounts": payload.get("linked_accounts", []),
            "received_at": report["received_at"],
        })
        self.reports[report_no] = report

        # 普通批评：只登记观察，不立为保护事件，避免把批评误当网暴进入处置流程
        if not self.config.is_openable_severity(severity):
            report["decision"] = "不立案：普通批评，登记观察"
            self._append("report_screened", {
                "report_no": report_no, "decision": report["decision"], "at": now_iso(),
            })
            return {"report_no": report_no, "incident_id": None, "decision": report["decision"]}

        incident_id = self._open_incident(report, scopes)
        report["incident_id"] = incident_id
        return {"report_no": report_no, "incident_id": incident_id, "decision": "已立案"}

    def _open_incident(self, report, scopes):
        incident_id = new_id("inc")
        at = now_iso()
        self._append("incident_opened", {
            "incident_id": incident_id,
            "report_no": report["report_no"],
            "victim_code": report["victim_code"],
            "platform": report["platform"],
            "severity": report["severity"],
            "opened_at": at,
        })
        self._append("consent_granted", {
            "incident_id": incident_id, "scopes": scopes,
            "by": report["submitted_by"], "at": at,
        })
        self._append("evidence_registered", {
            "incident_id": incident_id,
            "evidence_id": new_id("ev"),
            "kind": "url",
            "content_ref": report["content_url"],
            "content_sha256": report["content_sha256"],
            "state": "online",
            "submitted_by": report["submitted_by"],
            "at": at,
            "note": "立案线索的受控引用",
        })
        for account in report["linked_accounts"]:
            self._append("account_linked", {
                "incident_id": incident_id,
                "link_id": new_id("acct"),
                "platform": account.get("platform"),
                "account_key": account.get("account_key"),
                "url": account.get("url"),
                "display_name": account.get("display_name"),
                "at": at,
            })
        for receipt in report["receipts"]:
            self._append("receipt_recorded", {
                "incident_id": incident_id,
                "receipt_id": receipt.get("receipt_id"),
                "platform": receipt.get("platform", report["platform"]),
                "status": receipt.get("status"),
                "reported_at": receipt.get("reported_at"),
                "via": "report",
                "at": now_iso(),
            })

        incident = self.incidents[incident_id]
        if self.config.should_escalate(report["severity"]):
            self._raise_escalation(incident_id, "立案等级为直接人身威胁，按值班规则自动升级")
        self._suggest_clusters_for(incident)
        return incident_id

    # ------------------------------------------------------------- 事件投影
    def _on_report_received(self, p):
        # submit_report 直接持有 report 对象；重放时重建
        if p["report_no"] not in self.reports:
            self.reports[p["report_no"]] = {
                "report_no": p["report_no"], "submitted_by": p["submitted_by"],
                "submitter_role": p["submitter_role"], "victim_code": p["victim_code"],
                "platform": p["platform"], "content_url": p["content_url"],
                "content_sha256": p["content_sha256"], "severity": p["severity"],
                "linked_accounts": p.get("linked_accounts", []), "receipts": [],
                "received_at": p["received_at"], "decision": None, "incident_id": None,
            }

    def _on_report_screened(self, p):
        report = self.reports.get(p["report_no"])
        if report:
            report["decision"] = p["decision"]

    def _on_incident_opened(self, p):
        self.incidents[p["incident_id"]] = {
            "incident_id": p["incident_id"],
            "report_nos": [p["report_no"]],
            "victim_code": p["victim_code"],
            "platform": p["platform"],
            "severity": p["severity"],
            "opened_at": p["opened_at"],
            "closed_at": None,
            "close_reason": None,
            "consent_scopes": [],
            "evidence": [],
            "accounts": [],
            "receipts": [],
            "actions": [],
            "escalation": None,
            "appeal": None,
            "merged_into": None,
            "absorbed": [],
            "false_report_upheld": False,
        }
        report = self.reports.get(p["report_no"])
        if report is not None and report.get("incident_id") is None:
            report["incident_id"] = p["incident_id"]
            report["decision"] = "已立案"

    def _on_consent_granted(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc:
            for scope in p["scopes"]:
                if scope not in inc["consent_scopes"]:
                    inc["consent_scopes"].append(scope)

    def _on_consent_revoked(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc:
            inc["consent_scopes"] = [s for s in inc["consent_scopes"] if s not in p["scopes"]]

    def _on_evidence_registered(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc:
            inc["evidence"].append({
                "evidence_id": p["evidence_id"], "kind": p["kind"],
                "content_ref": p["content_ref"], "content_sha256": p["content_sha256"],
                "state": p.get("state", "online"), "submitted_by": p.get("submitted_by"),
                "at": p["at"], "note": p.get("note", ""),
            })

    def _on_evidence_supplemented(self, p):
        self._on_evidence_registered(p)

    def _on_content_state_changed(self, p):
        inc = self.incidents.get(p["incident_id"])
        if not inc:
            return
        # 删除状态可能指向被吸收子案件的证据：在整个合并组内定位
        for member in self._merge_group(inc):
            for ev in member["evidence"]:
                if ev["evidence_id"] == p["evidence_id"]:
                    ev["state"] = p["new_state"]

    def _on_account_linked(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc:
            inc["accounts"].append({
                "link_id": p["link_id"], "platform": p["platform"],
                "account_key": p["account_key"], "url": p.get("url"),
                "display_name": p.get("display_name"),
                "name_history": ([{"name": p.get("display_name"), "at": p["at"]}]
                                 if p.get("display_name") else []),
            })

    def _on_account_renamed(self, p):
        inc = self.incidents.get(p["incident_id"])
        if not inc:
            return
        # 改名事实记在主链，但账号引用可能落在被吸收子案件：合并组内同步更新
        for member in self._merge_group(inc):
            for acct in member["accounts"]:
                if acct["platform"] == p["platform"] and acct["account_key"] == p["account_key"]:
                    acct["name_history"].append({"name": p["new_name"], "at": p["at"]})
                    acct["display_name"] = p["new_name"]

    def _record_receipt(self, inc, receipt):
        """回执按 receipt_id 在合并组内去重后落到指定案件：同一回执的最新状态只保留一份。"""
        receipt_id = receipt.get("receipt_id")
        for member in self._merge_group(inc):
            member["receipts"] = [r for r in member["receipts"] if r["receipt_id"] != receipt_id]
        inc["receipts"].append(receipt)

    def _on_receipt_recorded(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc:
            self._record_receipt(inc, {
                "receipt_id": p["receipt_id"], "platform": p["platform"],
                "status": p["status"], "reported_at": p.get("reported_at"),
                "via": p.get("via", "callback"), "at": p["at"],
            })

    def _on_escalation_raised(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc:
            inc["escalation"] = {
                "escalation_id": p["escalation_id"], "reason": p["reason"],
                "raised_at": p["at"], "status": "open",
                "last_confirmed_at": p["at"], "acknowledged_at": None,
                "acknowledged_by": None,
            }

    def _on_escalation_confirmed(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc and inc["escalation"]:
            inc["escalation"]["last_confirmed_at"] = p["at"]

    def _on_escalation_acknowledged(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc and inc["escalation"]:
            inc["escalation"]["status"] = "acknowledged"
            inc["escalation"]["acknowledged_at"] = p["at"]
            inc["escalation"]["acknowledged_by"] = p["by"]

    def _on_severity_confirmed(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc:
            inc["severity"] = p["severity"]

    def _on_merge_suggested(self, p):
        sugg = {
            "suggestion_id": p["suggestion_id"], "incident_ids": list(p["incident_ids"]),
            "reason": p["reason"], "status": "open",
            "created_at": p["created_at"], "resolved_by": None, "resolved_at": None,
            "merged_into": None,
        }
        self.suggestions[p["suggestion_id"]] = sugg
        self._suggestion_keys.add(self._pair_key(p["incident_ids"]))

    def _on_suggestion_resolved(self, p):
        sugg = self.suggestions.get(p["suggestion_id"])
        if sugg:
            sugg["status"] = p["decision"]
            sugg["resolved_by"] = p["by"]
            sugg["resolved_at"] = p["at"]
            sugg["merged_into"] = p.get("merged_into")

    def _on_incidents_merged(self, p):
        survivor = self.incidents.get(p["survivor_id"])
        absorbed = self.incidents.get(p["merged_id"])
        if survivor and absorbed:
            survivor["absorbed"].append(p["merged_id"])
            absorbed["merged_into"] = p["survivor_id"]

    def _on_appeal_opened(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc:
            inc["appeal"] = {"reason": p["reason"], "opened_by": p["by"],
                             "opened_at": p["at"], "status": "open",
                             "resolved_at": None, "decision": None}

    def _on_appeal_resolved(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc and inc["appeal"]:
            inc["appeal"]["status"] = "resolved"
            inc["appeal"]["decision"] = p["decision"]
            inc["appeal"]["resolved_at"] = p["at"]
            if p["decision"] == "upheld":
                inc["false_report_upheld"] = True

    def _on_incident_closed(self, p):
        inc = self.incidents.get(p["incident_id"])
        if inc:
            inc["closed_at"] = p["at"]
            inc["close_reason"] = p["reason"]

    def _on_action_proposed(self, p):
        self.actions[p["action_id"]] = {
            "action_id": p["action_id"], "incident_id": p["incident_id"],
            "action_type": p["action_type"], "params": p.get("params", {}),
            "proposed_by": p["proposed_by"], "proposed_by_role": p["proposed_by_role"],
            "required_reviewer_role": p["required_reviewer_role"],
            "required_scopes": p.get("required_scopes", []),
            "status": "pending", "reviewer": None, "reviewer_role": None,
            "review_reason": None, "reviewed_at": None,
            "executed_at": None, "result": None, "proposed_at": p["at"],
        }
        inc = self.incidents.get(p["incident_id"])
        if inc:
            inc["actions"].append(p["action_id"])

    def _on_action_reviewed(self, p):
        action = self.actions.get(p["action_id"])
        if action:
            action["status"] = "approved" if p["decision"] == "approve" else "rejected"
            action["reviewer"] = p["reviewer"]
            action["reviewer_role"] = p["reviewer_role"]
            action["review_reason"] = p.get("reason")
            action["reviewed_at"] = p["at"]

    def _on_action_executed(self, p):
        action = self.actions.get(p["action_id"])
        if action:
            action["status"] = "executed"
            action["executed_at"] = p["at"]
            action["result"] = p.get("result", {})
            if p.get("receipt"):
                inc = self.incidents.get(action["incident_id"])
                if inc:
                    self._record_receipt(inc, {"via": "action", "at": p["at"], **p["receipt"]})

    def _on_notification_sent(self, p):
        self.notifications.append(p)

    def _on_callback_processed(self, p):
        if p["callback_id"] not in self.callbacks:
            stored = dict(p["result"])
            if p.get("request_hash") is not None:
                stored["request_hash"] = p["request_hash"]
            self.callbacks[p["callback_id"]] = stored

    # ------------------------------------------------------------- 严重度确认
    def confirm_severity(self, incident_id, severity, actor):
        _require(actor, ("俱乐部保护专员", "俱乐部值班主管"))
        inc = self._get_open_incident(incident_id)
        if not self.config.is_valid_severity(severity):
            raise AppError(f"未知严重度：{severity}")
        self._append("severity_confirmed", {
            "incident_id": incident_id, "severity": severity,
            "by": actor.get("name"), "at": now_iso(),
        })
        if self.config.should_escalate(severity):
            esc = inc["escalation"]
            if esc and esc["status"] == "open":
                # 同一值班周期内重复确认：只刷新确认时间，不再升级、不再次通知
                self._append("escalation_confirmed", {
                    "incident_id": incident_id, "at": now_iso(),
                })
            else:
                self._raise_escalation(incident_id, "等级经确认升至直接人身威胁")

    # ------------------------------------------------------------- 值班升级
    def _raise_escalation(self, incident_id, reason):
        inc = self._get_open_incident(incident_id)
        if inc["escalation"] and inc["escalation"]["status"] == "open":
            return inc["escalation"]["escalation_id"]
        escalation_id = new_id("esc")
        at = now_iso()
        self._append("escalation_raised", {
            "incident_id": incident_id, "escalation_id": escalation_id,
            "reason": reason, "at": at,
        })
        for role in self.config.duty["通知角色"]:
            self._append("notification_sent", {
                "notif_id": new_id("ntf"),
                "incident_id": incident_id,
                "channel": "duty",
                "to_role": role,
                "reason": reason,
                "escalation_id": escalation_id,
                "at": at,
            })
        return escalation_id

    def acknowledge_escalation(self, incident_id, actor):
        _require(actor, ("俱乐部值班主管",))
        inc = self._get_incident(incident_id)
        if not inc["escalation"] or inc["escalation"]["status"] != "open":
            raise AppError("该事件没有待响应的值班升级")
        self._append("escalation_acknowledged", {
            "incident_id": incident_id, "by": actor.get("name"), "at": now_iso(),
        })

    # ------------------------------------------------------------------ 证据
    def add_evidence(self, incident_id, payload, actor):
        _require(actor, self.SUBMIT_ROLES + ("平台联络员", "法务复核员"))
        inc = self._get_open_incident(incident_id)
        self._assert_not_appealed(inc)
        if not payload.get("content_ref"):
            raise AppError("证据补充必须提供受控引用 content_ref，不接受原始内容入库")
        evidence_id = new_id("ev")
        self._append("evidence_registered", {
            "incident_id": incident_id, "evidence_id": evidence_id,
            "kind": payload.get("kind", "supplement"),
            "content_ref": payload["content_ref"],
            "content_sha256": payload.get("content_sha256")
                              or content_hash(payload.get("raw_excerpt", "")),
            "state": payload.get("state", "online"),
            "submitted_by": actor.get("name"), "at": now_iso(),
            "note": payload.get("note", "证据补充"),
        })
        return {"evidence_id": evidence_id}

    def link_account(self, incident_id, payload, actor):
        _require(actor, self.SUBMIT_ROLES + ("平台联络员",))
        inc = self._get_open_incident(incident_id)
        if not payload.get("account_key"):
            raise AppError("关联账号必须包含 platform 与 account_key")
        link_id = new_id("acct")
        self._append("account_linked", {
            "incident_id": incident_id, "link_id": link_id,
            "platform": payload.get("platform"), "account_key": payload["account_key"],
            "url": payload.get("url"), "display_name": payload.get("display_name"),
            "at": now_iso(),
        })
        self._suggest_clusters_for(inc)
        return {"link_id": link_id}

    # ------------------------------------------------------------------ 聚类
    def _pair_key(self, incident_ids):
        return "|".join(sorted(incident_ids))

    def _suggest_clusters_for(self, inc):
        """只生成合并建议；任何合并都必须由保护专员确认。"""
        candidates = []
        for other_id, other in self.incidents.items():
            if other_id == inc["incident_id"] or other.get("merged_into") or other.get("closed_at"):
                continue
            reason = None
            same_victim = other["victim_code"] == inc["victim_code"]
            if same_victim:
                old_hashes = {e["content_sha256"] for e in other["evidence"] if e["content_sha256"]}
                new_hashes = {e["content_sha256"] for e in inc["evidence"] if e["content_sha256"]}
                if old_hashes & new_hashes:
                    reason = "同一当事人且内容哈希一致"
            if reason is None:
                old_keys = {(a["platform"], a["account_key"]) for a in other["accounts"]}
                new_keys = {(a["platform"], a["account_key"]) for a in inc["accounts"]}
                if old_keys & new_keys:
                    reason = "共享同一平台关联账号"
            if reason:
                candidates.append((other_id, reason))
        for other_id, reason in candidates:
            pair = [inc["incident_id"], other_id]
            if self._pair_key(pair) in self._suggestion_keys:
                continue
            self._append("merge_suggested", {
                "suggestion_id": new_id("sug"),
                "incident_ids": pair,
                "reason": reason,
                "created_at": now_iso(),
            })

    def resolve_suggestion(self, suggestion_id, decision, actor, target_incident=None):
        _require(actor, ("俱乐部保护专员",))
        with self._lock:
            sugg = self.suggestions.get(suggestion_id)
            if not sugg:
                raise AppError("合并建议不存在", 404)
            if sugg["status"] != "open":
                raise AppError("该建议已处理")
            if decision not in ("accept", "reject"):
                raise AppError("decision 仅支持 accept/reject")
            merged_into = None
            if decision == "accept":
                merged_into = target_incident or sugg["incident_ids"][0]
                source_id = sugg["incident_ids"][1] if merged_into == sugg["incident_ids"][0] else sugg["incident_ids"][0]
                if merged_into not in sugg["incident_ids"]:
                    raise AppError("合并目标必须是建议涉及的事件之一")
                self._get_open_incident(merged_into)
                self._get_open_incident(source_id)
                self._append("incidents_merged", {
                    "survivor_id": merged_into, "merged_id": source_id,
                    "by": actor.get("name"), "at": now_iso(),
                })
            self._append("suggestion_resolved", {
                "suggestion_id": suggestion_id, "decision": decision,
                "by": actor.get("name"), "at": now_iso(), "merged_into": merged_into,
            })
            return {"status": decision, "merged_into": merged_into}

    # ------------------------------------------------------------------ 授权
    def grant_consent(self, incident_id, scopes, actor):
        _require(actor, ("当事人代理",))
        self._get_incident(incident_id)
        unknown = set(scopes) - set(self.config.scopes)
        if unknown:
            raise AppError(f"未知授权范围：{sorted(unknown)}")
        self._append("consent_granted", {
            "incident_id": incident_id, "scopes": scopes,
            "by": actor.get("name"), "at": now_iso(),
        })
        return {"scopes": self.incidents[incident_id]["consent_scopes"]}

    def revoke_consent(self, incident_id, scopes, actor):
        _require(actor, ("当事人代理",))
        inc = self._get_incident(incident_id)
        unknown = set(scopes) - set(self.config.scopes)
        if unknown:
            raise AppError(f"未知授权范围：{sorted(unknown)}")
        # 申诉或司法移交存续期间，证据留存授权不可撤回（其余授权仍可撤回）
        if "evidence_storage" in scopes and (inc["appeal"] and inc["appeal"]["status"] == "open"):
            raise AppError("误报申诉存续期间不可撤回证据留存授权")
        if "evidence_storage" in scopes and self._has_executed(incident_id, "police_report"):
            raise AppError("已报案移交的事件处于司法程序中，证据留存授权不可单独撤回")
        self._append("consent_revoked", {
            "incident_id": incident_id, "scopes": scopes,
            "by": actor.get("name"), "at": now_iso(),
        })
        return {"scopes": inc["consent_scopes"]}

    def _has_executed(self, incident_id, action_type):
        return any(self.actions[a]["action_type"] == action_type
                   and self.actions[a]["status"] == "executed"
                   for a in self.incidents[incident_id]["actions"])

    # ------------------------------------------------------------------ 动作
    EXTERNAL_ACTIONS = ("platform_complaint", "police_report", "public_statement")

    def propose_action(self, incident_id, action_type, actor, params=None):
        _require(actor, self.SUBMIT_ROLES)
        inc = self._get_open_incident(incident_id)
        if action_type not in self.config.actions:
            raise AppError(f"未知处置动作：{action_type}")
        if action_type in self.EXTERNAL_ACTIONS and inc["appeal"] and inc["appeal"]["status"] == "open":
            raise AppError("误报申诉期间不得发起新的对外动作")
        action_id = new_id("act")
        self._append("action_proposed", {
            "action_id": action_id, "incident_id": incident_id,
            "action_type": action_type, "params": params or {},
            "proposed_by": actor.get("name"), "proposed_by_role": actor["role"],
            "required_reviewer_role": self.config.reviewer_role_for(action_type),
            "required_scopes": self.config.required_scopes_for(action_type),
            "at": now_iso(),
        })
        return {"action_id": action_id,
                "required_reviewer_role": self.config.reviewer_role_for(action_type)}

    def review_action(self, action_id, decision, actor, reason=None):
        action = self.actions.get(action_id)
        if not action:
            raise AppError("处置动作不存在", 404)
        inc = self._get_open_incident(action["incident_id"])
        if action["status"] != "pending":
            raise AppError(f"动作已{action['status']}，不能重复复核")
        if decision not in ("approve", "reject"):
            raise AppError("decision 仅支持 approve/reject")
        if actor["role"] != action["required_reviewer_role"]:
            raise AppError(
                f"该动作须由 {action['required_reviewer_role']} 复核", 403)
        if self.config.separation["禁止自复核"] and actor.get("name") == action["proposed_by"]:
            raise AppError("提交人不能复核自己发起的动作", 403)
        self._append("action_reviewed", {
            "action_id": action_id, "incident_id": action["incident_id"],
            "decision": decision,
            "reviewer": actor.get("name"), "reviewer_role": actor["role"],
            "reason": reason, "at": now_iso(),
        })
        return {"action_id": action_id, "status": "approved" if decision == "approve" else "rejected"}

    def execute_action(self, action_id, actor):
        action = self.actions.get(action_id)
        if not action:
            raise AppError("处置动作不存在", 404)
        inc = self._get_open_incident(action["incident_id"])
        if action["status"] != "approved":
            raise AppError("仅已复核通过的动作可以执行")
        missing = [s for s in action["required_scopes"] if s not in inc["consent_scopes"]]
        if missing:
            names = "、".join(self.config.scopes[s]["名称"] for s in missing)
            raise AppError(f"当事人当前授权不足，缺少：{names}；动作保持已批准待执行", 409)
        if action["action_type"] in self.EXTERNAL_ACTIONS and inc["appeal"] and inc["appeal"]["status"] == "open":
            raise AppError("误报申诉期间不得执行对外动作", 409)

        at = now_iso()
        receipt = None
        result = {"executed_by": actor.get("name")}
        if action["action_type"] == "platform_complaint":
            platform = action["params"].get("platform") or inc["platform"]
            receipt = {
                "receipt_id": new_id("RCP"),
                "platform": platform,
                "status": "accepted",
                "reported_at": at,
            }
            result["complaint_ref"] = receipt["receipt_id"]
        elif action["action_type"] == "police_report":
            result["transfer_ref"] = new_id("POL")
        elif action["action_type"] == "public_statement":
            result["statement_ref"] = new_id("STM")
        else:
            result["note"] = "内部保护动作已落实"
        self._append("action_executed", {
            "action_id": action_id, "incident_id": action["incident_id"],
            "at": at, "result": result, "receipt": receipt,
        })
        return {"action_id": action_id, "status": "executed", "result": result}

    # ------------------------------------------------------------------ 申诉
    def open_appeal(self, incident_id, reason, actor):
        _require(actor, self.SUBMIT_ROLES)
        inc = self._get_open_incident(incident_id)
        if inc["appeal"] and inc["appeal"]["status"] == "open":
            raise AppError("该事件已在申诉中")
        self._append("appeal_opened", {
            "incident_id": incident_id, "reason": reason,
            "by": actor.get("name"), "at": now_iso(),
        })

    def resolve_appeal(self, incident_id, decision, actor, note=None):
        _require(actor, ("法务复核员",))
        with self._lock:
            inc = self._get_incident(incident_id)
            if not inc["appeal"] or inc["appeal"]["status"] != "open":
                raise AppError("该事件没有待裁定的申诉")
            if decision not in ("upheld", "dismissed"):
                raise AppError("decision 仅支持 upheld（误报成立）/dismissed（申诉驳回）")
            self._append("appeal_resolved", {
                "incident_id": incident_id, "decision": decision,
                "by": actor.get("name"), "at": now_iso(), "note": note,
            })
            if decision == "upheld":
                self._append("incident_closed", {
                    "incident_id": incident_id,
                    "reason": "误报申诉成立，按误报关闭（责任链留存）",
                    "by": actor.get("name"), "at": now_iso(),
                })

    def close_incident(self, incident_id, reason, actor):
        _require(actor, ("俱乐部保护专员", "法务复核员"))
        with self._lock:
            inc = self._get_open_incident(incident_id)
            pending = [a for a in inc["actions"] if self.actions[a]["status"] in ("pending", "approved")]
            if inc["escalation"] and inc["escalation"]["status"] == "open":
                raise AppError("值班升级尚未响应，不能关闭事件")
            if pending:
                raise AppError(f"尚有 {len(pending)} 个保护动作未完成，不能关闭事件")
            self._append("incident_closed", {
                "incident_id": incident_id, "reason": reason or "保护动作完成，关闭",
                "by": actor.get("name"), "at": now_iso(),
            })

    # ------------------------------------------------------------------ 回调
    def platform_callback(self, payload):
        """平台/采集回调。

        - 以 callback_id 幂等：重复回调返回首次处理结果（duplicate=true）；
          同一 callback_id 携带不同内容时保留首次结果并明确报冲突
          （conflict=true），不再写入任何事件；
        - 回调无论通过显式案件号、既有回执号还是内容引用命中被吸收子案件，
          都解析到唯一主案件，新增事实原子记入主链，并保留原始命中来源
          （hit_via / routed_from）；旧子案件不再发生业务变更；
        - 合并链异常、主案件已关闭、多条线索无法唯一归属时返回稳定业务错误，
          绝不另立案件。
        """
        with self._lock:
            callback_id = payload.get("callback_id")
            if not callback_id:
                raise AppError("回调必须携带 callback_id")
            request_hash = callback_fingerprint(payload)
            known = self.callbacks.get(callback_id)
            if known is not None:
                first = {k: v for k, v in known.items() if k != "request_hash"}
                response = {"duplicate": True, "callback_id": callback_id, **first}
                if known.get("request_hash") is not None and known["request_hash"] != request_hash:
                    response["conflict"] = True
                    response["conflict_detail"] = (
                        "同一 callback_id 的回调内容与首次处理不一致，"
                        "已保留首次处理结果，本次内容不写入")
                return response

            incident, hit = self._resolve_callback_incident(payload)
            if incident is None:
                raise AppError("回调未匹配到既有事件，须先经当事人或授权代理报送立案", 404)
            incident_id = incident["incident_id"]
            at = now_iso()
            routed_from = [iid for iid in hit["matched_incident_ids"] if iid != incident_id]
            origin = {"callback_id": callback_id, "hit_via": list(hit["via"])}
            if routed_from:
                origin["routed_from"] = routed_from

            attached = []
            events = []
            receipt = payload.get("receipt")
            if receipt and receipt.get("receipt_id"):
                events.append(("receipt_recorded", {
                    "incident_id": incident_id,
                    "receipt_id": receipt["receipt_id"],
                    "platform": receipt.get("platform", payload.get("platform")),
                    "status": receipt.get("status"),
                    "reported_at": receipt.get("reported_at", at),
                    "via": "callback", "at": at, **origin,
                }))
                attached.append("receipt")
                if receipt.get("status") == "removed":
                    evidence = self._evidence_for(incident, receipt.get("content_url"))
                    if evidence:
                        events.append(("content_state_changed", {
                            "incident_id": incident_id,
                            "evidence_id": evidence["evidence_id"],
                            "old_state": evidence["state"], "new_state": "deleted",
                            "source": "platform_callback", "at": at, **origin,
                        }))
                        attached.append("content_deleted")

            account = payload.get("account")
            if account and account.get("account_key"):
                matched = self._account_in_group(incident, account)
                if matched:
                    new_name = account.get("display_name")
                    if new_name and new_name != matched["display_name"]:
                        events.append(("account_renamed", {
                            "incident_id": incident_id,
                            "platform": matched["platform"],
                            "account_key": matched["account_key"],
                            "old_name": matched["display_name"],
                            "new_name": new_name, "at": at, **origin,
                        }))
                        attached.append("account_renamed")
                else:
                    events.append(("account_linked", {
                        "incident_id": incident_id, "link_id": new_id("acct"),
                        "platform": account.get("platform", payload.get("platform")),
                        "account_key": account["account_key"], "url": account.get("url"),
                        "display_name": account.get("display_name"), "at": at, **origin,
                    }))
                    attached.append("account_linked")

            # 回调附件不产生任何通知，也绝不另立案件
            result = {"duplicate": False, "callback_id": callback_id,
                      "incident_id": incident_id, "attached": attached,
                      "hit_via": list(hit["via"])}
            if routed_from:
                result["routed_from"] = routed_from
            stored = {k: v for k, v in result.items() if k != "duplicate"}
            events.append(("callback_processed", {
                "callback_id": callback_id, "result": stored,
                "request_hash": request_hash, "at": at,
            }))
            # 同一回调的全部事实与幂等标记原子落账：不部分写入，重放后结论一致
            self.store.append_many(events)
            return result

    def _resolve_callback_incident(self, payload):
        """解析回调归属。

        显式案件号、既有回执号、内容引用三条线索各自命中后，都先沿合并链归并
        到唯一主案件；返回 (主案件, 命中来源)。无命中返回 (None, None)；
        合并链异常、主案件已关闭、线索指向不同主案件时抛出稳定业务错误。
        """
        hits = []
        seen = set()

        def add_hit(via, incident):
            key = (via, incident["incident_id"])
            if key not in seen:
                seen.add(key)
                hits.append((via, incident["incident_id"]))

        explicit = payload.get("incident_id")
        if explicit and explicit in self.incidents:
            add_hit("incident_id", self.incidents[explicit])
        receipt = payload.get("receipt") or {}
        receipt_id = receipt.get("receipt_id")
        if receipt_id:
            for inc in self.incidents.values():
                if any(r["receipt_id"] == receipt_id for r in inc["receipts"]):
                    add_hit("receipt", inc)
        url = receipt.get("content_url") or payload.get("content_url")
        if url:
            for inc in self.incidents.values():
                if any(e["content_ref"] == url for e in inc["evidence"]):
                    add_hit("content_url", inc)
        if not hits:
            return None, None
        roots = {}
        for _via, incident_id in hits:
            root = self._merge_root(self.incidents[incident_id])
            roots[root["incident_id"]] = root
        if len(roots) > 1:
            raise AppError(
                "回调线索无法唯一归属：命中多个未合并事件（"
                + "、".join(sorted(roots))
                + "），请由保护专员确认合并或补充明确案件号", 409)
        root = next(iter(roots.values()))
        if root.get("closed_at"):
            raise AppError(
                f"主案件 {root['incident_id']} 已关闭，回调事实不再写入，也不另立案件", 409)
        hit = {"via": [via for via, _ in hits],
               "matched_incident_ids": sorted({iid for _, iid in hits})}
        return root, hit

    def _merge_root(self, incident):
        """沿 merged_into 链解析唯一主案件；链异常（成环、目标缺失）报稳定业务错误。"""
        seen = {incident["incident_id"]}
        current = incident
        while current.get("merged_into"):
            target_id = current["merged_into"]
            if target_id in seen:
                raise AppError(f"合并链异常：{target_id} 在合并链中成环", 409)
            seen.add(target_id)
            target = self.incidents.get(target_id)
            if target is None:
                raise AppError(
                    f"合并链异常：{current['incident_id']} 的主案件 {target_id} 不存在", 409)
            current = target
        return current

    def _merge_group(self, incident):
        """主案件及其吸收的全部子案件（含间接吸收），用于统一视图与组内投影。"""
        group = [incident]
        seen = {incident["incident_id"]}
        queue = list(incident.get("absorbed", []))
        while queue:
            member_id = queue.pop(0)
            if member_id in seen:
                continue
            seen.add(member_id)
            member = self.incidents.get(member_id)
            if member is None:
                continue
            group.append(member)
            queue.extend(member.get("absorbed", []))
        return group

    def _evidence_for(self, incident, url):
        if not url:
            return None
        for member in self._merge_group(incident):
            found = next((e for e in member["evidence"] if e["content_ref"] == url), None)
            if found:
                return found
        return None

    def _account_in_group(self, incident, account):
        for member in self._merge_group(incident):
            found = next((a for a in member["accounts"]
                          if a["platform"] == account.get("platform")
                          and a["account_key"] == account["account_key"]), None)
            if found:
                return found
        return None

    # ------------------------------------------------------------------ 查询
    def _get_incident(self, incident_id):
        inc = self.incidents.get(incident_id)
        if not inc:
            raise AppError("事件不存在", 404)
        return inc

    def _get_open_incident(self, incident_id):
        inc = self._get_incident(incident_id)
        if inc.get("merged_into"):
            raise AppError(f"该事件已合并入 {inc['merged_into']}，请在主事件上操作", 409)
        if inc.get("closed_at"):
            raise AppError("事件已关闭，不可再变更", 409)
        return inc

    def _assert_not_appealed(self, inc):
        if inc["appeal"] and inc["appeal"]["status"] == "open":
            raise AppError("申诉期间限制敏感材料扩散，须先由法务复核员裁定")

    def _status_of(self, inc):
        if inc.get("closed_at"):
            return "已关闭"
        if inc.get("merged_into"):
            return "已关闭"
        if inc["appeal"] and inc["appeal"]["status"] == "open":
            return "申诉中"
        if self._has_executed(inc["incident_id"], "police_report"):
            return "已移交"
        if any(self.actions[a]["status"] == "pending" for a in inc["actions"]):
            return "待复核"
        if inc["actions"] or inc["escalation"]:
            return "保护中"
        return "已受理"

    def incident_digest(self, incident_id, as_role=None):
        """保护专员视角的统一视图：证据依据、处置决定、授权范围、待办保护动作。

        合并后被吸收子案件的证据、关联账号与平台回执一并并入主案件视图，
        并以 source_incident 标注来源案件，保证统一视图完整承接回调事实。
        """
        inc = self._get_incident(incident_id)
        appeal_open = inc["appeal"] and inc["appeal"]["status"] == "open"
        mask = appeal_open and not (as_role and self.config.appeal_can_view_sensitive(as_role))
        group = self._merge_group(inc)

        evidence = []
        for member in group:
            for e in member["evidence"]:
                evidence.append({
                    "evidence_id": e["evidence_id"], "kind": e["kind"],
                    "content_ref": "【申诉期间已限制查看】" if mask else e["content_ref"],
                    "content_sha256": e["content_sha256"], "state": e["state"],
                    "submitted_by": e["submitted_by"], "at": e["at"], "note": e["note"],
                    "source_incident": member["incident_id"],
                })

        accounts = []
        for member in group:
            for a in member["accounts"]:
                accounts.append({
                    "platform": "【申诉期间已限制】" if mask else a["platform"],
                    "account_key": "【申诉期间已限制】" if mask else a["account_key"],
                    "url": "【申诉期间已限制】" if mask else a.get("url"),
                    "display_name": "【申诉期间已限制】" if mask else a.get("display_name"),
                    "renamed": len(a["name_history"]) > 1,
                    "name_history": [] if mask else a["name_history"],
                    "source_incident": member["incident_id"],
                })

        receipts = []
        for member in group:
            for r in member["receipts"]:
                receipts.append({**r, "source_incident": member["incident_id"]})

        actions = [self._action_view(a, inc) for a in inc["actions"]]
        pending = [a["action_id"] for a in actions if a["status"] in ("pending", "approved", "blocked")]

        digest = {
            "incident_id": inc["incident_id"],
            "status": self._status_of(inc),
            "victim_code": inc["victim_code"],
            "platform": inc["platform"],
            "severity": self.config.severities[inc["severity"]],
            "report_nos": inc["report_nos"],
            "opened_at": inc["opened_at"],
            "merged_into": inc.get("merged_into"),
            "absorbed_incidents": inc.get("absorbed", []),
            "证据依据": {
                "evidence": evidence,
                "linked_accounts": accounts,
                "platform_receipts": receipts,
            },
            "处置决定": actions,
            "当事人当前授权范围": [
                {"code": s, "name": self.config.scopes[s]["名称"]}
                for s in inc["consent_scopes"]
            ],
            "尚未完成的保护动作": {
                "action_ids": pending,
                "open_escalation": bool(inc["escalation"] and inc["escalation"]["status"] == "open"),
            },
            "值班升级": inc["escalation"],
            "申诉": inc["appeal"],
            "责任链": self._timeline(inc, mask),
        }
        if inc.get("closed_at"):
            digest["closed_at"] = inc["closed_at"]
            digest["close_reason"] = inc["close_reason"]
        return digest

    def _action_view(self, action_id, inc):
        a = self.actions[action_id]
        view = {
            "action_id": a["action_id"], "action_type": a["action_type"],
            "name": self.config.actions[a["action_type"]]["名称"],
            "status": a["status"], "proposed_by": a["proposed_by"],
            "proposed_by_role": a["proposed_by_role"],
            "required_reviewer_role": a["required_reviewer_role"],
            "reviewer": a["reviewer"], "review_reason": a["review_reason"],
            "executed_at": a["executed_at"], "result": a["result"],
        }
        if a["status"] == "approved":
            missing = [s for s in a["required_scopes"] if s not in inc["consent_scopes"]]
            if missing:
                view["status"] = "blocked"
                view["blocked_reason"] = "授权已撤回：" + "、".join(
                    self.config.scopes[s]["名称"] for s in missing)
        return view

    def _timeline(self, inc, mask):
        wanted = set(inc["report_nos"])
        incident_ids = {inc["incident_id"]}
        for absorbed_id in inc.get("absorbed", []):
            absorbed = self.incidents.get(absorbed_id)
            if absorbed:
                incident_ids.add(absorbed_id)
                wanted.update(absorbed["report_nos"])
        chain = []
        for event in self.store.replay():
            p = event["payload"]
            if p.get("incident_id") in incident_ids or p.get("report_no") in wanted:
                chain.append({"seq": event["seq"], "type": event["type"], "payload": p})
        if mask:
            for item in chain:
                p = item["payload"]
                for field in ("content_ref", "content_url", "raw_excerpt", "url", "display_name"):
                    if field in p and p[field]:
                        p[field] = "【申诉期间已限制】"
                if "linked_accounts" in p:
                    p["linked_accounts"] = ["【申诉期间已限制】" for _ in p["linked_accounts"]]
        return chain

    def list_incidents(self, status=None, severity=None):
        out = []
        for incident_id, inc in self.incidents.items():
            current = self._status_of(inc)
            if status and current != status:
                continue
            if severity and inc["severity"] != severity:
                continue
            out.append({
                "incident_id": incident_id, "status": current,
                "victim_code": inc["victim_code"], "severity": inc["severity"],
                "platform": inc["platform"], "opened_at": inc["opened_at"],
                "merged_into": inc.get("merged_into"),
                "open_escalation": bool(inc["escalation"] and inc["escalation"]["status"] == "open"),
            })
        return out

    def list_suggestions(self, status="open"):
        return [s for s in self.suggestions.values() if status is None or s["status"] == status]

    def list_reports(self):
        return list(self.reports.values())

    def list_notifications(self, incident_id=None):
        if incident_id:
            return [n for n in self.notifications if n["incident_id"] == incident_id]
        return list(self.notifications)
