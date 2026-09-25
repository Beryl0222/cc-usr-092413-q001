"""网络侵害事件受理与协同处置的全链路契约测试。"""

import json
import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

from app import AppError, SafeguardingApp, content_hash, suggest_severity
from service import build_handler

AGENT = {"name": "代理人小林", "role": "当事人代理"}
OFFICER = {"name": "保护专员阿岚", "role": "俱乐部保护专员"}
DUTY = {"name": "值班主管老周", "role": "俱乐部值班主管"}
LIASON = {"name": "平台联络员小孟", "role": "平台联络员"}
LEGAL = {"name": "法务复核员老许", "role": "法务复核员"}

THREAT_TEXT = "你在19号更衣室门口等着，今晚别想走着出去"
CRITICISM_TEXT = "这场换人太晚，球员状态明显不行，踢得太差"


def threat_report(**overrides):
    payload = {
        "victim_code": "ATH-007",
        "platform": "weibo",
        "content_url": "https://weibo.example/comment/90210",
        "raw_excerpt": THREAT_TEXT,
        "severity": "direct_threat",
        "linked_accounts": [
            {"platform": "weibo", "account_key": "u_threat_77",
             "url": "https://weibo.example/u/77", "display_name": "黑哨敢死队"}
        ],
        "授权范围": ["report", "evidence_storage", "platform_complaint",
                  "police_report", "public_statement"],
    }
    payload.update(overrides)
    return payload


def abuse_report(**overrides):
    payload = {
        "victim_code": "ATH-009",
        "platform": "douyin",
        "content_url": "https://video.example/comment/55",
        "raw_excerpt": "这人就该被网暴到退役，全家都不是好东西",
        "severity": "abuse",
        "linked_accounts": [
            {"platform": "douyin", "account_key": "dy_hater_9",
             "url": "https://video.example/u/9", "display_name": "辱骂账号"}
        ],
        "授权范围": ["report", "evidence_storage", "platform_complaint"],
    }
    payload.update(overrides)
    return payload


class DomainRulesTest(unittest.TestCase):
    def setUp(self):
        self.app = SafeguardingApp()

    def test_severity_suggestion_is_advisory(self):
        self.assertEqual(suggest_severity(THREAT_TEXT), "direct_threat")
        self.assertEqual(suggest_severity(CRITICISM_TEXT), "criticism")

    def test_criticism_is_logged_but_not_opened_as_incident(self):
        result = self.app.submit_report(
            {"victim_code": "ATH-001", "platform": "weibo",
             "content_url": "https://weibo.example/comment/1",
             "raw_excerpt": CRITICISM_TEXT, "severity": "criticism"}, AGENT)
        self.assertIsNone(result["incident_id"])
        self.assertIn("不立案", result["decision"])
        self.assertEqual(self.app.list_incidents(), [])
        # 线索仍可查，便于观察是否升级为网暴
        self.assertEqual(len(self.app.list_reports()), 1)

    def test_unknown_severity_and_missing_reference_rejected(self):
        with self.assertRaises(AppError):
            self.app.submit_report(
                {"victim_code": "ATH-001", "content_url": "u", "severity": "bomb"}, AGENT)
        with self.assertRaises(AppError):
            self.app.submit_report(
                {"victim_code": "ATH-001", "severity": "abuse"}, AGENT)

    def test_raw_content_never_enters_the_ledger(self):
        result = self.app.submit_report(threat_report(), AGENT)
        dumped = json.dumps(self.app.store.replay(), ensure_ascii=False)
        self.assertNotIn(THREAT_TEXT, dumped)  # 原始内容不入库
        digest = self.app.incident_digest(result["incident_id"])
        self.assertEqual(digest["证据依据"]["evidence"][0]["content_sha256"],
                         content_hash(THREAT_TEXT))
        self.assertEqual(digest["证据依据"]["evidence"][0]["content_ref"],
                         "https://weibo.example/comment/90210")


class DutyEscalationTest(unittest.TestCase):
    def setUp(self):
        self.app = SafeguardingApp()
        self.result = self.app.submit_report(threat_report(), AGENT)
        self.incident_id = self.result["incident_id"]

    def test_direct_threat_escalates_once_with_dedup_notifications(self):
        digest = self.app.incident_digest(self.incident_id)
        self.assertTrue(digest["尚未完成的保护动作"]["open_escalation"])
        notifs = self.app.list_notifications(self.incident_id)
        roles = sorted(n["to_role"] for n in notifs)
        self.assertEqual(roles, ["俱乐部保护专员", "俱乐部值班主管"])

        # 再次以直接威胁确认：只刷新确认时间，不产生第二案件、不第二次通知
        self.app.confirm_severity(self.incident_id, "direct_threat", OFFICER)
        self.assertEqual(len(self.app.incidents), 1)
        self.assertEqual(len(self.app.list_notifications(self.incident_id)), 2)
        digest = self.app.incident_digest(self.incident_id)
        self.assertIsNotNone(digest["值班升级"]["last_confirmed_at"])

        # 值班主管响应后升级关闭
        self.app.acknowledge_escalation(self.incident_id, DUTY)
        self.assertFalse(
            self.app.incident_digest(self.incident_id)["尚未完成的保护动作"]["open_escalation"])

    def test_only_duty_lead_can_acknowledge(self):
        with self.assertRaises(AppError):
            self.app.acknowledge_escalation(self.incident_id, OFFICER)


class CallbackIdempotencyTest(unittest.TestCase):
    def setUp(self):
        self.app = SafeguardingApp()
        self.incident_id = self.app.submit_report(abuse_report(), AGENT)["incident_id"]
        self.callback = {
            "callback_id": "CB-001",
            "incident_id": self.incident_id,
            "receipt": {
                "receipt_id": "DY-8840217", "platform": "douyin",
                "status": "removed",
                "reported_at": "2026-09-18T21:03:00+08:00",
                "content_url": "https://video.example/comment/55",
            },
            "account": {"platform": "douyin", "account_key": "dy_hater_9",
                        "display_name": "改名前的账号名"},
        }

    def test_repeated_callback_attaches_once_notifies_nothing(self):
        first = self.app.platform_callback(self.callback)
        self.assertFalse(first["duplicate"])
        self.assertIn("content_deleted", first["attached"])

        second = self.app.platform_callback(self.callback)
        self.assertTrue(second["duplicate"])
        self.assertEqual(second["incident_id"], self.incident_id)
        self.assertEqual(len(self.app.incidents), 1)  # 没有第二案件
        self.assertEqual(self.app.list_notifications(), [])  # 回调不通知

        digest = self.app.incident_digest(self.incident_id)
        states = [e["state"] for e in digest["证据依据"]["evidence"]]
        self.assertIn("deleted", states)
        receipts = digest["证据依据"]["platform_receipts"]
        self.assertEqual(len(receipts), 1)

    def test_rename_callback_appends_history_without_breaking_chain(self):
        self.app.platform_callback(self.callback)
        renamed = dict(self.callback)
        renamed["account"] = {"platform": "douyin", "account_key": "dy_hater_9",
                              "display_name": "改名后的账号名"}
        response = self.app.platform_callback(renamed)
        self.assertTrue(response["duplicate"])  # 同 callback_id：不重复处理改名
        new_cb = json.loads(json.dumps(self.callback))
        new_cb["callback_id"] = "CB-002"
        new_cb["account"]["display_name"] = "改名后的账号名"
        response = self.app.platform_callback(new_cb)
        self.assertFalse(response["duplicate"])
        digest = self.app.incident_digest(self.incident_id)
        account = digest["证据依据"]["linked_accounts"][0]
        self.assertTrue(account["renamed"])
        self.assertEqual(account["display_name"], "改名后的账号名")
        self.assertEqual([h["name"] for h in account["name_history"]],
                         ["辱骂账号", "改名前的账号名", "改名后的账号名"])

    def test_callback_unknown_reference_cannot_open_case(self):
        with self.assertRaises(AppError) as ctx:
            self.app.platform_callback({
                "callback_id": "CB-404",
                "receipt": {"receipt_id": "NOPE", "content_url": "https://x/unknown"}})
        self.assertEqual(ctx.exception.status, 404)


class ActionSeparationAndConsentTest(unittest.TestCase):
    def setUp(self):
        self.app = SafeguardingApp()
        self.incident_id = self.app.submit_report(abuse_report(), AGENT)["incident_id"]

    def test_reviewer_role_and_self_review_are_enforced(self):
        action_id = self.app.propose_action(
            self.incident_id, "platform_complaint", AGENT)["action_id"]
        with self.assertRaises(AppError) as ctx:
            self.app.review_action(action_id, "approve", AGENT)
        self.assertEqual(ctx.exception.status, 403)  # 禁止自复核
        with self.assertRaises(AppError) as ctx:
            self.app.review_action(action_id, "approve", LEGAL)
        self.assertEqual(ctx.exception.status, 403)  # 法务不能复核平台投诉
        reviewed = self.app.review_action(action_id, "approve", LIASON)
        self.assertEqual(reviewed["status"], "approved")
        executed = self.app.execute_action(action_id, LIASON)
        self.assertEqual(executed["status"], "executed")
        digest = self.app.incident_digest(self.incident_id)
        self.assertEqual(len(digest["证据依据"]["platform_receipts"]), 1)

    def test_rejection_needs_resubmission_and_no_double_review(self):
        action_id = self.app.propose_action(
            self.incident_id, "public_statement", AGENT)["action_id"]
        self.app.review_action(action_id, "reject", LEGAL, reason="事实未清，不宜公开")
        with self.assertRaises(AppError):
            self.app.review_action(action_id, "approve", LEGAL)

    def test_revoked_consent_blocks_pending_action_but_keeps_chain(self):
        first = self.app.propose_action(
            self.incident_id, "platform_complaint", AGENT)["action_id"]
        self.app.review_action(first, "approve", LIASON)
        self.app.execute_action(first, LIASON)  # 已执行的投诉不可逆转

        second = self.app.propose_action(
            self.incident_id, "platform_complaint", AGENT)["action_id"]
        self.app.review_action(second, "approve", LIASON)
        self.app.revoke_consent(self.incident_id, ["platform_complaint"], AGENT)

        with self.assertRaises(AppError) as ctx:
            self.app.execute_action(second, LIASON)
        self.assertEqual(ctx.exception.status, 409)
        digest = self.app.incident_digest(self.incident_id)
        blocked = next(a for a in digest["处置决定"] if a["action_id"] == second)
        self.assertEqual(blocked["status"], "blocked")
        self.assertIn("授权已撤回", blocked["blocked_reason"])
        # 已执行动作与授权撤回事件都留在责任链
        chain_types = [c["type"] for c in digest["责任链"]]
        self.assertIn("action_executed", chain_types)
        self.assertIn("consent_revoked", chain_types)

        # 重新授权后可执行，不产生新事件以外的重复案件
        self.app.grant_consent(self.incident_id, ["platform_complaint"], AGENT)
        self.assertEqual(self.app.execute_action(second, LIASON)["status"], "executed")
        self.assertEqual(len(self.app.incidents), 1)


class ClusteringAndMergingTest(unittest.TestCase):
    def setUp(self):
        self.app = SafeguardingApp()
        same = threat_report()
        self.first_id = self.app.submit_report(same, AGENT)["incident_id"]
        self.app.acknowledge_escalation(self.first_id, DUTY)
        # 先响应升级，避免第二事件也升级影响后续关闭类断言
        second = threat_report(content_url="https://weibo.example/comment/90210?mirror=1",
                               receipts=[{"receipt_id": "WB-2026-09-18-7781",
                                          "platform": "weibo", "status": "accepted"}])
        self.second_id = self.app.submit_report(second, AGENT)["incident_id"]
        self.app.acknowledge_escalation(self.second_id, DUTY)

    def test_cluster_is_only_a_suggestion_until_officer_confirms(self):
        suggestions = self.app.list_suggestions()
        self.assertEqual(len(suggestions), 1)
        sugg = suggestions[0]
        self.assertEqual(sugg["status"], "open")
        self.assertIn("内容哈希", sugg["reason"])
        # 自动聚类没有擅自合并
        self.assertIsNone(self.app.incidents[self.first_id]["merged_into"])

    def test_reject_suggestion_keeps_two_cases(self):
        sugg_id = self.app.list_suggestions()[0]["suggestion_id"]
        self.app.resolve_suggestion(sugg_id, "reject", OFFICER)
        self.assertIsNone(self.app.incidents[self.first_id]["merged_into"])

    def test_accept_suggestion_merges_and_preserves_full_chain(self):
        sugg_id = self.app.list_suggestions()[0]["suggestion_id"]
        result = self.app.resolve_suggestion(sugg_id, "accept", OFFICER,
                                             target_incident=self.first_id)
        self.assertEqual(result["merged_into"], self.first_id)
        survivor = self.app.incident_digest(self.first_id)
        self.assertEqual(survivor["absorbed_incidents"], [self.second_id])
        chain_reports = {c["payload"].get("report_no") for c in survivor["责任链"]
                         if c["type"] == "report_received"}
        self.assertEqual(len(chain_reports), 2)  # 两条线索的责任链都在
        with self.assertRaises(AppError) as ctx:
            self.app.add_evidence(self.second_id, {"content_ref": "u"}, AGENT)
        self.assertEqual(ctx.exception.status, 409)  # 被合并事件不可再操作


class AppealTest(unittest.TestCase):
    def setUp(self):
        self.app = SafeguardingApp()
        self.incident_id = self.app.submit_report(abuse_report(), AGENT)["incident_id"]

    def test_appeal_masks_sensitive_material_and_blocks_external_action(self):
        self.app.open_appeal(self.incident_id, "当事人称账号被盗，内容系误认", AGENT)
        digest_agent = self.app.incident_digest(self.incident_id, as_role="当事人代理")
        self.assertEqual(digest_agent["status"], "申诉中")
        self.assertIn("限制", digest_agent["证据依据"]["evidence"][0]["content_ref"])
        self.assertIn("限制", digest_agent["证据依据"]["linked_accounts"][0]["account_key"])

        digest_legal = self.app.incident_digest(self.incident_id, as_role="法务复核员")
        self.assertEqual(digest_legal["证据依据"]["evidence"][0]["content_ref"],
                         "https://video.example/comment/55")

        with self.assertRaises(AppError):
            self.app.propose_action(self.incident_id, "public_statement", AGENT)
        with self.assertRaises(AppError):
            self.app.add_evidence(self.incident_id, {"content_ref": "https://new"}, AGENT)
        # 申诉期间证据留存授权不可撤回
        with self.assertRaises(AppError):
            self.app.revoke_consent(self.incident_id, ["evidence_storage"], AGENT)

    def test_upheld_appeal_closes_case_but_chain_remains(self):
        self.app.open_appeal(self.incident_id, "误认", AGENT)
        self.app.resolve_appeal(self.incident_id, "upheld", LEGAL, note="证据不足，误报成立")
        digest = self.app.incident_digest(self.incident_id)
        self.assertEqual(digest["status"], "已关闭")
        self.assertIn("误报", digest["close_reason"])
        self.assertTrue(any(c["type"] == "evidence_registered" for c in digest["责任链"]))

    def test_dismissed_appeal_resumes_protection(self):
        self.app.open_appeal(self.incident_id, "误认", AGENT)
        self.app.resolve_appeal(self.incident_id, "dismissed", LEGAL)
        digest = self.app.incident_digest(self.incident_id, as_role="当事人代理")
        self.assertNotEqual(digest["status"], "申诉中")
        self.assertEqual(digest["证据依据"]["evidence"][0]["content_ref"],
                         "https://video.example/comment/55")


class ClosureAndDigestTest(unittest.TestCase):
    def setUp(self):
        self.app = SafeguardingApp()

    def test_cannot_close_with_open_escalation_or_pending_actions(self):
        incident_id = self.app.submit_report(threat_report(), AGENT)["incident_id"]
        with self.assertRaises(AppError):
            self.app.close_incident(incident_id, "想关掉", OFFICER)
        self.app.acknowledge_escalation(incident_id, DUTY)
        action_id = self.app.propose_action(incident_id, "protection_plan", AGENT)["action_id"]
        with self.assertRaises(AppError):
            self.app.close_incident(incident_id, "还有待办", OFFICER)
        # 保护方案由保护专员复核（提交人与复核人不得为同一人）
        self.app.review_action(action_id, "approve", OFFICER)
        self.app.execute_action(action_id, OFFICER)
        self.app.close_incident(incident_id, "保护到位", OFFICER)
        self.assertEqual(self.app.incident_digest(incident_id)["status"], "已关闭")

    def test_digest_shows_four_pillars(self):
        incident_id = self.app.submit_report(abuse_report(), AGENT)["incident_id"]
        digest = self.app.incident_digest(incident_id)
        for key in ("证据依据", "处置决定", "当事人当前授权范围", "尚未完成的保护动作"):
            self.assertIn(key, digest)
        scopes = {s["code"] for s in digest["当事人当前授权范围"]}
        self.assertEqual(scopes, {"report", "evidence_storage", "platform_complaint"})


class MergedCallbackRoutingTest(unittest.TestCase):
    """合并后平台迟到回调的归属：旧子案件不再被写入，主案件完整承接事实。"""

    def setUp(self):
        self.app = SafeguardingApp()
        self.first_id = self.app.submit_report(abuse_report(), AGENT)["incident_id"]
        second = abuse_report(
            content_url="https://video.example/comment/55?mirror=1",
            receipts=[{"receipt_id": "DY-8840217", "platform": "douyin",
                       "status": "accepted", "reported_at": "2026-09-18T20:00:00+08:00"}],
            linked_accounts=[{"platform": "douyin", "account_key": "dy_hater_9b",
                              "url": "https://video.example/u/9b", "display_name": "辱骂分身"}],
        )
        self.second_id = self.app.submit_report(second, AGENT)["incident_id"]
        sugg_id = self.app.list_suggestions()[0]["suggestion_id"]
        self.app.resolve_suggestion(sugg_id, "accept", OFFICER, target_incident=self.first_id)
        self.sub_events_at_merge = self._sub_case_events()

    def _sub_case_events(self):
        return [e for e in self.app.store.replay()
                if e["payload"].get("incident_id") == self.second_id]

    def _merged_callback(self, **overrides):
        callback = {
            "callback_id": "CB-MERGED-1",
            "incident_id": self.second_id,
            "receipt": {"receipt_id": "DY-8840217", "platform": "douyin",
                        "status": "removed", "reported_at": "2026-09-20T09:00:00+08:00",
                        "content_url": "https://video.example/comment/55?mirror=1"},
            "account": {"platform": "douyin", "account_key": "dy_hater_9b",
                        "display_name": "改名后的分身"},
        }
        callback.update(overrides)
        return callback

    def test_callback_with_absorbed_incident_id_lands_on_master(self):
        result = self.app.platform_callback(self._merged_callback())
        self.assertFalse(result["duplicate"])
        self.assertEqual(result["incident_id"], self.first_id)
        self.assertEqual(result["routed_from"], [self.second_id])
        self.assertEqual(result["hit_via"], ["incident_id", "receipt", "content_url"])
        self.assertEqual(result["attached"],
                         ["receipt", "content_deleted", "account_renamed"])

        # 旧子案件不再发生业务变更：合并后子案件链上没有追加任何事件
        self.assertEqual(self._sub_case_events(), self.sub_events_at_merge)

        # 回执、删除状态、改名全部记入主链，并保留原始命中来源
        master_events = [e for e in self.app.store.replay()
                         if e["payload"].get("callback_id") == "CB-MERGED-1"]
        self.assertEqual([e["type"] for e in master_events],
                         ["receipt_recorded", "content_state_changed",
                          "account_renamed", "callback_processed"])
        for event in master_events[:-1]:
            self.assertEqual(event["payload"]["incident_id"], self.first_id)
            self.assertEqual(event["payload"]["routed_from"], [self.second_id])

        # 主案件统一视图完整承接：回执最新状态、镜像内容已删除、账号已改名
        digest = self.app.incident_digest(self.first_id)
        receipts = [r for r in digest["证据依据"]["platform_receipts"]
                    if r["receipt_id"] == "DY-8840217"]
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0]["status"], "removed")
        self.assertEqual(receipts[0]["source_incident"], self.first_id)
        states = {e["content_ref"]: e["state"] for e in digest["证据依据"]["evidence"]}
        self.assertEqual(states["https://video.example/comment/55?mirror=1"], "deleted")
        accounts = {a["account_key"]: a for a in digest["证据依据"]["linked_accounts"]}
        self.assertEqual(accounts["dy_hater_9b"]["display_name"], "改名后的分身")
        self.assertEqual(accounts["dy_hater_9b"]["source_incident"], self.second_id)
        # 子案件自身的责任链停在合并时点，回调事实只在主链
        sub_chain = self.app.incident_digest(self.second_id)["责任链"]
        self.assertFalse(any(c["payload"].get("callback_id") == "CB-MERGED-1"
                             for c in sub_chain))
        # 回调不产生任何通知
        self.assertEqual(self.app.list_notifications(), [])

    def test_callback_matching_absorbed_receipt_resolves_to_master(self):
        result = self.app.platform_callback({
            "callback_id": "CB-MERGED-2",
            "receipt": {"receipt_id": "DY-8840217", "platform": "douyin",
                        "status": "processing"},
        })
        self.assertEqual(result["incident_id"], self.first_id)
        self.assertEqual(result["routed_from"], [self.second_id])
        self.assertEqual(result["hit_via"], ["receipt"])
        self.assertEqual(self._sub_case_events(), self.sub_events_at_merge)

    def test_callback_matching_absorbed_content_resolves_to_master(self):
        result = self.app.platform_callback({
            "callback_id": "CB-MERGED-3",
            "content_url": "https://video.example/comment/55?mirror=1",
            "receipt": {"receipt_id": "DY-9000", "platform": "douyin",
                        "status": "removed",
                        "content_url": "https://video.example/comment/55?mirror=1"},
            "account": {"platform": "douyin", "account_key": "dy_new_1",
                        "display_name": "新关联账号"},
        })
        self.assertEqual(result["incident_id"], self.first_id)
        self.assertEqual(result["hit_via"], ["content_url"])
        self.assertIn("content_deleted", result["attached"])
        self.assertIn("account_linked", result["attached"])
        # 新关联账号挂在主案件，旧子案件不再被写入
        digest = self.app.incident_digest(self.first_id)
        keys = {a["account_key"] for a in digest["证据依据"]["linked_accounts"]}
        self.assertIn("dy_new_1", keys)
        self.assertFalse(any(a["account_key"] == "dy_new_1"
                             for a in self.app.incidents[self.second_id]["accounts"]))
        self.assertEqual(self._sub_case_events(), self.sub_events_at_merge)

    def test_duplicate_and_conflicting_callback_after_merge(self):
        callback = self._merged_callback()
        first = self.app.platform_callback(callback)
        events_after_first = list(self.app.store.replay())

        again = self.app.platform_callback(callback)
        self.assertTrue(again["duplicate"])
        self.assertNotIn("conflict", again)
        self.assertEqual(again["incident_id"], self.first_id)
        self.assertEqual(again["routed_from"], [self.second_id])
        self.assertEqual(self.app.store.replay(), events_after_first)

        # 同一回调标识携带不同内容：保留首次结果、明确报冲突、不再写入
        altered = json.loads(json.dumps(callback))
        altered["receipt"]["status"] = "processing"
        conflict = self.app.platform_callback(altered)
        self.assertTrue(conflict["duplicate"])
        self.assertTrue(conflict["conflict"])
        self.assertIn("首次", conflict["conflict_detail"])
        self.assertEqual(conflict["attached"], first["attached"])
        self.assertEqual(self.app.store.replay(), events_after_first)
        # 首次处理结果仍然有效
        digest = self.app.incident_digest(self.first_id)
        receipt = next(r for r in digest["证据依据"]["platform_receipts"]
                       if r["receipt_id"] == "DY-8840217")
        self.assertEqual(receipt["status"], "removed")

    def test_callback_to_closed_master_is_stable_error(self):
        self.app.close_incident(self.first_id, "处置完成", OFFICER)
        events_before = list(self.app.store.replay())
        with self.assertRaises(AppError) as ctx:
            self.app.platform_callback(self._merged_callback(callback_id="CB-CLOSED"))
        self.assertEqual(ctx.exception.status, 409)
        self.assertIn("已关闭", str(ctx.exception))
        # 不另立案件、不写入任何事件
        self.assertEqual(len(self.app.incidents), 2)
        self.assertEqual(self.app.store.replay(), events_before)

    def test_ambiguous_callback_hints_are_rejected(self):
        other_id = self.app.submit_report(abuse_report(
            victim_code="ATH-100",
            content_url="https://video.example/comment/999",
            linked_accounts=[{"platform": "douyin", "account_key": "dy_other"}],
            receipts=[{"receipt_id": "DY-OTHER", "platform": "douyin",
                       "status": "accepted"}],
        ), AGENT)["incident_id"]
        events_before = list(self.app.store.replay())
        with self.assertRaises(AppError) as ctx:
            self.app.platform_callback({
                "callback_id": "CB-AMB",
                "receipt": {"receipt_id": "DY-OTHER", "platform": "douyin",
                            "status": "removed",
                            "content_url": "https://video.example/comment/55?mirror=1"}})
        self.assertEqual(ctx.exception.status, 409)
        self.assertIn("唯一归属", str(ctx.exception))
        self.assertIn(other_id, str(ctx.exception))
        self.assertEqual(self.app.store.replay(), events_before)

    def test_merge_chain_cycle_is_stable_error(self):
        # 账本层面构造异常合并链（正常接口不会产生）：主案件又指回子案件成环
        self.app._append("incidents_merged", {
            "survivor_id": self.second_id, "merged_id": self.first_id,
            "by": "账本修复", "at": "2026-09-25T00:00:00+08:00",
        })
        with self.assertRaises(AppError) as ctx:
            self.app.platform_callback(self._merged_callback(callback_id="CB-LOOP"))
        self.assertEqual(ctx.exception.status, 409)
        self.assertIn("合并链异常", str(ctx.exception))

    def test_merge_chain_missing_root_is_stable_error(self):
        self.app.incidents[self.second_id]["merged_into"] = "inc_ghost"
        with self.assertRaises(AppError) as ctx:
            self.app.platform_callback(self._merged_callback(callback_id="CB-GHOST"))
        self.assertEqual(ctx.exception.status, 409)
        self.assertIn("合并链异常", str(ctx.exception))


class MergeCallbackConcurrencyTest(unittest.TestCase):
    """合并与回调并发：只形成一个可解释顺序，统一视图结论一致。"""

    def test_merge_and_callback_race_forms_single_explainable_order(self):
        for _ in range(10):
            app = SafeguardingApp()
            first_id = app.submit_report(abuse_report(), AGENT)["incident_id"]
            second_id = app.submit_report(abuse_report(
                content_url="https://video.example/comment/55?mirror=1"), AGENT)["incident_id"]
            sugg_id = app.list_suggestions()[0]["suggestion_id"]
            callback = {"callback_id": "CB-RACE", "incident_id": second_id,
                        "receipt": {"receipt_id": "DY-RACE-1", "platform": "douyin",
                                    "status": "removed",
                                    "content_url": "https://video.example/comment/55?mirror=1"}}
            barrier = threading.Barrier(2)
            outcome = {}

            def do_merge():
                barrier.wait()
                outcome["merge"] = app.resolve_suggestion(
                    sugg_id, "accept", OFFICER, target_incident=first_id)

            def do_callback():
                barrier.wait()
                outcome["cb"] = app.platform_callback(callback)

            threads = [threading.Thread(target=do_merge),
                       threading.Thread(target=do_callback)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            merge_seq = next(e["seq"] for e in app.store.replay()
                             if e["type"] == "incidents_merged")
            landed = outcome["cb"]["incident_id"]
            fact_events = [e for e in app.store.replay()
                           if e["payload"].get("callback_id") == "CB-RACE"
                           and e["type"] != "callback_processed"]
            self.assertTrue(fact_events)
            # 回调事实只落在一个案件上：要么先于合并落在子案件，要么归并到主案件
            self.assertIn(landed, (first_id, second_id))
            for event in fact_events:
                self.assertEqual(event["payload"]["incident_id"], landed)
            if landed == second_id:
                # 回调先于合并：事实在子案件链上，且全部早于合并事件
                for event in fact_events:
                    self.assertLess(event["seq"], merge_seq)
            else:
                self.assertEqual(outcome["cb"]["routed_from"], [second_id])
            # 无论哪种顺序，主案件统一视图都必须看到回执与删除状态
            digest = app.incident_digest(first_id)
            self.assertTrue(any(r["receipt_id"] == "DY-RACE-1" and r["status"] == "removed"
                                for r in digest["证据依据"]["platform_receipts"]))
            states = {e["content_ref"]: e["state"] for e in digest["证据依据"]["evidence"]}
            self.assertEqual(states["https://video.example/comment/55?mirror=1"], "deleted")
            # 重复回调安全重放，不再写入
            events_before = list(app.store.replay())
            again = app.platform_callback(callback)
            self.assertTrue(again["duplicate"])
            self.assertEqual(app.store.replay(), events_before)


class MergedCallbackPersistenceTest(unittest.TestCase):
    def test_replay_preserves_merged_routing_and_idempotency(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "events.jsonl")
            app = SafeguardingApp(store_path=path)
            first_id = app.submit_report(abuse_report(), AGENT)["incident_id"]
            second_id = app.submit_report(abuse_report(
                content_url="https://video.example/comment/55?mirror=1",
                receipts=[{"receipt_id": "DY-8840217", "platform": "douyin",
                           "status": "accepted"}],
            ), AGENT)["incident_id"]
            sugg_id = app.list_suggestions()[0]["suggestion_id"]
            app.resolve_suggestion(sugg_id, "accept", OFFICER, target_incident=first_id)
            callback = {"callback_id": "CB-REPLAY", "incident_id": second_id,
                        "receipt": {"receipt_id": "DY-8840217", "platform": "douyin",
                                    "status": "removed",
                                    "content_url": "https://video.example/comment/55?mirror=1"}}
            app.platform_callback(callback)
            digest_before = app.incident_digest(first_id)
            sub_events_before = [e for e in app.store.replay()
                                 if e["payload"].get("incident_id") == second_id]

            reloaded = SafeguardingApp(store_path=path)
            # 重启重放后统一视图给出相同结论
            self.assertEqual(reloaded.incident_digest(first_id), digest_before)
            self.assertEqual([e for e in reloaded.store.replay()
                              if e["payload"].get("incident_id") == second_id],
                             sub_events_before)
            # 幂等索引恢复：重复回调仍返回首次结果
            again = reloaded.platform_callback(callback)
            self.assertTrue(again["duplicate"])
            self.assertEqual(again["incident_id"], first_id)
            self.assertEqual(again["routed_from"], [second_id])
            # 冲突检测在重放后同样有效
            altered = json.loads(json.dumps(callback))
            altered["receipt"]["status"] = "processing"
            conflict = reloaded.platform_callback(altered)
            self.assertTrue(conflict["conflict"])
            # 子案件在重放后依旧没有新事件，重复与冲突回调都不落账
            self.assertEqual([e for e in reloaded.store.replay()
                              if e["payload"].get("incident_id") == second_id],
                             sub_events_before)
            self.assertEqual(len(reloaded.store.replay()), len(app.store.replay()))


class MergedCallbackHttpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = SafeguardingApp()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(cls.app))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def _request(self, method, path, payload=None):
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else None
        request = Request(f"{self.base_url}{path}", data=data, method=method,
                          headers={"Content-Type": "application/json"})
        try:
            with urlopen(request, timeout=3) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            return error.code, json.load(error)

    def test_merged_callback_flow_over_http(self):
        first = dict(abuse_report(actor=AGENT))
        status, body = self._request("POST", "/reports", first)
        self.assertEqual(status, 201)
        first_id = body["incident_id"]
        second = dict(abuse_report(
            actor=AGENT, content_url="https://video.example/comment/55?mirror=1",
            receipts=[{"receipt_id": "DY-8840217", "platform": "douyin",
                       "status": "accepted"}]))
        status, body = self._request("POST", "/reports", second)
        self.assertEqual(status, 201)
        second_id = body["incident_id"]

        status, body = self._request("GET", "/suggestions")
        self.assertEqual(status, 200)
        sugg_id = body["suggestions"][0]["suggestion_id"]
        status, body = self._request("POST", f"/suggestions/{sugg_id}", {
            "actor": OFFICER, "decision": "accept", "target_incident": first_id})
        self.assertEqual(status, 200)
        self.assertEqual(body["merged_into"], first_id)

        callback = {"callback_id": "CB-HTTP-MERGED", "incident_id": second_id,
                    "receipt": {"receipt_id": "DY-8840217", "platform": "douyin",
                                "status": "removed",
                                "content_url": "https://video.example/comment/55?mirror=1"}}
        status, body = self._request("POST", "/callbacks/platform", callback)
        self.assertEqual(status, 200)
        self.assertFalse(body["duplicate"])
        self.assertEqual(body["incident_id"], first_id)
        self.assertEqual(body["routed_from"], [second_id])

        status, digest = self._request("GET", f"/incidents/{first_id}/digest")
        self.assertEqual(status, 200)
        receipts = [r for r in digest["证据依据"]["platform_receipts"]
                    if r["receipt_id"] == "DY-8840217"]
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0]["status"], "removed")
        states = {e["content_ref"]: e["state"] for e in digest["证据依据"]["evidence"]}
        self.assertEqual(states["https://video.example/comment/55?mirror=1"], "deleted")
        # 子案件视图中没有新增回执
        status, sub_digest = self._request("GET", f"/incidents/{second_id}/digest")
        self.assertEqual(status, 200)
        self.assertFalse(any(r["receipt_id"] == "DY-8840217"
                             for r in sub_digest["证据依据"]["platform_receipts"]))

        # 重复回调安全重放
        status, body = self._request("POST", "/callbacks/platform", callback)
        self.assertEqual(status, 200)
        self.assertTrue(body["duplicate"])
        self.assertNotIn("conflict", body)
        # 同键不同内容：409 报冲突并保留首次结果
        altered = json.loads(json.dumps(callback))
        altered["receipt"]["status"] = "processing"
        status, body = self._request("POST", "/callbacks/platform", altered)
        self.assertEqual(status, 409)
        self.assertTrue(body["conflict"])
        self.assertEqual(body["attached"], ["receipt", "content_deleted"])
        # 通知查询与之一致：回调没有产生任何通知
        status, body = self._request("GET", f"/notifications?incident_id={first_id}")
        self.assertEqual(status, 200)
        self.assertEqual(body["notifications"], [])


class PersistenceTest(unittest.TestCase):
    def test_ledger_replay_restores_state_and_callback_idempotency(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "events.jsonl")
            app = SafeguardingApp(store_path=path)
            incident_id = app.submit_report(abuse_report(), AGENT)["incident_id"]
            app.platform_callback({
                "callback_id": "CB-PERSIST", "incident_id": incident_id,
                "receipt": {"receipt_id": "R1", "platform": "douyin", "status": "processing"}})

            reloaded = SafeguardingApp(store_path=path)
            self.assertIn(incident_id, reloaded.incidents)
            again = reloaded.platform_callback({
                "callback_id": "CB-PERSIST", "incident_id": incident_id,
                "receipt": {"receipt_id": "R1", "platform": "douyin", "status": "removed"}})
            self.assertTrue(again["duplicate"])  # 重放后重复回调仍不二次处理
            self.assertEqual(len(reloaded.list_notifications()), 0)


class HttpContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = SafeguardingApp()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(cls.app))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def _request(self, method, path, payload=None):
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else None
        request = Request(f"{self.base_url}{path}", data=data, method=method,
                          headers={"Content-Type": "application/json"})
        try:
            with urlopen(request, timeout=3) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            return error.code, json.load(error)

    def test_full_flow_over_http(self):
        status, body = self._request("POST", "/reports", threat_report(actor=AGENT))
        self.assertEqual(status, 201)
        incident_id = body["incident_id"]

        status, body = self._request(
            "GET", f"/incidents/{incident_id}/digest?as_role={quote('俱乐部保护专员')}")
        self.assertEqual(status, 200)
        self.assertTrue(body["尚未完成的保护动作"]["open_escalation"])

        status, body = self._request("POST", f"/incidents/{incident_id}/escalation/ack",
                                     {"actor": DUTY})
        self.assertEqual(status, 200)

        status, body = self._request("POST", f"/incidents/{incident_id}/actions",
                                     {"actor": AGENT, "action_type": "police_report"})
        self.assertEqual(status, 201)
        action_id = body["action_id"]
        self.assertEqual(body["required_reviewer_role"], "法务复核员")

        status, body = self._request("POST", f"/actions/{action_id}/review",
                                     {"actor": LIASON, "decision": "approve"})
        self.assertEqual(status, 403)
        status, body = self._request("POST", f"/actions/{action_id}/review",
                                     {"actor": LEGAL, "decision": "approve"})
        self.assertEqual(status, 200)
        status, body = self._request("POST", f"/actions/{action_id}/execute", {"actor": LEGAL})
        self.assertEqual(status, 200)
        self.assertIn("transfer_ref", body["result"])

        # 重复回调
        cb = {"callback_id": "CB-HTTP", "incident_id": incident_id,
              "receipt": {"receipt_id": "WB-1", "platform": "weibo", "status": "accepted"}}
        status, first = self._request("POST", "/callbacks/platform", cb)
        self.assertEqual(status, 200)
        self.assertFalse(first["duplicate"])
        status, second = self._request("POST", "/callbacks/platform", cb)
        self.assertTrue(second["duplicate"])

    def test_criticism_report_returns_200_without_incident(self):
        status, body = self._request("POST", "/reports", {
            "actor": AGENT, "victim_code": "ATH-020", "platform": "weibo",
            "content_url": "https://weibo.example/comment/2",
            "raw_excerpt": CRITICISM_TEXT, "severity": "criticism"})
        self.assertEqual(status, 200)
        self.assertIsNone(body["incident_id"])

    def test_unknown_route_is_404(self):
        status, _ = self._request("GET", "/unknown")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
