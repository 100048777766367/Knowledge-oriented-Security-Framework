"""
KOS Logic Analysis Layer
=========================
Module: logic_engine.py
Purpose: Tiếp nhận AlertEvent từ Perception Layer, phân tầng nguy cơ (Layer A–E),
         chấm điểm uy tín IP (IP Reputation), và trả về đối tượng Intelligence.

Pipeline:
  PerceptionLayer → [AlertEvent] → LogicEngine → [Intelligence] → Response Layer

Phân tầng nguy cơ (dựa trên rule.level của Wazuh):
  Layer A : level 0–2   │ Bình thường, không đáng kể
  Layer B : level 3–4   │ Thông tin, theo dõi nhẹ
  Layer C : level 5–7   │ Đáng ngờ, cần theo dõi
  Layer D : level 8–9   │ Cảnh báo, cần điều tra
  Layer E : level 10+   │ Tấn công nghiêm trọng (Brute Force / Exploit / Rootkit)
"""

import json
import os
import logging
import threading
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List, Callable
from enum import Enum

# Import từ Perception Layer
# (kos_kernel.py phải nằm cùng thư mục hoặc trong PYTHONPATH)
try:
    from src.kos_kernel import AlertEvent
except ImportError:
    # Fallback: định nghĩa lại AlertEvent tối giản để module chạy độc lập
    from dataclasses import dataclass as _dc

    @_dc
    class AlertEvent:  # type: ignore
        timestamp: str
        rule_id: str
        rule_level: int
        rule_description: str
        agent_name: str
        srcip: str
        raw: Dict[str, Any] = field(default_factory=dict)

        def to_dict(self):
            return {k: v for k, v in self.__dict__.items() if k != "raw"}


# ─────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("KOS.LogicEngine")


# ─────────────────────────────────────────────
# Enums & Constants
# ─────────────────────────────────────────────
class RiskLayer(str, Enum):
    """Phân tầng nguy cơ KOS (A–E)."""
    A = "A"  # level 0–2  : Bình thường
    B = "B"  # level 3–4  : Theo dõi nhẹ
    C = "C"  # level 5–7  : Đáng ngờ
    D = "D"  # level 8–9  : Cảnh báo
    E = "E"  # level 10+  : Tấn công nghiêm trọng


class ThreatCategory(str, Enum):
    """Danh mục loại tấn công."""
    NORMAL          = "Normal Activity"
    RECON           = "Reconnaissance"
    BRUTE_FORCE     = "Brute Force"
    EXPLOIT         = "Exploitation"
    MALWARE         = "Malware / Rootkit"
    POLICY          = "Policy Violation"
    UNKNOWN         = "Unknown Threat"


# Ánh xạ rule.level → RiskLayer
LEVEL_TO_LAYER: Dict[range, RiskLayer] = {
    range(0,  3):  RiskLayer.A,
    range(3,  5):  RiskLayer.B,
    range(5,  8):  RiskLayer.C,
    range(8,  10): RiskLayer.D,
    range(10, 16): RiskLayer.E,
}

# Từ khóa phát hiện loại tấn công từ rule_description
THREAT_KEYWORDS: List[tuple] = [
    (ThreatCategory.BRUTE_FORCE, ["brute force", "authentication fail", "login fail",
                                   "multiple auth", "invalid user", "repeated fail"]),
    (ThreatCategory.EXPLOIT,     ["exploit", "overflow", "injection", "rce", "lfi", "rfi",
                                   "command injection", "sql injection", "xss"]),
    (ThreatCategory.MALWARE,     ["rootkit", "malware", "trojan", "backdoor", "hidden process",
                                   "suspicious process", "ransomware"]),
    (ThreatCategory.RECON,       ["scan", "probe", "enumeration", "nmap", "recon",
                                   "port scan", "sweep"]),
    (ThreatCategory.POLICY,      ["policy", "unauthorized", "forbidden", "access denied",
                                   "privilege escalation", "sudo"]),
]

# Cấu hình IP Reputation
REPUTATION_INITIAL_SCORE  = 100   # Điểm khởi đầu cho mọi IP
REPUTATION_PENALTY_LAYER_E = 15   # Trừ điểm mỗi lần xuất hiện ở Layer E
REPUTATION_PENALTY_LAYER_D =  5   # Trừ điểm mỗi lần xuất hiện ở Layer D
REPUTATION_PENALTY_LAYER_C =  2   # Trừ điểm nhẹ ở Layer C
REPUTATION_FLOOR           =  0   # Điểm tối thiểu
REPUTATION_BLOCKED_THRESHOLD = 30 # Ngưỡng để đánh dấu BLOCKED


# ─────────────────────────────────────────────
# Data Model: Intelligence
# ─────────────────────────────────────────────
@dataclass
class Intelligence:
    """
    Kết quả phân tích từ LogicEngine.
    Đây là đơn vị dữ liệu được truyền sang Response / Output Layer.
    """
    # Nguồn gốc
    source_event: AlertEvent

    # Phân tầng nguy cơ
    risk_layer: RiskLayer
    threat_category: ThreatCategory

    # IP Reputation
    ip_reputation_score: int          # 0–100
    ip_reputation_label: str          # TRUSTED / SUSPICIOUS / DANGEROUS / BLOCKED
    ip_total_layer_e_hits: int        # Số lần IP xuất hiện ở Layer E

    # Metadata phân tích
    analyzed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    recommended_action: str = ""
    notes: List[str] = field(default_factory=list)

    # ── Derived properties ──────────────────────────────────────────────
    @property
    def is_critical(self) -> bool:
        return self.risk_layer == RiskLayer.E

    @property
    def requires_immediate_action(self) -> bool:
        return self.risk_layer in (RiskLayer.D, RiskLayer.E) or self.ip_reputation_score < REPUTATION_BLOCKED_THRESHOLD

    def to_dict(self) -> Dict[str, Any]:
        """Serialize Intelligence (không bao gồm raw event data)."""
        return {
            "analyzed_at": self.analyzed_at,
            "risk_layer": self.risk_layer.value,
            "threat_category": self.threat_category.value,
            "recommended_action": self.recommended_action,
            "is_critical": self.is_critical,
            "requires_immediate_action": self.requires_immediate_action,
            "ip_reputation": {
                "score": self.ip_reputation_score,
                "label": self.ip_reputation_label,
                "layer_e_hits": self.ip_total_layer_e_hits,
            },
            "alert": self.source_event.to_dict(),
            "notes": self.notes,
        }

    def __str__(self) -> str:
        return (
            f"[Layer {self.risk_layer.value}] {self.threat_category.value} | "
            f"IP: {self.source_event.srcip} "
            f"(Score: {self.ip_reputation_score} – {self.ip_reputation_label}) | "
            f"{self.source_event.rule_description}"
        )


# ─────────────────────────────────────────────
# IP Reputation Database
# ─────────────────────────────────────────────
class IPReputationDB:
    """
    Quản lý điểm uy tín IP, lưu trữ persistent vào reputation_db.json.

    Schema của mỗi bản ghi:
    {
        "score": 85,
        "label": "SUSPICIOUS",
        "layer_e_hits": 1,
        "layer_d_hits": 2,
        "layer_c_hits": 0,
        "first_seen": "2025-01-15T...",
        "last_seen": "2025-01-15T...",
        "history": [ { "timestamp": ..., "rule_id": ..., "layer": ... } ]
    }
    """

    def __init__(self, db_path: str = "reputation_db.json"):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._db: Dict[str, Any] = {}
        self._load()

    # ── Persistence ────────────────────────────────────────────────────
    def _load(self):
        """Tải database từ file (nếu tồn tại)."""
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, "r", encoding="utf-8") as f:
                    self._db = json.load(f)
                logger.info(f"Đã tải reputation DB: {len(self._db)} IPs từ {self.db_path}")
            except (json.JSONDecodeError, OSError) as e:
                logger.error(f"Lỗi tải reputation DB: {e}. Khởi tạo DB mới.")
                self._db = {}
        else:
            logger.info(f"Tạo mới reputation DB: {self.db_path}")
            self._db = {}

    def _save(self):
        """Ghi database ra file JSON (gọi sau mỗi update)."""
        try:
            tmp_path = self.db_path + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(self._db, f, ensure_ascii=False, indent=2)
            os.replace(tmp_path, self.db_path)  # Atomic write
        except OSError as e:
            logger.error(f"Lỗi ghi reputation DB: {e}")

    # ── Core Logic ────────────────────────────────────────────────────
    def _init_ip(self, ip: str) -> Dict[str, Any]:
        """Khởi tạo bản ghi mới cho IP chưa từng gặp."""
        now = datetime.now(timezone.utc).isoformat()
        return {
            "score": REPUTATION_INITIAL_SCORE,
            "label": "TRUSTED",
            "layer_e_hits": 0,
            "layer_d_hits": 0,
            "layer_c_hits": 0,
            "first_seen": now,
            "last_seen": now,
            "history": [],
        }

    @staticmethod
    def _compute_label(score: int) -> str:
        """Chuyển điểm số thành nhãn."""
        if score >= 80:
            return "TRUSTED"
        elif score >= 60:
            return "SUSPICIOUS"
        elif score >= REPUTATION_BLOCKED_THRESHOLD:
            return "DANGEROUS"
        return "BLOCKED"

    def update(self, ip: str, layer: RiskLayer, event: AlertEvent) -> Dict[str, Any]:
        """
        Cập nhật điểm uy tín cho IP sau mỗi alert.

        Args:
            ip:    Địa chỉ IP nguồn.
            layer: Tầng nguy cơ của alert hiện tại.
            event: AlertEvent liên quan.

        Returns:
            Bản ghi reputation hiện tại của IP.
        """
        if not ip or ip in ("N/A", "unknown", ""):
            return {"score": 100, "label": "N/A", "layer_e_hits": 0}

        with self._lock:
            if ip not in self._db:
                self._db[ip] = self._init_ip(ip)

            record = self._db[ip]
            now = datetime.now(timezone.utc).isoformat()

            # Tính điểm phạt
            penalty = 0
            if layer == RiskLayer.E:
                penalty = REPUTATION_PENALTY_LAYER_E
                record["layer_e_hits"] += 1
            elif layer == RiskLayer.D:
                penalty = REPUTATION_PENALTY_LAYER_D
                record["layer_d_hits"] += 1
            elif layer == RiskLayer.C:
                penalty = REPUTATION_PENALTY_LAYER_C
                record["layer_c_hits"] += 1

            # Cập nhật điểm (không xuống dưới 0)
            record["score"] = max(REPUTATION_FLOOR, record["score"] - penalty)
            record["label"] = self._compute_label(record["score"])
            record["last_seen"] = now

            # Ghi lịch sử (giữ tối đa 50 sự kiện gần nhất)
            record["history"].append({
                "timestamp": event.timestamp,
                "rule_id": event.rule_id,
                "rule_level": event.rule_level,
                "layer": layer.value,
                "agent": event.agent_name,
            })
            if len(record["history"]) > 50:
                record["history"] = record["history"][-50:]

            self._save()

            if penalty > 0:
                logger.info(
                    f"[ReputationDB] {ip} → Score: {record['score']} "
                    f"({self._compute_label(record['score'])}) "
                    f"[-{penalty}pts | Layer {layer.value}]"
                )

            return dict(record)

    def get(self, ip: str) -> Dict[str, Any]:
        """Lấy thông tin reputation của một IP."""
        with self._lock:
            return dict(self._db.get(ip, self._init_ip(ip)))

    def get_all_blocked(self) -> Dict[str, Any]:
        """Trả về danh sách tất cả IP bị BLOCKED."""
        with self._lock:
            return {ip: rec for ip, rec in self._db.items() if rec["label"] == "BLOCKED"}

    def get_stats(self) -> Dict[str, int]:
        """Thống kê tổng quan database."""
        with self._lock:
            labels = [r["label"] for r in self._db.values()]
            return {
                "total_ips": len(self._db),
                "trusted":   labels.count("TRUSTED"),
                "suspicious": labels.count("SUSPICIOUS"),
                "dangerous": labels.count("DANGEROUS"),
                "blocked":   labels.count("BLOCKED"),
            }

    def export_report(self) -> List[Dict[str, Any]]:
        """Xuất danh sách IP theo thứ tự điểm tăng dần (nguy hiểm nhất trước)."""
        with self._lock:
            records = [{"ip": ip, **rec} for ip, rec in self._db.items()]
            return sorted(records, key=lambda x: x["score"])


# ─────────────────────────────────────────────
# Classifier
# ─────────────────────────────────────────────
class ThreatClassifier:
    """Phân loại loại mối đe dọa dựa trên rule_description."""

    @staticmethod
    def classify(description: str) -> ThreatCategory:
        desc_lower = description.lower()
        for category, keywords in THREAT_KEYWORDS:
            if any(kw in desc_lower for kw in keywords):
                return category
        return ThreatCategory.UNKNOWN

    @staticmethod
    def get_layer(level: int) -> RiskLayer:
        """Ánh xạ rule.level → RiskLayer."""
        for level_range, layer in LEVEL_TO_LAYER.items():
            if level in level_range:
                return layer
        return RiskLayer.E  # Mọi level > 15 cũng là Layer E

    @staticmethod
    def recommend_action(layer: RiskLayer, category: ThreatCategory, rep_score: int) -> str:
        """Đề xuất hành động dựa trên tầng và loại mối đe dọa."""
        if rep_score < REPUTATION_BLOCKED_THRESHOLD:
            return "🚫 BLOCK IP ngay lập tức – Điểm uy tín cực thấp"

        actions = {
            RiskLayer.A: "✅ Ghi log, không cần hành động",
            RiskLayer.B: "📋 Ghi log và theo dõi định kỳ",
            RiskLayer.C: "👀 Theo dõi chặt, kiểm tra context xung quanh",
            RiskLayer.D: "⚠️ Điều tra ngay, tạo ticket phân tích",
            RiskLayer.E: "🚨 PHẢN ỨNG NGAY – Cô lập agent, thu thập forensics",
        }

        base_action = actions.get(layer, "Theo dõi")

        # Bổ sung theo loại mối đe dọa
        supplements = {
            ThreatCategory.BRUTE_FORCE: " | Kiểm tra chính sách lockout, xem xét block IP",
            ThreatCategory.EXPLOIT:     " | Patch ngay lập tức, rà soát IOC",
            ThreatCategory.MALWARE:     " | Cô lập máy, chạy AV scan toàn bộ",
            ThreatCategory.RECON:       " | Giám sát traffic, tăng log verbosity",
            ThreatCategory.POLICY:      " | Xem xét quyền truy cập, báo cáo quản lý",
        }

        return base_action + supplements.get(category, "")


# ─────────────────────────────────────────────
# Logic Engine – Core Class
# ─────────────────────────────────────────────
class LogicEngine:
    """
    KOS Logic Analysis Layer.

    Quy trình xử lý mỗi AlertEvent:
      1. Phân tầng nguy cơ (Layer A–E) theo rule.level
      2. Phân loại mối đe dọa (ThreatCategory) theo rule_description
      3. Cập nhật điểm uy tín IP (IPReputationDB)
      4. Tạo đối tượng Intelligence
      5. Gọi callback on_intelligence để chuyển sang Response Layer

    Ví dụ:
      engine = LogicEngine(on_intelligence=my_response_handler)
      engine.process(alert_event)
    """

    def __init__(
        self,
        reputation_db_path: str = "reputation_db.json",
        on_intelligence: Optional[Callable[[Intelligence], None]] = None,
    ):
        """
        Args:
            reputation_db_path: Đường dẫn file lưu IP reputation.
            on_intelligence:    Callback gửi Intelligence sang Response Layer.
        """
        self.reputation_db = IPReputationDB(db_path=reputation_db_path)
        self.on_intelligence = on_intelligence or self._default_output
        self._classifier = ThreatClassifier()

        self._stats = {
            "total_processed": 0,
            "layer_counts": {l.value: 0 for l in RiskLayer},
            "category_counts": {c.value: 0 for c in ThreatCategory},
        }
        self._lock = threading.Lock()

        logger.info(f"LogicEngine khởi tạo | Reputation DB: {reputation_db_path}")

    # ── Public API ────────────────────────────────────────────────────
    def process(self, event: AlertEvent) -> Intelligence:
        """
        Phân tích một AlertEvent và trả về Intelligence.
        Đây là hàm chính được gọi từ Perception Layer.

        Args:
            event: AlertEvent từ PerceptionLayer.

        Returns:
            Intelligence object đã phân tích đầy đủ.
        """
        # 1. Phân tầng nguy cơ
        layer = self._classifier.get_layer(event.rule_level)

        # 2. Phân loại mối đe dọa
        category = self._classifier.classify(event.rule_description)

        # 3. Cập nhật IP Reputation
        rep_record = self.reputation_db.update(event.srcip, layer, event)
        rep_score  = rep_record.get("score", 100)
        rep_label  = rep_record.get("label", "TRUSTED")
        layer_e_hits = rep_record.get("layer_e_hits", 0)

        # 4. Đề xuất hành động
        action = self._classifier.recommend_action(layer, category, rep_score)

        # 5. Ghi chú bổ sung
        notes = self._build_notes(event, layer, category, rep_score, layer_e_hits)

        # 6. Tạo Intelligence object
        intel = Intelligence(
            source_event=event,
            risk_layer=layer,
            threat_category=category,
            ip_reputation_score=rep_score,
            ip_reputation_label=rep_label,
            ip_total_layer_e_hits=layer_e_hits,
            recommended_action=action,
            notes=notes,
        )

        # 7. Cập nhật thống kê
        with self._lock:
            self._stats["total_processed"] += 1
            self._stats["layer_counts"][layer.value] += 1
            self._stats["category_counts"][category.value] += 1

        # 8. Gọi callback sang Response Layer
        try:
            self.on_intelligence(intel)
        except Exception as e:
            logger.error(f"Lỗi trong on_intelligence callback: {e}")

        return intel

    def get_stats(self) -> Dict[str, Any]:
        """Thống kê xử lý của LogicEngine."""
        with self._lock:
            return {**self._stats, "reputation_db": self.reputation_db.get_stats()}

    def get_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Tra cứu reputation của một IP cụ thể."""
        return self.reputation_db.get(ip)

    def get_blocked_ips(self) -> Dict[str, Any]:
        """Trả về tất cả IP đang bị BLOCKED."""
        return self.reputation_db.get_all_blocked()

    def export_reputation_report(self) -> List[Dict[str, Any]]:
        """Xuất báo cáo reputation đầy đủ, sắp xếp theo mức nguy hiểm."""
        return self.reputation_db.export_report()

    # ── Internal Helpers ─────────────────────────────────────────────
    @staticmethod
    def _build_notes(
        event: AlertEvent,
        layer: RiskLayer,
        category: ThreatCategory,
        rep_score: int,
        layer_e_hits: int,
    ) -> List[str]:
        """Tạo danh sách ghi chú ngữ cảnh."""
        notes = []

        if layer == RiskLayer.E:
            notes.append(f"⚡ Layer E kích hoạt – rule level {event.rule_level} vượt ngưỡng nghiêm trọng (≥10)")

        if layer_e_hits > 1:
            notes.append(f"🔁 IP này đã xuất hiện {layer_e_hits} lần ở Layer E – hành vi tái diễn")

        if rep_score < REPUTATION_BLOCKED_THRESHOLD:
            notes.append(f"🔴 IP uy tín cực thấp ({rep_score}/100) – khuyến nghị BLOCK")
        elif rep_score < 60:
            notes.append(f"🟡 IP uy tín thấp ({rep_score}/100) – cần theo dõi tăng cường")

        if category == ThreatCategory.BRUTE_FORCE and layer in (RiskLayer.D, RiskLayer.E):
            notes.append("🔐 Nghi ngờ tấn công Brute Force – kiểm tra account lockout policy")

        if category == ThreatCategory.MALWARE:
            notes.append("☣️ Dấu hiệu Malware/Rootkit – ưu tiên cô lập ngay")

        if event.srcip in ("N/A", "unknown", ""):
            notes.append("ℹ️ Không có srcip – alert nội bộ hoặc thiếu metadata")

        return notes

    @staticmethod
    def _default_output(intel: Intelligence):
        """Output mặc định nếu chưa kết nối Response Layer."""
        layer_icons = {
            RiskLayer.A: "🟢", RiskLayer.B: "🔵",
            RiskLayer.C: "🟡", RiskLayer.D: "🟠", RiskLayer.E: "🔴",
        }
        icon = layer_icons.get(intel.risk_layer, "⚪")
        print(f"\n{icon} {intel}")
        print(f"   ↳ Hành động: {intel.recommended_action}")
        if intel.notes:
            for note in intel.notes:
                print(f"   ↳ {note}")


# ─────────────────────────────────────────────
# Pipeline Helper: kết nối 2 layer
# ─────────────────────────────────────────────
def build_kos_pipeline(
    alerts_path: str,
    reputation_db_path: str = "reputation_db.json",
    on_intelligence: Optional[Callable[[Intelligence], None]] = None,
):
    """
    Hàm tiện ích tạo pipeline hoàn chỉnh:
      PerceptionLayer → LogicEngine → on_intelligence callback

    Args:
        alerts_path:         Đường dẫn alerts.json của Wazuh.
        reputation_db_path:  Đường dẫn file reputation DB.
        on_intelligence:     Callback nhận Intelligence (Response Layer).

    Returns:
        (perception_layer, logic_engine) – gọi perception_layer.listen() để chạy.
    """
    try:
        from src.kos_kernel import PerceptionLayer
    except ImportError:
        raise ImportError("Không tìm thấy kos_kernel.py. Đảm bảo file nằm cùng thư mục.")

    engine = LogicEngine(
        reputation_db_path=reputation_db_path,
        on_intelligence=on_intelligence,
    )

    perception = PerceptionLayer(
        alerts_path=alerts_path,
        on_event=engine.process,
    )

    return perception, engine


# ─────────────────────────────────────────────
# Entry Point – Demo / Standalone Test
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    argp = argparse.ArgumentParser(description="KOS Logic Engine – Analysis Layer")
    argp.add_argument("--db", default="reputation_db.json", help="Đường dẫn reputation DB")
    argp.add_argument("--report", action="store_true", help="Xuất báo cáo IP reputation")
    argp.add_argument("--demo",   action="store_true", help="Chạy demo với dữ liệu mẫu")
    args = argp.parse_args()

    engine = LogicEngine(reputation_db_path=args.db)

    if args.report:
        # ── Xuất báo cáo ──────────────────────────────────────────────
        report = engine.export_reputation_report()
        print(f"\n{'═'*65}")
        print(f"  KOS IP REPUTATION REPORT  ({len(report)} IPs)")
        print(f"{'═'*65}")
        for rec in report:
            label_icon = {"TRUSTED": "🟢", "SUSPICIOUS": "🟡", "DANGEROUS": "🟠", "BLOCKED": "🔴"}.get(rec["label"], "⚪")
            print(
                f"  {label_icon} {rec['ip']:<18} Score: {rec['score']:>3}/100  "
                f"LayerE: {rec['layer_e_hits']}x  "
                f"Last: {rec.get('last_seen', 'N/A')[:19]}"
            )
        print(f"{'═'*65}")
        stats = engine.reputation_db.get_stats()
        print(f"  Tổng: {stats['total_ips']} IPs | "
              f"Trusted: {stats['trusted']} | Suspicious: {stats['suspicious']} | "
              f"Dangerous: {stats['dangerous']} | Blocked: {stats['blocked']}")

    elif args.demo:
        # ── Demo với dữ liệu AlertEvent mẫu ──────────────────────────
        print(f"\n{'═'*65}")
        print("  KOS Logic Engine – DEMO MODE")
        print(f"{'═'*65}\n")

        SAMPLE_EVENTS = [
            AlertEvent("2025-01-15T08:00:00Z", "1001", 1,  "System boot",                 "server-01", "N/A"),
            AlertEvent("2025-01-15T08:05:00Z", "2501", 3,  "User login success",           "server-01", "10.0.0.5"),
            AlertEvent("2025-01-15T08:10:00Z", "5710", 5,  "SSH port probe detected",      "server-02", "185.220.101.45"),
            AlertEvent("2025-01-15T08:11:00Z", "5710", 5,  "SSH port probe detected",      "server-02", "185.220.101.45"),
            AlertEvent("2025-01-15T08:15:00Z", "5712", 8,  "Multiple SSH auth failures",   "server-02", "185.220.101.45"),
            AlertEvent("2025-01-15T08:20:00Z", "5712", 10, "SSH brute force attack",       "server-02", "185.220.101.45"),
            AlertEvent("2025-01-15T08:21:00Z", "5712", 10, "SSH brute force attack",       "server-03", "185.220.101.45"),
            AlertEvent("2025-01-15T08:25:00Z", "31151",13, "Web exploit attempt detected", "web-01",    "91.108.56.170"),
            AlertEvent("2025-01-15T08:30:00Z", "87002",15, "Rootkit hidden process found", "db-server", "172.16.0.200"),
            AlertEvent("2025-01-15T08:35:00Z", "5712", 10, "SSH brute force attack",       "server-04", "185.220.101.45"),
        ]

        results = []
        for ev in SAMPLE_EVENTS:
            intel = engine.process(ev)
            results.append(intel)
            print()

        # Tóm tắt
        print(f"\n{'═'*65}")
        print("  TỔNG KẾT PHÂN TÍCH")
        print(f"{'═'*65}")
        stats = engine.get_stats()
        print(f"  Tổng xử lý  : {stats['total_processed']} events")
        print(f"  Phân tầng   : {stats['layer_counts']}")
        print(f"  Loại mối đe : {stats['category_counts']}")
        print(f"\n  IP Reputation DB:")
        rep_stats = stats['reputation_db']
        print(f"  ├─ Tổng IPs  : {rep_stats['total_ips']}")
        print(f"  ├─ Trusted   : {rep_stats['trusted']}")
        print(f"  ├─ Suspicious: {rep_stats['suspicious']}")
        print(f"  ├─ Dangerous : {rep_stats['dangerous']}")
        print(f"  └─ Blocked   : {rep_stats['blocked']}")

        blocked = engine.get_blocked_ips()
        if blocked:
            print(f"\n  🚫 IPs bị BLOCKED:")
            for ip, rec in blocked.items():
                print(f"     {ip} – Score: {rec['score']} – Layer E hits: {rec['layer_e_hits']}")

        print(f"\n  Reputation DB đã lưu tại: {args.db}")
        print(f"{'═'*65}")

    else:
        print("Dùng --demo để chạy thử, hoặc --report để xem báo cáo IP.")
        print("Ví dụ: python logic_engine.py --demo")
