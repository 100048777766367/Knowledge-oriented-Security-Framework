"""
╔══════════════════════════════════════════════════════════════════════════════╗
║          KOS – Knowledge-oriented Security Framework  │  main.py                       ║
║          Hệ thống Phân tích Bảo mật Thông minh cho SMBs                      ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                 ║
║                                              ║
║          ║
║  Ngày       : 2026-04-11                                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝

LUỒNG XỬ LÝ CHÍNH (3 tầng):
┌─────────────────────────────────────────────────────────────────────────────┐
│  Wazuh alerts.json                                                          │
│       │                                                                     │
│       ▼  [TẦNG 1 – PERCEPTION]                                              │
│  PerceptionLayer (kos_kernel.py)                                            │
│    • Giám sát file bằng watchdog hoặc polling                               │
│    • Parse log thô → AlertEvent (có xử lý log Wazuh thật)                  │
│       │  perception_data: AlertEvent                                        │
│       ▼  [TẦNG 2 – LOGIC ANALYSIS]                                          │
│  LogicEngine (logic_engine.py)                                              │
│    • Phân tầng nguy cơ A–E theo rule.level                                  │
│    • Phân loại mối đe dọa (Brute Force / Exploit / Malware…)               │
│    • Chấm điểm IP Reputation → reputation_db.json                          │
│       │  threat_intel: Intelligence                                         │
│       ▼  [TẦNG 3 – OPERATION]                                               │
│  OperationCenter (operation_center.py)                                      │
│    • Tạo incident_<ID>.md (báo cáo)                          │
│    • Tạo remedy_<ID>.sh   (kịch bản chặn IP iptables/ufw)                  │
│       │  knowledge_node: KnowledgeNode                                      │
│       ▼  [KHO TRI THỨC]                                                     │
│  KnowledgeBase                                                              │
│    • Lưu lịch sử vào knowledge_store.json để đối chiếu sau này             │
└─────────────────────────────────────────────────────────────────────────────┘

YÊU CẦU:
  pip install watchdog
  Python 3.8+

CÁCH CHẠY:
  # Chế độ demo (không cần Wazuh thật):
  python main.py --demo

  # Chế độ production (trỏ vào Wazuh thật):
  python main.py --alerts /var/ossec/logs/alerts/alerts.json

  # Xem báo cáo knowledge base:
  python main.py --knowledge-report
"""

# ══════════════════════════════════════════════════════════════════════════════
#  IMPORTS – Thư viện chuẩn Python
# ══════════════════════════════════════════════════════════════════════════════
import os           # Thao tác file/thư mục
import re           # Regex để trích xuất dữ liệu từ log thô
import sys          # Thoát chương trình, đường dẫn module
import json         # Đọc/ghi JSON
import time         # Dừng chương trình tạm thời
import signal       # Bắt tín hiệu dừng (Ctrl+C)
import logging      # Ghi log hệ thống
import threading    # Xử lý đa luồng
import argparse     # Phân tích tham số dòng lệnh
from datetime import datetime, timezone  # Xử lý thời gian chuẩn UTC
from dataclasses import dataclass, field, asdict  # Cấu trúc dữ liệu có kiểu
from typing import Optional, Dict, Any, List, Callable  # Gợi ý kiểu dữ liệu
from pathlib import Path  # Thao tác đường dẫn an toàn
from collections import defaultdict  # Dict có giá trị mặc định

# ══════════════════════════════════════════════════════════════════════════════
#  IMPORTS – Các module KOS
#  Sử dụng try/except để chương trình không "văng" nếu thiếu module
# ══════════════════════════════════════════════════════════════════════════════
_import_errors: List[str] = []  # Thu thập lỗi import để báo cáo sau

try:
    from src.kos_kernel import PerceptionLayer, AlertEvent, AlertParser
except ImportError as _e:
    _import_errors.append(f"kos_kernel: {_e}")
    PerceptionLayer = None  # type: ignore
    AlertEvent = None       # type: ignore
    AlertParser = None      # type: ignore

try:
    from src.logic_engine import LogicEngine, Intelligence, RiskLayer, ThreatCategory
except ImportError as _e:
    _import_errors.append(f"logic_engine: {_e}")
    LogicEngine = None      # type: ignore
    Intelligence = None     # type: ignore
    RiskLayer = None        # type: ignore
    ThreatCategory = None   # type: ignore

try:
    from src.operation_center import OperationCenter
except ImportError as _e:
    _import_errors.append(f"operation_center: {_e}")
    OperationCenter = None  # type: ignore


# ══════════════════════════════════════════════════════════════════════════════
#  CẤU HÌNH HỆ THỐNG
#  Tập trung tất cả hằng số vào một chỗ để dễ chỉnh sửa khi demo
# ══════════════════════════════════════════════════════════════════════════════
class KOSConfig:
    """
    Cấu hình trung tâm của hệ thống KOS.
    Thay đổi các giá trị tại đây để tinh chỉnh hành vi hệ thống.
    """
    # Đường dẫn mặc định
    ALERTS_FILE       = "/var/ossec/logs/alerts/alerts.json"
    REPUTATION_DB     = "knowledge_base/reputation_db.json"
    KNOWLEDGE_STORE   = "knowledge_base/knowledge_store.json"
    OUTPUT_DIR        = "reports"
    LOG_FILE          = "kos_system.log"

    # Hành vi hệ thống
    POLL_INTERVAL_SEC   = 1.0   # Chu kỳ polling khi không có watchdog
    AUTO_FLUSH_SEC      = 300   # Tự tạo báo cáo sau 5 phút không có sự kiện mới
    MAX_KNOWLEDGE_NODES = 10000 # Giới hạn số bản ghi trong knowledge_store.json

    # Ngưỡng cảnh báo
    CRITICAL_LEVEL_THRESHOLD = 10   # Rule level >= 10 → Layer E → kích hoạt báo cáo
    REPUTATION_ALERT_SCORE   = 50   # IP có score <= 50 → cảnh báo bổ sung

    # Màu console (ANSI escape codes)
    COLOR = {
        "RED":    "\033[0;31m",  "BRED":    "\033[1;31m",
        "GREEN":  "\033[0;32m",  "BGREEN":  "\033[1;32m",
        "YELLOW": "\033[1;33m",  "BLUE":    "\033[0;34m",
        "CYAN":   "\033[0;36m",  "MAGENTA": "\033[0;35m",
        "BOLD":   "\033[1m",     "NC":      "\033[0m",      # No Color (reset)
    }

    # Biểu tượng theo tầng
    LAYER_ICON = {
        "A": "🟢", "B": "🔵", "C": "🟡", "D": "🟠", "E": "🔴"
    }


# ══════════════════════════════════════════════════════════════════════════════
#  CẤU HÌNH LOGGING
#  Ghi log ra cả console VÀ file để dễ debug khi demo
# ══════════════════════════════════════════════════════════════════════════════
def _setup_logging(log_file: str = KOSConfig.LOG_FILE) -> logging.Logger:
    """
    Khởi tạo hệ thống logging 2 luồng: console + file.
    Console hiển thị INFO trở lên; file ghi tất cả kể cả DEBUG.
    """
    logger = logging.getLogger("KOS")
    logger.setLevel(logging.DEBUG)

    # Định dạng log
    fmt_detailed = logging.Formatter(
        fmt="%(asctime)s [%(levelname)-8s] %(name)-20s │ %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    fmt_console = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    # Handler 1: Console (INFO+)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(fmt_console)
    logger.addHandler(console_handler)

    # Handler 2: File (DEBUG+) – xử lý lỗi khi không ghi được file
    try:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(fmt_detailed)
        logger.addHandler(file_handler)
    except OSError as e:
        logger.warning(f"Không thể ghi log ra file '{log_file}': {e}. Chỉ dùng console.")

    return logger


# Logger toàn cục của main.py
logger = _setup_logging()


# ══════════════════════════════════════════════════════════════════════════════
#  WAZUH LOG PARSER – Trích xuất chính xác từ log thật
#
#  Dữ liệu thật từ Wazuh có cấu trúc lồng nhau:
#  {
#    "_source": {                     ← wrapper của Elasticsearch
#      "timestamp": "2026-04-11T...", ← hoặc nằm ở _source.timestamp
#      "agent": { "name": "manh" },
#      "rule":  { "id": "5760", "level": 5, "description": "..." },
#      "data":  { "srcip": "192.168.1.9" },
#      "full_log": "Apr 11 ... Failed password..."
#    }
#  }
#  HOẶC không có wrapper (Wazuh ghi thẳng _source ra file alerts.json):
#  {
#    "timestamp": "...",
#    "agent": { ... }, "rule": { ... }, "data": { ... }
#  }
# ══════════════════════════════════════════════════════════════════════════════
class WazuhLogParser:
    """
    Bộ phân tích log chuyên biệt cho định dạng Wazuh 4.x.

    Xử lý 2 trường hợp:
      1. Log có wrapper Elasticsearch (_source)
      2. Log trực tiếp từ Wazuh (không có _source)

    Sử dụng regex để trích xuất srcip từ full_log khi trường data.srcip vắng mặt.
    """

    # Regex trích xuất IP nguồn từ dòng log thô
    # Ví dụ: "Failed password for manh from 192.168.1.9 port 34252 ssh2"
    # Ví dụ: "rhost=192.168.1.9  user=manh"
    _REGEX_SRCIP_FROM = re.compile(
        r"from\s+((?:\d{1,3}\.){3}\d{1,3})"          # Mẫu: "from 1.2.3.4"
    )
    _REGEX_SRCIP_RHOST = re.compile(
        r"rhost=((?:\d{1,3}\.){3}\d{1,3})"           # Mẫu: "rhost=1.2.3.4"
    )
    _REGEX_SRCIP_SRC = re.compile(
        r"\bsrc[_\s]?(?:ip)?[=:\s]+((?:\d{1,3}\.){3}\d{1,3})"  # Mẫu: "src_ip=1.2.3.4"
    )
    # Regex kiểm tra IP hợp lệ (không phải localhost hay link-local)
    _REGEX_VALID_IP = re.compile(
        r"^(?!127\.)(?!169\.254\.)(?!0\.)(?:(?:\d{1,3}\.){3}\d{1,3})$"
    )

    @classmethod
    def parse(cls, raw_line: str) -> Optional[Dict[str, Any]]:
        """
        Phân tích một dòng JSON từ alerts.json của Wazuh.

        Quy trình:
          1. Parse JSON
          2. Phát hiện wrapper _source (nếu có)
          3. Trích xuất từng trường với fallback chain
          4. Lấy srcip: ưu tiên data.srcip → regex từ full_log

        Args:
            raw_line: Một dòng chuỗi JSON từ file alerts.json.

        Returns:
            Dict chuẩn hóa hoặc None nếu dòng không hợp lệ.
        """
        # ── Bước 1: Làm sạch và kiểm tra dòng trống ──────────────────────
        raw_line = raw_line.strip()
        if not raw_line or raw_line.startswith("#"):
            return None  # Bỏ qua dòng trống và comment

        # ── Bước 2: Parse JSON – bắt lỗi cụ thể ─────────────────────────
        try:
            perception_data = json.loads(raw_line)
        except json.JSONDecodeError as e:
            # Log ở WARNING thay vì ERROR vì dòng lỗi có thể do rotation
            logger.warning(
                f"[WazuhParser] JSON không hợp lệ tại byte {e.pos}: {e.msg} "
                f"| Dòng: {raw_line[:100]}..."
            )
            return None
        except MemoryError:
            # Phòng trường hợp dòng log quá lớn (bất thường)
            logger.error("[WazuhParser] Dòng log quá lớn, bỏ qua.")
            return None

        # ── Bước 3: Phát hiện wrapper Elasticsearch ──────────────────────
        # Wazuh xuất qua Elasticsearch có wrapper: { "_source": { ... } }
        if "_source" in perception_data:
            perception_data = perception_data["_source"]

        # ── Bước 4: Trích xuất từng trường với fallback chain ─────────────
        # Timestamp: thử nhiều vị trí khác nhau tùy version Wazuh
        timestamp = (
            perception_data.get("timestamp")                    # Wazuh 4.x trực tiếp
            or perception_data.get("@timestamp")               # Elasticsearch format
            or perception_data.get("predecoder", {}).get("timestamp")  # Predecoder
            or datetime.now(timezone.utc).isoformat()          # Fallback: thời gian hiện tại
        )

        # Rule: Wazuh luôn có trường "rule", nhưng bắt lỗi nếu thiếu
        rule_block = perception_data.get("rule", {})
        if not isinstance(rule_block, dict):
            logger.warning("[WazuhParser] Trường 'rule' không phải dict, bỏ qua.")
            return None

        rule_id    = str(rule_block.get("id", "unknown"))
        rule_level_raw = rule_block.get("level", 0)
        try:
            rule_level = int(rule_level_raw)
        except (ValueError, TypeError):
            logger.warning(f"[WazuhParser] rule.level không hợp lệ: {rule_level_raw!r}")
            rule_level = 0
        rule_description = rule_block.get("description", "No description")

        # Agent: tên máy chủ đang chạy Wazuh agent
        agent_block = perception_data.get("agent", {})
        agent_name  = (
            agent_block.get("name", "")
            or perception_data.get("predecoder", {}).get("hostname", "unknown-agent")
        )

        # SrcIP: trích xuất theo thứ tự ưu tiên
        srcip = cls._extract_srcip(perception_data)

        # Các trường bổ sung từ log thật Wazuh (phục vụ Knowledge Base)
        mitre_block = rule_block.get("mitre", {})
        extra_fields = {
            "full_log":        perception_data.get("full_log", ""),
            "location":        perception_data.get("location", ""),
            "manager_name":    perception_data.get("manager", {}).get("name", ""),
            "agent_ip":        agent_block.get("ip", "N/A"),
            "agent_id":        agent_block.get("id", "N/A"),
            "rule_groups":     rule_block.get("groups", []),
            "rule_mitre_id":   mitre_block.get("id", []),
            "rule_mitre_tactic": mitre_block.get("tactic", []),
            "rule_mitre_technique": mitre_block.get("technique", []),
            "dstuser":         perception_data.get("data", {}).get("dstuser", ""),
            "srcport":         perception_data.get("data", {}).get("srcport", ""),
        }

        return {
            "timestamp":        timestamp,
            "rule_id":          rule_id,
            "rule_level":       rule_level,
            "rule_description": rule_description,
            "agent_name":       agent_name,
            "srcip":            srcip,
            "raw":              perception_data,
            "extra":            extra_fields,
        }

    @classmethod
    def _extract_srcip(cls, perception_data: Dict[str, Any]) -> str:
        """
        Trích xuất địa chỉ IP nguồn từ nhiều vị trí khác nhau trong log Wazuh.

        Thứ tự ưu tiên:
          1. data.srcip          (trường chuẩn Wazuh)
          2. data.src_ip         (biến thể)
          3. data.rhost          (một số decoder cũ)
          4. Regex từ full_log   (fallback cuối cùng)
          5. "N/A"               (không xác định được)
        """
        data_block = perception_data.get("data", {})
        if not isinstance(data_block, dict):
            data_block = {}

        # Ưu tiên 1–3: trường có sẵn trong JSON
        for field_name in ("srcip", "src_ip", "rhost"):
            candidate = data_block.get(field_name, "")
            if candidate and cls._is_valid_ip(candidate):
                return candidate

        # Ưu tiên 4: regex từ full_log (ví dụ: "Failed password for X from 1.2.3.4 port 22")
        full_log = perception_data.get("full_log", "")
        if full_log:
            for pattern in (cls._REGEX_SRCIP_FROM, cls._REGEX_SRCIP_RHOST, cls._REGEX_SRCIP_SRC):
                match = pattern.search(full_log)
                if match:
                    ip_candidate = match.group(1)
                    if cls._is_valid_ip(ip_candidate):
                        return ip_candidate

        return "N/A"

    @classmethod
    def _is_valid_ip(cls, ip_str: str) -> bool:
        """Kiểm tra IP có hợp lệ và không phải localhost/link-local."""
        if not ip_str or not isinstance(ip_str, str):
            return False
        return bool(cls._REGEX_VALID_IP.match(ip_str.strip()))


# ══════════════════════════════════════════════════════════════════════════════
#  KNOWLEDGE BASE – Kho tri thức lịch sử tấn công
#
#  Mỗi sự kiện được phân tích sẽ được lưu thành một "knowledge_node" –
#  một đơn vị tri thức độc lập chứa đầy đủ context để đối chiếu sau này.
# ══════════════════════════════════════════════════════════════════════════════
@dataclass
class KnowledgeNode:
    """
    Đơn vị tri thức cơ bản của KOS Knowledge Base.

    Mỗi KnowledgeNode là một "hạt nhân tri thức" ghi lại toàn bộ
    thông tin của một sự kiện bảo mật đã được phân tích đầy đủ.

    Tên gọi "node" phản ánh triết lý KOS: tri thức được tổ chức
    như một mạng lưới các nút liên kết, không phải bảng dữ liệu phẳng.
    """
    # ── Định danh ─────────────────────────────────────────────────────
    node_id:         str   # ID duy nhất: KN-YYYYMMDD-HHMMSS-<counter>
    recorded_at:     str   # Thời điểm ghi vào knowledge base (UTC)

    # ── Dữ liệu cảm nhận (Perception Layer output) ────────────────────
    event_timestamp:     str   # Thời điểm xảy ra sự kiện (từ Wazuh)
    rule_id:             str   # ID rule Wazuh kích hoạt
    rule_level:          int   # Mức độ (1–15)
    rule_description:    str   # Mô tả rule
    agent_name:          str   # Tên máy chủ bị tác động
    srcip:               str   # IP nguồn tấn công

    # ── Tri thức phân tích (Logic Layer output) ───────────────────────
    risk_layer:          str   # A / B / C / D / E
    threat_category:     str   # Brute Force / Exploit / Malware / ...
    ip_reputation_score: int   # 0–100
    ip_reputation_label: str   # TRUSTED / SUSPICIOUS / DANGEROUS / BLOCKED
    recommended_action:  str   # Đề xuất ứng phó

    # ── Dữ liệu bổ sung từ Wazuh (phục vụ đối chiếu) ─────────────────
    mitre_tactics:       List[str] = field(default_factory=list)   # MITRE ATT&CK Tactics
    mitre_techniques:    List[str] = field(default_factory=list)   # MITRE ATT&CK Techniques
    mitre_ids:           List[str] = field(default_factory=list)   # MITRE IDs (T1110.001...)
    rule_groups:         List[str] = field(default_factory=list)   # Nhóm rule Wazuh
    full_log_excerpt:    str       = ""   # Đoạn trích log gốc (tối đa 200 ký tự)
    manager_name:        str       = ""   # Tên Wazuh manager
    incident_id:         str       = ""   # Liên kết đến incident report (nếu có)
    notes:               List[str] = field(default_factory=list)   # Ghi chú phân tích

    def to_dict(self) -> Dict[str, Any]:
        """Chuyển KnowledgeNode thành dict để serialize JSON."""
        return asdict(self)


class KnowledgeBase:
    """
    Kho tri thức trung tâm của KOS – lưu trữ lịch sử tấn công.

    Chức năng:
      • Lưu mỗi Intelligence đã phân tích thành một KnowledgeNode
      • Ghi persistent vào knowledge_store.json (atomic write)
      • Hỗ trợ truy vấn: theo IP, theo layer, theo khoảng thời gian
      • Tự dọn dẹp khi vượt giới hạn MAX_KNOWLEDGE_NODES

    Lý do dùng JSON thay vì database:
      - Không phụ thuộc thêm thư viện bên ngoài
      - Dễ đọc và trình bày trong buổi bảo vệ
      - Phù hợp với quy mô SMB (< 10,000 sự kiện/ngày)
    """

    def __init__(
        self,
        store_path: str = KOSConfig.KNOWLEDGE_STORE,
        max_nodes: int = KOSConfig.MAX_KNOWLEDGE_NODES,
    ):
        """
        Args:
            store_path: Đường dẫn file knowledge_store.json
            max_nodes:  Số lượng node tối đa trước khi xóa node cũ nhất
        """
        self.store_path = store_path
        self.max_nodes  = max_nodes
        self._lock      = threading.Lock()   # Đảm bảo thread-safe khi ghi

        # Bộ đếm cho ID node (thread-safe với lock)
        self._node_counter: int = 0

        # Cache trong bộ nhớ để truy vấn nhanh
        self._nodes: List[Dict[str, Any]] = []

        # Tải dữ liệu có sẵn từ file
        self._load_store()
        logger.info(
            f"[KnowledgeBase] Khởi tạo | "
            f"Store: {self.store_path} | "
            f"Đã tải: {len(self._nodes)} knowledge nodes"
        )

    # ──────────────────────────────────────────────────────────────────
    # PHƯƠNG THỨC CÔNG KHAI
    # ──────────────────────────────────────────────────────────────────

    def record(
        self,
        threat_intel: "Intelligence",
        extra: Optional[Dict[str, Any]] = None,
        incident_id: str = "",
    ) -> KnowledgeNode:
        """
        Ghi một Intelligence event vào kho tri thức.

        Đây là phương thức trọng tâm – nhận kết quả từ Logic Analysis Layer
        và chuyển hóa thành KnowledgeNode để lưu trữ lâu dài.

        Args:
            threat_intel: Đối tượng Intelligence từ LogicEngine.
            extra:        Dữ liệu bổ sung từ WazuhLogParser (MITRE, full_log...).
            incident_id:  ID của incident report liên quan (nếu có).

        Returns:
            KnowledgeNode đã được ghi vào store.
        """
        extra = extra or {}

        # Tạo ID duy nhất cho knowledge node
        with self._lock:
            self._node_counter += 1
            node_id = (
                f"KN-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
                f"-{self._node_counter:04d}"
            )

        # Trích xuất dữ liệu event nguồn
        src_event = threat_intel.source_event

        # Cắt ngắn full_log để tránh file quá lớn
        full_log_raw  = extra.get("full_log", "")
        full_log_excerpt = full_log_raw[:200] + "…" if len(full_log_raw) > 200 else full_log_raw

        # Tạo KnowledgeNode
        knowledge_node = KnowledgeNode(
            node_id             = node_id,
            recorded_at         = datetime.now(timezone.utc).isoformat(),
            event_timestamp     = src_event.timestamp,
            rule_id             = src_event.rule_id,
            rule_level          = src_event.rule_level,
            rule_description    = src_event.rule_description,
            agent_name          = src_event.agent_name,
            srcip               = src_event.srcip,
            risk_layer          = threat_intel.risk_layer.value,
            threat_category     = threat_intel.threat_category.value,
            ip_reputation_score = threat_intel.ip_reputation_score,
            ip_reputation_label = threat_intel.ip_reputation_label,
            recommended_action  = threat_intel.recommended_action,
            mitre_tactics       = extra.get("rule_mitre_tactic", []),
            mitre_techniques    = extra.get("rule_mitre_technique", []),
            mitre_ids           = extra.get("rule_mitre_id", []),
            rule_groups         = extra.get("rule_groups", []),
            full_log_excerpt    = full_log_excerpt,
            manager_name        = extra.get("manager_name", ""),
            incident_id         = incident_id,
            notes               = list(threat_intel.notes),
        )

        # Ghi vào store (thread-safe)
        with self._lock:
            self._nodes.append(knowledge_node.to_dict())

            # Dọn dẹp nếu vượt giới hạn: xóa node cũ nhất
            if len(self._nodes) > self.max_nodes:
                removed = len(self._nodes) - self.max_nodes
                self._nodes = self._nodes[-self.max_nodes:]
                logger.info(f"[KnowledgeBase] Đã xóa {removed} node cũ nhất (giới hạn {self.max_nodes})")

            self._save_store()

        logger.debug(f"[KnowledgeBase] Ghi node {node_id} | Layer {threat_intel.risk_layer.value} | {src_event.srcip}")
        return knowledge_node

    def query_by_ip(self, srcip: str) -> List[Dict[str, Any]]:
        """
        Truy vấn tất cả sự kiện liên quan đến một IP cụ thể.
        Dùng để đối chiếu lịch sử tấn công của một địa chỉ IP.
        """
        with self._lock:
            return [
                node for node in self._nodes
                if node.get("srcip") == srcip
            ]

    def query_by_layer(self, layer: str) -> List[Dict[str, Any]]:
        """Truy vấn theo tầng nguy cơ (A/B/C/D/E)."""
        with self._lock:
            return [
                node for node in self._nodes
                if node.get("risk_layer") == layer.upper()
            ]

    def query_recent(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Lấy N sự kiện gần nhất."""
        with self._lock:
            return list(self._nodes[-limit:])

    def get_statistics(self) -> Dict[str, Any]:
        """
        Thống kê tổng quan kho tri thức.
        Sử dụng trong báo cáo và dashboard.
        """
        with self._lock:
            total = len(self._nodes)
            if total == 0:
                return {"total_nodes": 0}

            # Đếm theo tầng
            layer_dist: Dict[str, int] = defaultdict(int)
            # Đếm theo category
            category_dist: Dict[str, int] = defaultdict(int)
            # Tập hợp IP duy nhất
            unique_ips: set = set()
            # IP tấn công nhiều nhất
            ip_frequency: Dict[str, int] = defaultdict(int)

            for node in self._nodes:
                layer_dist[node.get("risk_layer", "?")] += 1
                category_dist[node.get("threat_category", "?")] += 1
                ip = node.get("srcip", "N/A")
                if ip not in ("N/A", "unknown", ""):
                    unique_ips.add(ip)
                    ip_frequency[ip] += 1

            # Top 5 IP tấn công
            top_attackers = sorted(
                ip_frequency.items(), key=lambda x: x[1], reverse=True
            )[:5]

            return {
                "total_nodes":      total,
                "layer_distribution": dict(layer_dist),
                "category_distribution": dict(category_dist),
                "unique_attacker_ips": len(unique_ips),
                "top_attackers": [
                    {"ip": ip, "count": cnt} for ip, cnt in top_attackers
                ],
                "oldest_record": self._nodes[0].get("recorded_at", "") if self._nodes else "",
                "newest_record": self._nodes[-1].get("recorded_at", "") if self._nodes else "",
            }

    def print_report(self):
        """In báo cáo tổng quan knowledge base ra console."""
        stats = self.get_statistics()
        C = KOSConfig.COLOR

        print(f"\n{C['BOLD']}{'═'*60}{C['NC']}")
        print(f"{C['CYAN']}  📚 KOS KNOWLEDGE BASE – BÁO CÁO TỔNG QUAN{C['NC']}")
        print(f"{C['BOLD']}{'═'*60}{C['NC']}")
        print(f"  Tổng số knowledge nodes  : {C['BOLD']}{stats.get('total_nodes', 0)}{C['NC']}")
        print(f"  IP tấn công duy nhất     : {stats.get('unique_attacker_ips', 0)}")
        print(f"  Ghi nhận đầu tiên        : {stats.get('oldest_record', 'N/A')[:19]}")
        print(f"  Ghi nhận gần nhất        : {stats.get('newest_record', 'N/A')[:19]}")

        print(f"\n  {C['BOLD']}Phân bố theo Tầng Nguy Cơ:{C['NC']}")
        for layer, count in sorted(stats.get("layer_distribution", {}).items()):
            icon = KOSConfig.LAYER_ICON.get(layer, "⚪")
            bar  = "█" * min(count, 30) + ("…" if count > 30 else "")
            print(f"    {icon} Layer {layer}: {count:4d}  {C['CYAN']}{bar}{C['NC']}")

        print(f"\n  {C['BOLD']}Phân bố theo Loại Mối Đe Dọa:{C['NC']}")
        for cat, count in sorted(
            stats.get("category_distribution", {}).items(),
            key=lambda x: -x[1]
        ):
            print(f"    • {cat:<25} : {count}")

        print(f"\n  {C['BOLD']}Top 5 IP Tấn Công:{C['NC']}")
        for entry in stats.get("top_attackers", []):
            print(f"    🔴 {entry['ip']:<18} : {entry['count']} sự kiện")

        print(f"{C['BOLD']}{'═'*60}{C['NC']}\n")

    # ──────────────────────────────────────────────────────────────────
    # PHƯƠNG THỨC NỘI BỘ – Đọc/ghi file
    # ──────────────────────────────────────────────────────────────────

    def _load_store(self):
        """
        Tải dữ liệu từ knowledge_store.json.
        Xử lý an toàn: không bị crash nếu file bị hỏng hoặc trống.
        """
        store_path = Path(self.store_path)

        if not store_path.exists():
            logger.info(f"[KnowledgeBase] Tạo mới store: {self.store_path}")
            self._nodes = []
            return

        # Kiểm tra file trống
        if store_path.stat().st_size == 0:
            logger.warning(f"[KnowledgeBase] File store trống: {self.store_path}")
            self._nodes = []
            return

        try:
            with open(self.store_path, "r", encoding="utf-8") as f:
                raw_data = json.load(f)

            # Kiểm tra cấu trúc: phải là dict có trường "nodes"
            if isinstance(raw_data, dict) and "nodes" in raw_data:
                self._nodes = raw_data["nodes"]
            elif isinstance(raw_data, list):
                # Tương thích ngược: nếu file cũ lưu thẳng list
                self._nodes = raw_data
            else:
                logger.warning("[KnowledgeBase] Cấu trúc store không hợp lệ, khởi tạo lại.")
                self._nodes = []

        except json.JSONDecodeError as e:
            # File bị hỏng: đổi tên file cũ, tạo file mới
            backup = f"{self.store_path}.corrupted_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            logger.error(
                f"[KnowledgeBase] File store bị hỏng: {e}. "
                f"Đổi tên sang {backup} và tạo mới."
            )
            try:
                store_path.rename(backup)
            except OSError:
                pass
            self._nodes = []

        except OSError as e:
            # File bị khóa hoặc không có quyền đọc
            logger.error(
                f"[KnowledgeBase] Không đọc được file store: {e}. "
                "Sẽ tiếp tục với bộ nhớ tạm, dữ liệu sẽ không được lưu lại."
            )
            self._nodes = []

    def _save_store(self):
        """
        Ghi nodes vào knowledge_store.json.
        Sử dụng atomic write (ghi temp rồi đổi tên) để tránh mất dữ liệu
        nếu chương trình bị tắt giữa chừng.
        """
        store_data = {
            "meta": {
                "version":      "1.0",
                "system":       "KOS – Knowledge Operating System",
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "total_nodes":  len(self._nodes),
            },
            "nodes": self._nodes,
        }

        tmp_path = self.store_path + ".tmp"
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(store_data, f, ensure_ascii=False, indent=2)
            os.replace(tmp_path, self.store_path)   # Atomic: thay thế an toàn
        except OSError as e:
            logger.error(f"[KnowledgeBase] Không ghi được store: {e}")
            # Xóa file tạm nếu tạo dở
            try:
                os.remove(tmp_path)
            except OSError:
                pass


# ══════════════════════════════════════════════════════════════════════════════
#  KOS SYSTEM – Hệ thống tổng thể
#  Kết nối 3 tầng + Knowledge Base thành một thực thể duy nhất
# ══════════════════════════════════════════════════════════════════════════════
class KOSSystem:
    """
    Hệ thống KOS hoàn chỉnh – điều phối toàn bộ pipeline.

    Đây là lớp "bộ não" cao nhất, kết nối:
      PerceptionLayer → LogicEngine → OperationCenter → KnowledgeBase

    Thiết kế theo mô hình Observer:
      - Mỗi tầng không biết đến tầng tiếp theo
      - KOSSystem là "dây kết nối" truyền dữ liệu giữa các tầng
      - Cho phép thay thế từng module độc lập
    """

    def __init__(self, config: KOSConfig = KOSConfig()):
        """
        Khởi tạo và kết nối tất cả các tầng.

        Args:
            config: Cấu hình hệ thống (dùng KOSConfig mặc định nếu không truyền)
        """
        self.config = config

        # Bộ đếm sự kiện toàn cục
        self._stats = {
            "started_at":         datetime.now(timezone.utc).isoformat(),
            "total_perception":   0,   # Số alert đọc được từ Wazuh
            "total_analyzed":     0,   # Số alert qua Logic Engine
            "total_knowledge":    0,   # Số node ghi vào Knowledge Base
            "total_incidents":    0,   # Số incident report tạo ra
            "layer_e_count":      0,   # Số sự kiện Layer E (nghiêm trọng nhất)
            "errors_perception":  0,   # Số lỗi ở Perception Layer
            "errors_logic":       0,   # Số lỗi ở Logic Layer
        }
        self._stats_lock = threading.Lock()

        # Bộ nhớ tạm: lưu extra data của AlertEvent hiện tại
        # để truyền sang Knowledge Base (MITRE, full_log...)
        self._pending_extra: Dict[str, Dict] = {}
        self._extra_lock = threading.Lock()

        # ── Khởi tạo Knowledge Base (luôn khởi tạo, không phụ thuộc module khác) ──
        self.knowledge_base = KnowledgeBase(
            store_path=KOSConfig.KNOWLEDGE_STORE,
        )

        # ── Kiểm tra module còn thiếu ──────────────────────────────────────
        if _import_errors:
            logger.warning("Một số module KOS chưa sẵn sàng:")
            for err in _import_errors:
                logger.warning(f"  ✗ {err}")
            if PerceptionLayer is None or LogicEngine is None or OperationCenter is None:
                raise SystemExit(
                    "❌ Không thể khởi động KOS: thiếu module cốt lõi. "
                    "Hãy đảm bảo kos_kernel.py, logic_engine.py, operation_center.py "
                    "nằm cùng thư mục với main.py."
                )

        # ── Tầng 3: Operation Center ───────────────────────────────────────
        # Khởi tạo trước để truyền callback vào Logic Engine
        self.operation_center = OperationCenter(
            output_dir=KOSConfig.OUTPUT_DIR,
            on_incident_created=self._on_incident_created,  # Callback khi có báo cáo
            auto_flush_interval=KOSConfig.AUTO_FLUSH_SEC,
            include_layer_d=True,
        )

        # ── Tầng 2: Logic Engine ───────────────────────────────────────────
        self.logic_engine = LogicEngine(
            reputation_db_path=KOSConfig.REPUTATION_DB,
            on_intelligence=self._on_intelligence_ready,    # Callback khi có Intelligence
        )

        # ── Tầng 1: Perception Layer ───────────────────────────────────────
        # Khởi tạo sau cùng; chưa bắt đầu lắng nghe
        self.perception_layer = PerceptionLayer(
            alerts_path=KOSConfig.ALERTS_FILE,
            on_event=self._on_perception_data,              # Callback khi có AlertEvent
            poll_interval=KOSConfig.POLL_INTERVAL_SEC,
        )

        logger.info("✅ KOS System khởi tạo thành công – 3 tầng + Knowledge Base sẵn sàng.")

    # ──────────────────────────────────────────────────────────────────
    # CALLBACKS – Cầu nối giữa các tầng
    # ──────────────────────────────────────────────────────────────────

    def _on_perception_data(self, perception_data: "AlertEvent"):
        """
        [CALLBACK] Nhận AlertEvent từ Perception Layer.
        Đây là điểm đầu tiên dữ liệu đi vào hệ thống KOS.

        Lưu extra data (MITRE, full_log...) để dùng ở tầng Knowledge Base,
        sau đó chuyển tiếp sang Logic Engine.
        """
        try:
            with self._stats_lock:
                self._stats["total_perception"] += 1

            # Lưu tạm extra data (dựa trên raw data trong AlertEvent)
            # Key: dùng combination timestamp+rule_id để tránh collision
            extra_key = f"{perception_data.timestamp}_{perception_data.rule_id}"

            if hasattr(perception_data, "raw") and perception_data.raw:
                # Chạy lại WazuhLogParser trên raw data để lấy extra fields
                raw_json = json.dumps(perception_data.raw)
                parsed   = WazuhLogParser.parse(raw_json)
                if parsed:
                    with self._extra_lock:
                        self._pending_extra[extra_key] = parsed.get("extra", {})
                        # Giới hạn bộ nhớ tạm: giữ tối đa 500 entry
                        if len(self._pending_extra) > 500:
                            oldest_key = next(iter(self._pending_extra))
                            del self._pending_extra[oldest_key]

            # Ghi log ở mức DEBUG để không làm rối console khi demo
            logger.debug(
                f"[Perception→Logic] Rule {perception_data.rule_id} "
                f"Lv.{perception_data.rule_level} | "
                f"Agent: {perception_data.agent_name} | IP: {perception_data.srcip}"
            )

        except Exception as e:
            # KHÔNG để exception lan ra ngoài – tránh làm dừng Perception Layer
            with self._stats_lock:
                self._stats["errors_perception"] += 1
            logger.error(f"[_on_perception_data] Lỗi không mong đợi: {e}", exc_info=True)

    def _on_intelligence_ready(self, threat_intel: "Intelligence"):
        """
        [CALLBACK] Nhận Intelligence từ Logic Engine.
        Đây là điểm giữa pipeline: dữ liệu đã được phân tích.

        Thực hiện 2 việc song song:
          1. Ghi vào Knowledge Base (lịch sử lâu dài)
          2. Chuyển sang Operation Center (nếu đủ nghiêm trọng)
        """
        try:
            with self._stats_lock:
                self._stats["total_analyzed"] += 1
                if threat_intel.risk_layer == RiskLayer.E:
                    self._stats["layer_e_count"] += 1

            # Lấy extra data đã lưu tạm
            src = threat_intel.source_event
            extra_key = f"{src.timestamp}_{src.rule_id}"
            with self._extra_lock:
                extra = self._pending_extra.pop(extra_key, {})

            # ── Ghi vào Knowledge Base ────────────────────────────────
            knowledge_node = self.knowledge_base.record(
                threat_intel=threat_intel,
                extra=extra,
            )
            with self._stats_lock:
                self._stats["total_knowledge"] += 1

            # ── In ra console (tóm tắt ngắn gọn) ────────────────────
            self._print_intelligence_summary(threat_intel, knowledge_node.node_id)

            # Lưu ý: Operation Center nhận threat_intel trực tiếp
            # qua callback on_intelligence của LogicEngine (đã cấu hình sẵn).
            # Không cần gọi thêm ở đây để tránh gọi 2 lần.

        except Exception as e:
            with self._stats_lock:
                self._stats["errors_logic"] += 1
            logger.error(f"[_on_intelligence_ready] Lỗi: {e}", exc_info=True)

    def _on_incident_created(self, report_path: str, script_path: str):
        """
        [CALLBACK] Được gọi khi Operation Center tạo xong báo cáo và script.
        Cập nhật thống kê và notify operator.
        """
        with self._stats_lock:
            self._stats["total_incidents"] += 1

        C = KOSConfig.COLOR
        print(f"\n{C['BRED']}{'▓'*60}{C['NC']}")
        print(f"{C['BRED']}  🚨 INCIDENT REPORT ĐÃ TẠO XONG!{C['NC']}")
        print(f"  📄 Báo cáo  : {C['BOLD']}{report_path}{C['NC']}")
        print(f"  🛠️  Script   : {C['BOLD']}{script_path}{C['NC']}")
        print(f"{C['YELLOW']}  ⚠️  Xem xét kỹ script trước khi chạy trên hệ thống!{C['NC']}")
        print(f"{C['BRED']}{'▓'*60}{C['NC']}\n")

    # ──────────────────────────────────────────────────────────────────
    # PHƯƠNG THỨC CÔNG KHAI
    # ──────────────────────────────────────────────────────────────────

    def start(self, alerts_path: str, blocking: bool = True):
        """
        Khởi động toàn bộ hệ thống KOS.

        Args:
            alerts_path: Đường dẫn file alerts.json của Wazuh.
            blocking:    True = chặn đến khi Ctrl+C; False = chạy nền.
        """
        # Cập nhật đường dẫn file (nếu khác mặc định)
        self.perception_layer.alerts_path = os.path.abspath(alerts_path)

        C = KOSConfig.COLOR
        self._print_banner()

        logger.info(f"[KOS] Bắt đầu lắng nghe: {alerts_path}")
        try:
            self.perception_layer.listen(blocking=blocking)
        except KeyboardInterrupt:
            # Bắt Ctrl+C ở đây để không bị traceback xấu
            pass
        finally:
            if blocking:
                self.shutdown()

    def shutdown(self):
        """Tắt hệ thống an toàn – flush incident đang dang dở."""
        logger.info("[KOS] Đang tắt hệ thống...")

        # Flush incident chưa hoàn thành
        try:
            result = self.operation_center.flush()
            if result:
                logger.info(f"[KOS] Đã flush incident cuối: {result[0]}")
        except Exception as e:
            logger.error(f"[KOS] Lỗi flush khi tắt: {e}")

        # Dừng perception layer
        try:
            self.perception_layer.stop()
        except Exception as e:
            logger.error(f"[KOS] Lỗi dừng PerceptionLayer: {e}")

        self._print_shutdown_summary()

    def get_stats(self) -> Dict[str, Any]:
        """Trả về thống kê hoạt động của toàn hệ thống."""
        with self._stats_lock:
            base = dict(self._stats)
        base["knowledge_base"]  = self.knowledge_base.get_statistics()
        base["reputation_db"]   = self.logic_engine.get_stats().get("reputation_db", {})
        base["operation_center"] = self.operation_center.get_stats()
        return base

    # ──────────────────────────────────────────────────────────────────
    # PHƯƠNG THỨC NỘI BỘ – Hiển thị
    # ──────────────────────────────────────────────────────────────────

    def _print_intelligence_summary(self, threat_intel: "Intelligence", node_id: str):
        """In tóm tắt một Intelligence event ra console."""
        C    = KOSConfig.COLOR
        src  = threat_intel.source_event
        icon = KOSConfig.LAYER_ICON.get(threat_intel.risk_layer.value, "⚪")

        # Chọn màu theo tầng
        layer_color = {
            "A": C["GREEN"], "B": C["BLUE"],
            "C": C["YELLOW"], "D": C["MAGENTA"], "E": C["BRED"],
        }.get(threat_intel.risk_layer.value, C["NC"])

        print(
            f"{layer_color}{icon} [{threat_intel.risk_layer.value}]{C['NC']} "
            f"{src.rule_description[:55]:<55} │ "
            f"IP: {C['BOLD']}{src.srcip:<17}{C['NC']} │ "
            f"Score: {threat_intel.ip_reputation_score:>3}/100 "
            f"({threat_intel.ip_reputation_label}) │ "
            f"{src.agent_name}"
        )

        # Chỉ in chi tiết cho Layer D và E
        if threat_intel.risk_layer.value in ("D", "E"):
            print(f"   {C['YELLOW']}↳ {threat_intel.recommended_action}{C['NC']}")
            for note in threat_intel.notes[:2]:  # Tối đa 2 note để gọn
                print(f"   {C['CYAN']}↳ {note}{C['NC']}")
            print(f"   {C['MAGENTA']}↳ KnowledgeNode: {node_id}{C['NC']}")

    def _print_banner(self):
        """In banner khởi động KOS."""
        C = KOSConfig.COLOR
        print(f"\n{C['CYAN']}")
        print("  ╔══════════════════════════════════════════════════════════╗")
        print("  ║     KOS – Knowledge-oriented Security Framework  v1.0              ║")
        print("  ║     Hệ thống Phân tích Bảo mật Thông minh cho SMB       ║")
        print("  ╠══════════════════════════════════════════════════════════╣")
        print(f"  ║  Perception → Logic → Operation → Knowledge Base       ║")
        print("  ╚══════════════════════════════════════════════════════════╝")
        print(f"{C['NC']}")
        print(f"  📂 Alerts file   : {self.perception_layer.alerts_path}")
        print(f"  📊 Reputation DB : {KOSConfig.REPUTATION_DB}")
        print(f"  📚 Knowledge Base: {KOSConfig.KNOWLEDGE_STORE}")
        print(f"  📁 Reports dir   : {KOSConfig.OUTPUT_DIR}/")
        print(f"  {C['YELLOW']}  Nhấn Ctrl+C để dừng hệ thống an toàn.{C['NC']}\n")
        print(f"  {'─'*60}")
        print(f"  {'LAYER':<8} {'IP NGUỒN':<18} {'SCORE':>7} {'AGENT':<20} MÔ TẢ")
        print(f"  {'─'*60}")

    def _print_shutdown_summary(self):
        """In tóm tắt khi tắt hệ thống."""
        C     = KOSConfig.COLOR
        stats = self.get_stats()
        print(f"\n{C['CYAN']}{'═'*60}{C['NC']}")
        print(f"{C['BOLD']}  KOS System – Tóm tắt phiên làm việc{C['NC']}")
        print(f"{'═'*60}")
        print(f"  Tổng alert nhận được : {stats['total_perception']}")
        print(f"  Tổng đã phân tích    : {stats['total_analyzed']}")
        print(f"  Layer E (nghiêm trọng): {C['BRED']}{stats['layer_e_count']}{C['NC']}")
        print(f"  Incident reports     : {stats['total_incidents']}")
        print(f"  Knowledge nodes ghi  : {stats['total_knowledge']}")
        print(f"  Lỗi Perception       : {stats['errors_perception']}")
        print(f"  Lỗi Logic            : {stats['errors_logic']}")
        kb_stats = stats.get("knowledge_base", {})
        print(f"  Knowledge Base tổng  : {kb_stats.get('total_nodes', 0)} nodes")
        print(f"{'═'*60}\n")


# ══════════════════════════════════════════════════════════════════════════════
#  CHẾ ĐỘ DEMO – Chạy với dữ liệu log Wazuh thật (giả lập ghi vào file)
# ══════════════════════════════════════════════════════════════════════════════
def run_demo_mode(output_dir: str = KOSConfig.OUTPUT_DIR):
    """
    Chế độ demo: Giả lập Wazuh ghi log thật vào file tạm,
    rồi để KOS phân tích và tạo báo cáo.

    Sử dụng đúng định dạng log thật từ Wazuh 4.x (như log mẫu cung cấp).
    """
    C = KOSConfig.COLOR
    DEMO_ALERTS_FILE = "/tmp/kos_demo_alerts.json"

    # ── Log mẫu THẬT từ Wazuh (như được cung cấp trong yêu cầu) ─────────
    # Chú ý: đây là định dạng Elasticsearch export – có wrapper _source
    WAZUH_REAL_LOGS = [
        # Log 1: SSH authentication failed (level 5 – Layer C)
        {
            "_index": "wazuh-alerts-4.x-2026.04.11",
            "_id":    "JTG4e50B-B5CUsqUHY5h",
            "_source": {
                "predecoder": {
                    "hostname":     "manh",
                    "program_name": "sshd",
                    "timestamp":    "Apr 11 08:45:47",
                },
                "agent":   {"ip": "192.168.1.8", "name": "manh", "id": "001"},
                "manager": {"name": "wazuh-server"},
                "data":    {"srcip": "192.168.1.9", "dstuser": "manh", "srcport": "34252"},
                "rule": {
                    "level": 5, "id": "5760",
                    "description": "sshd: authentication failed.",
                    "groups": ["syslog", "sshd", "authentication_failed"],
                    "mitre": {
                        "technique": ["Password Guessing", "SSH"],
                        "id":        ["T1110.001", "T1021.004"],
                        "tactic":    ["Credential Access", "Lateral Movement"],
                    },
                },
                "location": "journald",
                "full_log": "Apr 11 08:45:47 manh sshd[2296]: Failed password for manh from 192.168.1.9 port 34252 ssh2",
                "timestamp": "2026-04-11T08:45:49.432+0000",
            },
        },
        # Log 2: PAM User login failed (level 5 – Layer C)
        {
            "_index": "wazuh-alerts-4.x-2026.04.11",
            "_id":    "JDG4e50B-B5CUsqUHY5h",
            "_source": {
                "predecoder": {
                    "hostname":     "manh",
                    "program_name": "sshd",
                    "timestamp":    "Apr 11 08:45:45",
                },
                "agent":   {"ip": "192.168.1.8", "name": "manh", "id": "001"},
                "manager": {"name": "wazuh-server"},
                "data":    {"uid": "0", "srcip": "192.168.1.9", "euid": "0", "dstuser": "manh", "tty": "ssh"},
                "rule": {
                    "level": 5, "id": "5503",
                    "description": "PAM: User login failed.",
                    "groups": ["pam", "syslog", "authentication_failed"],
                    "mitre": {
                        "technique": ["Password Guessing"],
                        "id":        ["T1110.001"],
                        "tactic":    ["Credential Access"],
                    },
                },
                "location": "journald",
                "full_log": "Apr 11 08:45:45 manh sshd[2296]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.1.9  user=manh",
                "timestamp": "2026-04-11T08:45:47.435+0000",
            },
        },
        # Log 3: Nhiều lần thất bại liên tiếp → level 10 → Layer E
        {
            "_source": {
                "agent":   {"ip": "192.168.1.8", "name": "manh", "id": "001"},
                "manager": {"name": "wazuh-server"},
                "data":    {"srcip": "192.168.1.9", "dstuser": "root"},
                "rule": {
                    "level": 10, "id": "5712",
                    "description": "SSH brute force attack (multiple authentication failures).",
                    "groups": ["syslog", "sshd", "authentication_failures"],
                    "mitre": {
                        "technique": ["Brute Force", "Password Guessing"],
                        "id":        ["T1110", "T1110.001"],
                        "tactic":    ["Credential Access"],
                    },
                },
                "location": "journald",
                "full_log": "Apr 11 08:46:10 manh sshd[2296]: Failed password for root from 192.168.1.9 port 34260 ssh2",
                "timestamp": "2026-04-11T08:46:10.000+0000",
            },
        },
        # Log 4: Web exploit (level 13 – Layer E)
        {
            "_source": {
                "agent":   {"ip": "10.0.0.5", "name": "nginx-prod", "id": "002"},
                "manager": {"name": "wazuh-server"},
                "data":    {"srcip": "91.108.56.170", "url": "/etc/passwd"},
                "rule": {
                    "level": 13, "id": "31151",
                    "description": "Multiple web server 400 error codes (LFI/RFI exploit attempt).",
                    "groups": ["web", "attack", "web_attack"],
                    "mitre": {
                        "technique": ["Exploit Public-Facing Application"],
                        "id":        ["T1190"],
                        "tactic":    ["Initial Access"],
                    },
                },
                "full_log": "91.108.56.170 - - [11/Apr/2026:08:47:00] \"GET /../../etc/passwd HTTP/1.1\" 400",
                "timestamp": "2026-04-11T08:47:00.000+0000",
            },
        },
        # Log 5: Rootkit detection (level 15 – Layer E – cực kỳ nghiêm trọng)
        {
            "_source": {
                "agent":   {"ip": "172.16.0.10", "name": "db-server", "id": "003"},
                "manager": {"name": "wazuh-server"},
                "data":    {"srcip": "172.16.0.200"},
                "rule": {
                    "level": 15, "id": "87002",
                    "description": "Rootkit detection: hidden process found in /proc.",
                    "groups": ["rootkit", "malware"],
                    "mitre": {
                        "technique": ["Rootkit"],
                        "id":        ["T1014"],
                        "tactic":    ["Defense Evasion"],
                    },
                },
                "full_log": "Apr 11 08:50:00 db-server kernel: Rootkit detected: hidden PID 4721",
                "timestamp": "2026-04-11T08:50:00.000+0000",
            },
        },
        # Log 6: Tiếp tục tấn công từ cùng IP (để test IP Reputation giảm điểm)
        {
            "_source": {
                "agent":   {"ip": "192.168.1.8", "name": "web-server-02", "id": "004"},
                "manager": {"name": "wazuh-server"},
                "data":    {"srcip": "192.168.1.9"},
                "rule": {
                    "level": 10, "id": "5712",
                    "description": "SSH brute force attack (multiple authentication failures).",
                    "groups": ["syslog", "sshd", "authentication_failures"],
                    "mitre": {
                        "technique": ["Brute Force"],
                        "id":        ["T1110"],
                        "tactic":    ["Credential Access"],
                    },
                },
                "full_log": "Apr 11 08:51:00 web-server-02 sshd[3100]: Failed password for admin from 192.168.1.9 port 44100 ssh2",
                "timestamp": "2026-04-11T08:51:00.000+0000",
            },
        },
    ]

    print(f"\n{C['CYAN']}{'═'*65}{C['NC']}")
    print(f"{C['BOLD']}  KOS – DEMO MODE  │  Dữ liệu log Wazuh thật{C['NC']}")
    print(f"{C['CYAN']}{'═'*65}{C['NC']}")
    print(f"  File tạm : {DEMO_ALERTS_FILE}")
    print(f"  Log mẫu  : {len(WAZUH_REAL_LOGS)} alerts (2 log thật + {len(WAZUH_REAL_LOGS)-2} mở rộng)")
    print(f"{C['CYAN']}{'─'*65}{C['NC']}\n")

    # ── Bước 1: Tạo file alerts.json tạm (rỗng) ─────────────────────────
    try:
        open(DEMO_ALERTS_FILE, "w").close()
    except OSError as e:
        print(f"{C['RED']}[ERROR] Không tạo được file demo: {e}{C['NC']}")
        return

    # ── Bước 2: Khởi tạo KOS System ─────────────────────────────────────
    # Ghi đè cấu hình để trỏ vào file demo
    KOSConfig.ALERTS_FILE = DEMO_ALERTS_FILE
    KOSConfig.OUTPUT_DIR  = output_dir

    try:
        kos = KOSSystem()
    except SystemExit as e:
        print(f"{C['RED']}[ERROR] {e}{C['NC']}")
        return

    # ── Bước 3: Chạy Perception Layer ở background ───────────────────────
    kos.start(alerts_path=DEMO_ALERTS_FILE, blocking=False)
    time.sleep(0.5)  # Chờ listener sẵn sàng

    # ── Bước 4: Giả lập Wazuh ghi log vào file từng dòng ─────────────────
    print(f"  {C['YELLOW']}[SIM] Bắt đầu giả lập Wazuh ghi log...{C['NC']}\n")

    for i, raw_log in enumerate(WAZUH_REAL_LOGS, 1):
        time.sleep(1.2)  # Giả lập khoảng cách giữa các sự kiện thực tế

        # Chú ý: _source.timestamp là trường chính xác trong log thật
        ts_display = (
            raw_log.get("_source", raw_log)
            .get("timestamp", "N/A")[:19]
        )
        rule_id  = raw_log.get("_source", raw_log).get("rule", {}).get("id", "?")
        rule_lvl = raw_log.get("_source", raw_log).get("rule", {}).get("level", "?")

        print(f"  {C['MAGENTA']}[{i}/{len(WAZUH_REAL_LOGS)}]{C['NC']} "
              f"Ghi log: Rule {rule_id} (level {rule_lvl}) @ {ts_display}")

        try:
            with open(DEMO_ALERTS_FILE, "a", encoding="utf-8") as f:
                # Ghi mỗi log thành 1 dòng JSON (NDJSON format)
                f.write(json.dumps(raw_log, ensure_ascii=False) + "\n")
        except OSError as e:
            print(f"  {C['RED']}[ERROR] Không ghi được file demo: {e}{C['NC']}")

    # ── Bước 5: Đợi hệ thống xử lý xong ─────────────────────────────────
    time.sleep(2)
    print(f"\n  {C['YELLOW']}[*] Flush báo cáo cuối...{C['NC']}")
    result = kos.operation_center.flush()

    # ── Bước 6: Tắt hệ thống và in tóm tắt ──────────────────────────────
    kos.perception_layer.stop()
    kos._print_shutdown_summary()

    # ── Bước 7: Báo cáo Knowledge Base ───────────────────────────────────
    kos.knowledge_base.print_report()

    if result:
        report_path, script_path = result
        print(f"\n{C['BGREEN']}  ✅ Output files:{C['NC']}")
        print(f"     📄 {report_path}")
        print(f"     🛠️  {script_path}")
        print(f"     📚 {KOSConfig.KNOWLEDGE_STORE}")
        print(f"     📊 {KOSConfig.REPUTATION_DB}\n")


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT – Điểm khởi chạy chính
# ══════════════════════════════════════════════════════════════════════════════
def main():
    """
    Hàm main – phân tích tham số dòng lệnh và khởi động KOS.

    Cách chạy:
      python main.py --demo                            # Demo với log Wazuh thật
      python main.py --alerts /path/to/alerts.json    # Production mode
      python main.py --knowledge-report               # Xem báo cáo Knowledge Base
      python main.py --flush                          # Flush incident đang dở
    """
    # ── Parser tham số dòng lệnh ─────────────────────────────────────────
    arg_parser = argparse.ArgumentParser(
        prog="python main.py",
        description=(
            "KOS – Knowledge Operating System │ "
            "Hệ thống phân tích log SIEM Wazuh cho SMB"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ví dụ:
  python main.py --demo
  python main.py --alerts /var/ossec/logs/alerts/alerts.json
  python main.py --knowledge-report
        """,
    )
    arg_parser.add_argument(
        "--alerts",
        default=KOSConfig.ALERTS_FILE,
        metavar="PATH",
        help=f"Đường dẫn file alerts.json của Wazuh (mặc định: {KOSConfig.ALERTS_FILE})",
    )
    arg_parser.add_argument(
        "--demo",
        action="store_true",
        help="Chạy chế độ demo với log Wazuh thật (giả lập ghi file)",
    )
    arg_parser.add_argument(
        "--knowledge-report",
        action="store_true",
        help="Xem báo cáo tổng quan Knowledge Base hiện tại",
    )
    arg_parser.add_argument(
        "--output",
        default=KOSConfig.OUTPUT_DIR,
        metavar="DIR",
        help=f"Thư mục xuất báo cáo (mặc định: {KOSConfig.OUTPUT_DIR})",
    )
    arg_parser.add_argument(
        "--debug",
        action="store_true",
        help="Bật chế độ debug (in thêm thông tin chi tiết)",
    )
    args = arg_parser.parse_args()

    # ── Bật debug mode ────────────────────────────────────────────────────
    if args.debug:
        logging.getLogger("KOS").setLevel(logging.DEBUG)
        logger.debug("Debug mode: BẬT")

    # ── Cập nhật output dir từ tham số ────────────────────────────────────
    KOSConfig.OUTPUT_DIR = args.output
    os.makedirs(KOSConfig.OUTPUT_DIR, exist_ok=True)

    # THÊM DÒNG NÀY VÀO ĐỂ TỰ ĐỘNG TẠO THƯ MỤC KNOWLEDGE_BASE
    os.makedirs("knowledge_base", exist_ok=True)
    
    # ── Xử lý các chế độ ─────────────────────────────────────────────────

    if args.knowledge_report:
        # Chế độ: Xem báo cáo Knowledge Base (không cần chạy pipeline)
        kb = KnowledgeBase(store_path=KOSConfig.KNOWLEDGE_STORE)
        kb.print_report()
        return

    if args.demo:
        # Chế độ: Demo với log Wazuh thật
        run_demo_mode(output_dir=args.output)
        return

    # Chế độ Production: lắng nghe file Wazuh thật
    # Kiểm tra file tồn tại (cảnh báo, không dừng – file có thể tạo sau)
    if not os.path.exists(args.alerts):
        logger.warning(
            f"File alerts chưa tồn tại: {args.alerts}\n"
            "  KOS sẽ chờ file được tạo. Đảm bảo Wazuh đang chạy."
        )

    # Đăng ký xử lý tín hiệu SIGTERM (khi bị kill từ systemd/supervisor)
    kos_instance: List["KOSSystem"] = []

    def _handle_sigterm(signum, frame):
        logger.info(f"[KOS] Nhận tín hiệu {signum}, đang tắt an toàn...")
        if kos_instance:
            kos_instance[0].shutdown()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _handle_sigterm)

    # Khởi tạo và chạy KOS
    try:
        kos = KOSSystem()
        kos_instance.append(kos)
        kos.start(alerts_path=args.alerts, blocking=True)
    except KeyboardInterrupt:
        logger.info("[KOS] Nhận Ctrl+C – tắt hệ thống.")
    except Exception as e:
        logger.critical(f"[KOS] Lỗi nghiêm trọng: {e}", exc_info=True)
        sys.exit(1)


# ── Điểm vào chương trình ────────────────────────────────────────────────────
if __name__ == "__main__":
    main()
