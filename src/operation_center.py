"""
KOS Operation Center – Operation Layer
========================================
Module: operation_center.py
Purpose: Tiếp nhận Intelligence từ Logic Analysis Layer, tạo báo cáo sự cố
         chuyên nghiệp (Markdown) và kịch bản ứng phó (Shell script).

Pipeline hoàn chỉnh:
  Wazuh alerts.json
    → PerceptionLayer   (kos_kernel.py)
    → LogicEngine       (logic_engine.py)
    → OperationCenter   (operation_center.py)  ← Module này
        ├── incident_YYYYMMDD_HHMMSS.md   (Báo cáo sự cố)
        └── remedy_YYYYMMDD_HHMMSS.sh     (Kịch bản ứng phó – CHỈ ĐỀ XUẤT)

⚠️  AN TOÀN: Module này KHÔNG tự động thực thi bất kỳ lệnh shell nào.
    Mọi script sinh ra chỉ là đề xuất, cần quản trị viên xem xét và chạy thủ công.
"""

import os
import json
import logging
import threading
from datetime import datetime, timezone
from collections import defaultdict
from typing import Optional, Dict, Any, List, Callable, Set
from dataclasses import dataclass, field

# ── Import từ các layer trước ────────────────────────────────────────────────
try:
    from src.logic_engine import Intelligence, RiskLayer, ThreatCategory
    from src.kos_kernel import AlertEvent
except ImportError:
    # Fallback tối giản để module chạy độc lập (unit test / demo)
    from enum import Enum
    from dataclasses import dataclass as _dc

    class RiskLayer(str, Enum):
        A = "A"; B = "B"; C = "C"; D = "D"; E = "E"

    class ThreatCategory(str, Enum):
        NORMAL = "Normal Activity"; RECON = "Reconnaissance"
        BRUTE_FORCE = "Brute Force"; EXPLOIT = "Exploitation"
        MALWARE = "Malware / Rootkit"; POLICY = "Policy Violation"
        UNKNOWN = "Unknown Threat"

    @_dc
    class AlertEvent:
        timestamp: str; rule_id: str; rule_level: int
        rule_description: str; agent_name: str; srcip: str
        raw: dict = field(default_factory=dict)
        def to_dict(self): return {k: v for k, v in self.__dict__.items() if k != "raw"}

    @_dc
    class Intelligence:
        source_event: AlertEvent
        risk_layer: RiskLayer
        threat_category: ThreatCategory
        ip_reputation_score: int
        ip_reputation_label: str
        ip_total_layer_e_hits: int
        analyzed_at: str = ""
        recommended_action: str = ""
        notes: list = field(default_factory=list)

        @property
        def is_critical(self): return self.risk_layer == RiskLayer.E
        @property
        def requires_immediate_action(self):
            return self.risk_layer in (RiskLayer.D, RiskLayer.E)
        def to_dict(self):
            return {
                "analyzed_at": self.analyzed_at,
                "risk_layer": self.risk_layer.value,
                "threat_category": self.threat_category.value,
                "recommended_action": self.recommended_action,
                "ip_reputation": {
                    "score": self.ip_reputation_score,
                    "label": self.ip_reputation_label,
                    "layer_e_hits": self.ip_total_layer_e_hits,
                },
                "alert": self.source_event.to_dict(),
                "notes": self.notes,
            }


# ─────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("KOS.OperationCenter")


# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────
DEFAULT_OUTPUT_DIR        = "kos_reports"
BLOCKED_SCORE_THRESHOLD   = 30     # IP có score ≤ này sẽ vào danh sách block
LAYER_E_TRIGGER_THRESHOLD = 1      # Số lần Layer E để đưa vào incident report
INCIDENT_FLUSH_INTERVAL   = 300    # Giây: tự flush incident nếu không có trigger mới (5 phút)


# ─────────────────────────────────────────────
# Data Model: IncidentRecord
# ─────────────────────────────────────────────
@dataclass
class IncidentRecord:
    """
    Tổng hợp tất cả Intelligence thuộc một incident cụ thể.
    Được thu thập liên tục và flush ra file khi đủ điều kiện.
    """
    incident_id: str
    created_at: str
    events: List[Intelligence] = field(default_factory=list)

    # Tổng hợp
    attacker_ips: Set[str] = field(default_factory=set)
    affected_agents: Set[str] = field(default_factory=set)
    threat_categories: Set[str] = field(default_factory=set)
    max_rule_level: int = 0

    def add(self, intel: Intelligence):
        self.events.append(intel)
        ip = intel.source_event.srcip
        if ip not in ("N/A", "unknown", ""):
            self.attacker_ips.add(ip)
        self.affected_agents.add(intel.source_event.agent_name)
        self.threat_categories.add(intel.threat_category.value)
        self.max_rule_level = max(self.max_rule_level, intel.source_event.rule_level)

    @property
    def total_events(self) -> int:
        return len(self.events)

    @property
    def severity_summary(self) -> str:
        counts = defaultdict(int)
        for ev in self.events:
            counts[ev.risk_layer.value] += 1
        parts = [f"Layer {l}: {n}" for l, n in sorted(counts.items())]
        return " | ".join(parts)


# ─────────────────────────────────────────────
# Markdown Report Generator
# ─────────────────────────────────────────────
class IncidentReportGenerator:
    """
    Tạo báo cáo sự cố chuyên nghiệp theo chuẩn Markdown.
    Bao gồm: Header, Executive Summary, bảng biểu, timeline, IP list.
    """

    @staticmethod
    def generate(incident: IncidentRecord, output_path: str) -> str:
        """
        Tạo file incident_report.md từ IncidentRecord.

        Args:
            incident:    Dữ liệu tổng hợp của incident.
            output_path: Đường dẫn file Markdown sẽ ghi.

        Returns:
            Nội dung Markdown (string).
        """
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        md = []

        # ╔══════════════════════════════════════╗
        # ║  HEADER                              ║
        # ╚══════════════════════════════════════╝
        md += [
            "---",
            f"**KOS Security Intelligence Report**  ",
            f"**Incident ID:** `{incident.incident_id}`  ",
            f"**Generated:** {now_str}  ",
            f"**Classification:** 🔴 CRITICAL – Layer E Detected  ",
            "---",
            "",
            f"# 🚨 Incident Report – {incident.incident_id}",
            "",
        ]

        # ╔══════════════════════════════════════╗
        # ║  EXECUTIVE SUMMARY                   ║
        # ╚══════════════════════════════════════╝
        top_cat = max(
            set(e.threat_category.value for e in incident.events),
            key=lambda c: sum(1 for e in incident.events if e.threat_category.value == c)
        ) if incident.events else "Unknown"

        md += [
            "## 📋 Executive Summary",
            "",
            f"Hệ thống KOS phát hiện **{incident.total_events} sự kiện bất thường** "
            f"trong khoảng thời gian từ `{incident.created_at}` đến `{now_str}`. "
            f"Loại tấn công chủ yếu được phân loại là **{top_cat}**, "
            f"với mức độ nghiêm trọng cao nhất đạt **Rule Level {incident.max_rule_level}/15**.",
            "",
        ]

        # ╔══════════════════════════════════════╗
        # ║  INCIDENT OVERVIEW TABLE             ║
        # ╚══════════════════════════════════════╝
        md += [
            "## 📊 Tổng Quan Sự Cố",
            "",
            "| Thông Số | Giá Trị |",
            "|:---|:---|",
            f"| 🆔 Incident ID | `{incident.incident_id}` |",
            f"| 🕐 Thời điểm phát hiện | `{incident.created_at}` |",
            f"| 📅 Thời điểm báo cáo | `{now_str}` |",
            f"| ⚡ Tổng số sự kiện | **{incident.total_events}** |",
            f"| 🌐 IP tấn công | **{len(incident.attacker_ips)}** địa chỉ |",
            f"| 🖥️ Máy chủ bị ảnh hưởng | **{len(incident.affected_agents)}** agent |",
            f"| 🎯 Loại mối đe dọa | {', '.join(sorted(incident.threat_categories))} |",
            f"| 📈 Rule Level cao nhất | **{incident.max_rule_level}/15** |",
            f"| 📉 Phân bố tầng | {incident.severity_summary} |",
            "",
        ]

        # ╔══════════════════════════════════════╗
        # ║  ATTACKER IP TABLE                   ║
        # ╚══════════════════════════════════════╝
        md += [
            "## 🌐 Danh Sách IP Tấn Công",
            "",
        ]

        if incident.attacker_ips:
            # Thu thập thông tin IP từ events
            ip_stats: Dict[str, Dict] = {}
            for ev in incident.events:
                ip = ev.source_event.srcip
                if ip in ("N/A", "unknown", ""):
                    continue
                if ip not in ip_stats:
                    ip_stats[ip] = {
                        "hit_count": 0,
                        "layer_e_hits": ev.ip_total_layer_e_hits,
                        "rep_score": ev.ip_reputation_score,
                        "rep_label": ev.ip_reputation_label,
                        "categories": set(),
                        "agents": set(),
                        "last_seen": ev.source_event.timestamp,
                    }
                ip_stats[ip]["hit_count"] += 1
                ip_stats[ip]["layer_e_hits"] = max(ip_stats[ip]["layer_e_hits"], ev.ip_total_layer_e_hits)
                ip_stats[ip]["rep_score"] = min(ip_stats[ip]["rep_score"], ev.ip_reputation_score)
                ip_stats[ip]["categories"].add(ev.threat_category.value)
                ip_stats[ip]["agents"].add(ev.source_event.agent_name)
                ip_stats[ip]["last_seen"] = ev.source_event.timestamp

            md += [
                "| IP Address | Số Lần Tấn Công | Layer E Hits | Rep. Score | Trạng Thái | Loại Tấn Công | Mục Tiêu |",
                "|:---|:---:|:---:|:---:|:---:|:---|:---|",
            ]

            for ip, stat in sorted(ip_stats.items(), key=lambda x: x[1]["rep_score"]):
                score = stat["rep_score"]
                label = stat["rep_label"]
                label_icon = {"TRUSTED": "🟢", "SUSPICIOUS": "🟡", "DANGEROUS": "🟠", "BLOCKED": "🔴"}.get(label, "⚪")
                cats = ", ".join(sorted(stat["categories"]))
                agents = ", ".join(sorted(stat["agents"]))
                md.append(
                    f"| `{ip}` | {stat['hit_count']} | {stat['layer_e_hits']} | "
                    f"**{score}/100** | {label_icon} {label} | {cats} | {agents} |"
                )
            md.append("")
        else:
            md += ["> ℹ️ Không xác định được IP nguồn trong các sự kiện này.", ""]

        # ╔══════════════════════════════════════╗
        # ║  AFFECTED AGENTS                     ║
        # ╚══════════════════════════════════════╝
        md += [
            "## 🖥️ Máy Chủ Bị Ảnh Hưởng",
            "",
            "| Agent Name | Số Sự Kiện | Mức Nghiêm Trọng Cao Nhất |",
            "|:---|:---:|:---:|",
        ]

        agent_stats: Dict[str, Dict] = {}
        for ev in incident.events:
            ag = ev.source_event.agent_name
            if ag not in agent_stats:
                agent_stats[ag] = {"count": 0, "max_level": 0}
            agent_stats[ag]["count"] += 1
            agent_stats[ag]["max_level"] = max(agent_stats[ag]["max_level"], ev.source_event.rule_level)

        for ag, stat in sorted(agent_stats.items(), key=lambda x: -x[1]["max_level"]):
            level_bar = "🔴" * (stat["max_level"] // 5) + "🟡" * ((stat["max_level"] % 5) // 2)
            md.append(f"| `{ag}` | {stat['count']} | Level {stat['max_level']} {level_bar} |")
        md.append("")

        # ╔══════════════════════════════════════╗
        # ║  EVENT TIMELINE                      ║
        # ╚══════════════════════════════════════╝
        md += [
            "## 🕐 Timeline Sự Kiện (Layer D & E)",
            "",
            "| Thời Gian | Layer | Rule ID | Level | Loại Tấn Công | Agent | Src IP | Mô Tả |",
            "|:---|:---:|:---:|:---:|:---|:---|:---|:---|",
        ]

        critical_events = [
            e for e in incident.events
            if e.risk_layer in (RiskLayer.D, RiskLayer.E)
        ]
        # Sắp xếp theo thời gian
        critical_events.sort(key=lambda x: x.source_event.timestamp)

        layer_icons_tl = {
            RiskLayer.A: "🟢 A", RiskLayer.B: "🔵 B",
            RiskLayer.C: "🟡 C", RiskLayer.D: "🟠 D", RiskLayer.E: "🔴 E",
        }

        for ev in critical_events:
            ts = ev.source_event.timestamp[:19].replace("T", " ")
            layer_str = layer_icons_tl.get(ev.risk_layer, ev.risk_layer.value)
            desc_short = ev.source_event.rule_description[:55]
            if len(ev.source_event.rule_description) > 55:
                desc_short += "…"
            md.append(
                f"| `{ts}` | {layer_str} | `{ev.source_event.rule_id}` | "
                f"{ev.source_event.rule_level} | {ev.threat_category.value} | "
                f"`{ev.source_event.agent_name}` | `{ev.source_event.srcip}` | {desc_short} |"
            )

        if not critical_events:
            md.append("| – | – | – | – | Không có sự kiện Layer D/E | – | – | – |")
        md.append("")

        # ╔══════════════════════════════════════╗
        # ║  RECOMMENDATIONS                     ║
        # ╚══════════════════════════════════════╝
        unique_actions = list(dict.fromkeys(
            e.recommended_action for e in incident.events if e.recommended_action
        ))

        md += [
            "## 💡 Khuyến Nghị Ứng Phó",
            "",
        ]

        for i, action in enumerate(unique_actions, 1):
            # Loại bỏ emoji ở đầu để format lại
            clean = action.strip()
            md.append(f"{i}. {clean}")

        md += [
            "",
            "> **Lưu ý:** Xem file `remedy_action.sh` đi kèm để biết chi tiết",
            "> các lệnh iptables/ufw được đề xuất để chặn IP tấn công.",
            "",
        ]

        # ╔══════════════════════════════════════╗
        # ║  NOTES & CONTEXT                     ║
        # ╚══════════════════════════════════════╝
        all_notes = []
        for ev in incident.events:
            for note in ev.notes:
                if note not in all_notes:
                    all_notes.append(note)

        if all_notes:
            md += [
                "## 📝 Ghi Chú Phân Tích",
                "",
            ]
            for note in all_notes:
                md.append(f"- {note}")
            md.append("")

        # ╔══════════════════════════════════════╗
        # ║  FOOTER                              ║
        # ╚══════════════════════════════════════╝
        md += [
            "---",
            "",
            "## ⚠️ Tuyên Bố Trách Nhiệm",
            "",
            "Báo cáo này được tạo **tự động** bởi hệ thống **KOS (Knowledge Operating System)**.",
            "Mọi đề xuất ứng phó trong tài liệu này cần được **quản trị viên có thẩm quyền**",
            "xem xét và phê duyệt trước khi thực thi.",
            "",
            "**KHÔNG** tự động chặn IP hay thực thi lệnh hệ thống mà không có quy trình phê duyệt.",
            "",
            "---",
            f"*Tạo bởi KOS Operation Center | {now_str}*",
            f"*Incident ID: `{incident.incident_id}`*",
        ]

        content = "\n".join(md)

        # Ghi file
        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)

        logger.info(f"[ReportGen] Đã tạo báo cáo: {output_path}")
        return content


# ─────────────────────────────────────────────
# Shell Script Generator
# ─────────────────────────────────────────────
class RemediationScriptGenerator:
    """
    Tạo kịch bản shell (.sh) chứa các lệnh chặn IP bằng iptables và ufw.

    ⚠️  SAFETY GUARANTEE:
        - Module này chỉ GHI FILE, tuyệt đối KHÔNG gọi subprocess hay os.system.
        - Script sinh ra cần quản trị viên xem xét, test trên staging, rồi mới chạy.
        - Tất cả lệnh trong script đều có comment giải thích và bước rollback.
    """

    FIREWALL_COMMENT_TAG = "KOS_AUTO_BLOCK"

    @classmethod
    def generate(cls, incident: IncidentRecord, output_path: str) -> str:
        """
        Tạo file remedy_action.sh.

        Args:
            incident:    IncidentRecord chứa danh sách IP và context tấn công.
            output_path: Đường dẫn file .sh sẽ ghi.

        Returns:
            Nội dung script (string).
        """
        now_str  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        now_safe = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        # Thu thập thông tin IP đầy đủ
        ip_info: Dict[str, Dict] = {}
        for ev in incident.events:
            ip = ev.source_event.srcip
            if ip in ("N/A", "unknown", ""):
                continue
            if ip not in ip_info:
                ip_info[ip] = {
                    "rep_score": ev.ip_reputation_score,
                    "rep_label": ev.ip_reputation_label,
                    "layer_e_hits": ev.ip_total_layer_e_hits,
                    "categories": set(),
                    "hit_count": 0,
                    "rule_ids": set(),
                }
            ip_info[ip]["hit_count"] += 1
            ip_info[ip]["rep_score"]  = min(ip_info[ip]["rep_score"], ev.ip_reputation_score)
            ip_info[ip]["layer_e_hits"] = max(ip_info[ip]["layer_e_hits"], ev.ip_total_layer_e_hits)
            ip_info[ip]["categories"].add(ev.threat_category.value)
            ip_info[ip]["rule_ids"].add(ev.source_event.rule_id)

        # Phân loại: block ngay vs monitor
        block_ips    = {ip: d for ip, d in ip_info.items() if d["rep_score"] <= 30 or d["layer_e_hits"] >= 3}
        monitor_ips  = {ip: d for ip, d in ip_info.items() if ip not in block_ips}

        lines = []

        # ── Header ──────────────────────────────────────────────────────────
        lines += [
            "#!/usr/bin/env bash",
            "# " + "═" * 70,
            f"# KOS REMEDIATION SCRIPT – Incident {incident.incident_id}",
            "# " + "═" * 70,
            "#",
            f"# Generated by  : KOS Operation Center",
            f"# Incident ID   : {incident.incident_id}",
            f"# Generated at  : {now_str}",
            f"# Total IPs     : {len(ip_info)}",
            f"# Block list    : {len(block_ips)} IP(s)",
            f"# Monitor list  : {len(monitor_ips)} IP(s)",
            "#",
            "# ⚠️  QUAN TRỌNG – ĐỌC KỸ TRƯỚC KHI CHẠY:",
            "#   1. Script này được tạo TỰ ĐỘNG bởi KOS. KHÔNG chạy mù quáng.",
            "#   2. Kiểm tra kỹ danh sách IP bên dưới, đảm bảo không block nhầm",
            "#      IP nội bộ, IP partner, hoặc IP load balancer.",
            "#   3. Test trên môi trường staging trước.",
            "#   4. Backup rule firewall hiện tại trước khi áp dụng.",
            "#   5. Đảm bảo bạn có kết nối dự phòng (console, IPMI) nếu bị lock.",
            "#",
            "# " + "═" * 70,
            "",
        ]

        # ── Safety checks ────────────────────────────────────────────────────
        lines += [
            "# ─────────────────────────────────────────────",
            "# SECTION 0: Kiểm tra môi trường và xác nhận",
            "# ─────────────────────────────────────────────",
            "",
            "set -euo pipefail   # Dừng ngay nếu có lỗi, biến chưa khai báo, hoặc pipe lỗi",
            "",
            "# Màu terminal",
            'RED="\\033[0;31m"; YELLOW="\\033[1;33m"; GREEN="\\033[0;32m"; NC="\\033[0m"',
            "",
            'echo -e "${YELLOW}╔══════════════════════════════════════════════╗${NC}"',
            f'echo -e "${{YELLOW}}║  KOS Remediation – Incident {incident.incident_id[:16]:<16} ║${{NC}}"',
            'echo -e "${YELLOW}╚══════════════════════════════════════════════╝${NC}"',
            'echo ""',
            "",
            "# Kiểm tra quyền root",
            'if [[ "$EUID" -ne 0 ]]; then',
            '  echo -e "${RED}[ERROR] Script này cần chạy với quyền root (sudo).${NC}"',
            '  exit 1',
            "fi",
            "",
            "# Xác nhận từ operator",
            'echo -e "${RED}[CẢNH BÁO] Script này sẽ CHẶN các IP sau:${NC}"',
        ]

        for ip, data in sorted(block_ips.items(), key=lambda x: x[1]["rep_score"]):
            lines.append(f'echo "  🔴 {ip} (Score: {data["rep_score"]}/100 | Layer E hits: {data["layer_e_hits"]})"')

        lines += [
            "",
            'read -rp "Bạn có chắc muốn tiếp tục? (yes/no): " CONFIRM',
            'if [[ "$CONFIRM" != "yes" ]]; then',
            '  echo "Đã hủy. Không có thay đổi nào được thực hiện."',
            '  exit 0',
            "fi",
            "",
        ]

        # ── Backup firewall rules ────────────────────────────────────────────
        lines += [
            "# ─────────────────────────────────────────────",
            "# SECTION 1: Backup quy tắc Firewall hiện tại",
            "# ─────────────────────────────────────────────",
            "",
            f'BACKUP_DIR="/var/backups/kos_firewall"',
            f'BACKUP_FILE="${{BACKUP_DIR}}/iptables_backup_{now_safe}.rules"',
            'mkdir -p "$BACKUP_DIR"',
            "",
            "# Backup iptables",
            'if command -v iptables-save &>/dev/null; then',
            '  iptables-save > "$BACKUP_FILE"',
            '  echo -e "${GREEN}[OK] Backup iptables → $BACKUP_FILE${NC}"',
            "fi",
            "",
            "# Backup ufw (nếu có)",
            'if command -v ufw &>/dev/null; then',
            '  ufw status verbose > "${BACKUP_DIR}/ufw_status_' + now_safe + '.txt" 2>/dev/null || true',
            '  echo -e "${GREEN}[OK] Backup trạng thái UFW${NC}"',
            "fi",
            "",
        ]

        # ── Auto-detect firewall ─────────────────────────────────────────────
        lines += [
            "# ─────────────────────────────────────────────",
            "# SECTION 2: Phát hiện Firewall đang dùng",
            "# ─────────────────────────────────────────────",
            "",
            "USE_UFW=0",
            "USE_IPTABLES=0",
            "",
            'if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then',
            '  USE_UFW=1',
            '  echo "[INFO] Phát hiện UFW đang hoạt động → Dùng UFW"',
            "elif command -v iptables &>/dev/null; then",
            '  USE_IPTABLES=1',
            '  echo "[INFO] Dùng iptables"',
            "else",
            '  echo -e "${RED}[ERROR] Không tìm thấy iptables hoặc ufw!${NC}"',
            '  exit 1',
            "fi",
            "",
        ]

        # ── Block IP section ─────────────────────────────────────────────────
        lines += [
            "# ─────────────────────────────────────────────",
            "# SECTION 3: CHẶN IP TẤN CÔNG (Mức độ cao)",
            f"# Danh sách: {len(block_ips)} IP cần block ngay",
            "# ─────────────────────────────────────────────",
            "",
            'echo ""',
            'echo -e "${RED}[*] Đang áp dụng block rules...${NC}"',
            "",
        ]

        for ip, data in sorted(block_ips.items(), key=lambda x: x[1]["rep_score"]):
            cats = ", ".join(sorted(data["categories"]))
            rule_ids = ", ".join(sorted(data["rule_ids"]))
            lines += [
                f"# ── IP: {ip} ──────────────────────────────────",
                f"# Reputation Score : {data['rep_score']}/100 ({data['rep_label']})",
                f"# Layer E Hits     : {data['layer_e_hits']} lần",
                f"# Số sự kiện       : {data['hit_count']}",
                f"# Loại tấn công    : {cats}",
                f"# Rule IDs liên quan: {rule_ids}",
                f'if [[ $USE_UFW -eq 1 ]]; then',
                f'  echo "  [UFW] Chặn {ip}..."',
                f'  ufw deny from {ip} to any comment "{cls.FIREWALL_COMMENT_TAG}_{incident.incident_id}"',
                f'elif [[ $USE_IPTABLES -eq 1 ]]; then',
                f'  echo "  [iptables] Chặn {ip}..."',
                f'  # Chặn mọi kết nối ĐẾN từ IP này',
                f'  iptables -I INPUT -s {ip} -j DROP -m comment --comment "{cls.FIREWALL_COMMENT_TAG}_{incident.incident_id}"',
                f'  # Chặn mọi kết nối ĐI ĐẾN IP này (ngăn lateral movement)',
                f'  iptables -I OUTPUT -d {ip} -j DROP -m comment --comment "{cls.FIREWALL_COMMENT_TAG}_{incident.incident_id}"',
                f'fi',
                f'echo "  ✅ Đã thêm rule block cho {ip}"',
                "",
            ]

        # ── Monitor IP section ───────────────────────────────────────────────
        if monitor_ips:
            lines += [
                "# ─────────────────────────────────────────────",
                "# SECTION 4: THEO DÕI IP ĐÁNG NGỜ (Mức độ trung bình)",
                f"# {len(monitor_ips)} IP cần giám sát tăng cường (chưa block ngay)",
                "# ─────────────────────────────────────────────",
                "",
                'echo ""',
                'echo -e "${YELLOW}[*] Áp dụng rate-limiting cho IP đáng ngờ...${NC}"',
                "",
            ]

            for ip, data in sorted(monitor_ips.items(), key=lambda x: x[1]["rep_score"]):
                cats = ", ".join(sorted(data["categories"]))
                lines += [
                    f"# ── IP: {ip} (Đáng ngờ – theo dõi) ──────────────────",
                    f"# Reputation Score : {data['rep_score']}/100 | Loại: {cats}",
                    f'if [[ $USE_UFW -eq 1 ]]; then',
                    f'  echo "  [UFW] Rate-limit {ip}..."',
                    f'  ufw limit from {ip} comment "{cls.FIREWALL_COMMENT_TAG}_MONITOR_{incident.incident_id}"',
                    f'elif [[ $USE_IPTABLES -eq 1 ]]; then',
                    f'  echo "  [iptables] Rate-limit {ip} (max 10 conn/min)..."',
                    f'  iptables -I INPUT -s {ip} -m state --state NEW -m recent --set --name KOS_MONITOR',
                    f'  iptables -I INPUT -s {ip} -m state --state NEW -m recent --update \\',
                    f'    --seconds 60 --hitcount 10 --name KOS_MONITOR -j DROP \\',
                    f'    -m comment --comment "{cls.FIREWALL_COMMENT_TAG}_MONITOR_{incident.incident_id}"',
                    f'fi',
                    f'echo "  🟡 Đã thêm rate-limit cho {ip}"',
                    "",
                ]

        # ── Logging & Persist ────────────────────────────────────────────────
        lines += [
            "# ─────────────────────────────────────────────",
            "# SECTION 5: Lưu thay đổi và ghi log",
            "# ─────────────────────────────────────────────",
            "",
            "# Lưu iptables rules để tồn tại sau reboot",
            'if [[ $USE_IPTABLES -eq 1 ]]; then',
            '  if command -v iptables-save &>/dev/null; then',
            '    iptables-save > /etc/iptables/rules.v4 2>/dev/null || \\',
            '    iptables-save > /etc/sysconfig/iptables 2>/dev/null || \\',
            '    echo "[WARN] Không thể lưu rules tự động. Chạy: iptables-save > /etc/iptables/rules.v4"',
            '  fi',
            "fi",
            "",
            "# Ghi audit log",
            f'AUDIT_LOG="/var/log/kos_remediation.log"',
            f'echo "[{now_str}] Incident={incident.incident_id} | '
            f'Blocked={len(block_ips)} IPs | Monitor={len(monitor_ips)} IPs | '
            f'Operator=$(whoami)" >> "$AUDIT_LOG"',
            'echo -e "${GREEN}[OK] Đã ghi audit log → $AUDIT_LOG${NC}"',
            "",
        ]

        # ── Rollback script ──────────────────────────────────────────────────
        lines += [
            "# ─────────────────────────────────────────────",
            "# SECTION 6: Hướng dẫn ROLLBACK (nếu cần hoàn tác)",
            "# ─────────────────────────────────────────────",
            "",
            'echo ""',
            'echo "════════════════════════════════════════════════"',
            'echo "  HƯỚNG DẪN ROLLBACK (hoàn tác nếu cần):"',
            'echo "════════════════════════════════════════════════"',
        ]

        for ip in sorted(block_ips.keys()):
            lines += [
                f'echo "  # Bỏ block IP {ip}:"',
                f'echo "  # ufw delete deny from {ip}"',
                f'echo "  # iptables -D INPUT -s {ip} -j DROP"',
                f'echo "  # iptables -D OUTPUT -d {ip} -j DROP"',
            ]

        lines += [
            f'echo ""',
            f'echo "  # Khôi phục từ backup:"',
            f'echo "  # iptables-restore < $BACKUP_FILE"',
            'echo "════════════════════════════════════════════════"',
            "",
        ]

        # ── Summary ─────────────────────────────────────────────────────────
        lines += [
            "# ─────────────────────────────────────────────",
            "# HOÀN TẤT",
            "# ─────────────────────────────────────────────",
            "",
            'echo ""',
            'echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"',
            'echo -e "${GREEN}║  ✅ KOS Remediation hoàn tất              ║${NC}"',
            'echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"',
            f'echo "  Incident : {incident.incident_id}"',
            f'echo "  Blocked  : {len(block_ips)} IP(s)"',
            f'echo "  Monitor  : {len(monitor_ips)} IP(s)"',
            'echo "  ⚠️  Hãy kiểm tra lại kết nối mạng và xác nhận dịch vụ còn hoạt động"',
            'echo ""',
            "",
            "# END OF SCRIPT",
        ]

        content = "\n".join(lines)

        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)

        # Đặt permission gợi ý (không execute ngay)
        os.chmod(output_path, 0o640)  # rw-r----- : chỉ owner đọc/ghi, group đọc

        logger.info(f"[ScriptGen] Đã tạo kịch bản ứng phó: {output_path} (chmod 640 – chưa executable)")
        return content


# ─────────────────────────────────────────────
# Operation Center – Core Class
# ─────────────────────────────────────────────
class OperationCenter:
    """
    KOS Operation Layer – Trung tâm điều hành ứng phó sự cố.

    Quy trình:
      1. Nhận Intelligence từ LogicEngine qua phương thức receive()
      2. Tích lũy các sự kiện Layer E vào IncidentRecord hiện hành
      3. Khi đủ điều kiện (hoặc gọi flush()), tạo:
           - incident_<ID>.md  (báo cáo chuyên nghiệp)
           - remedy_<ID>.sh    (kịch bản ứng phó)
      4. Gọi on_incident_created callback để notify Response Layer tiếp theo

    Ví dụ:
      center = OperationCenter(output_dir="kos_reports")
      engine = LogicEngine(on_intelligence=center.receive)
    """

    def __init__(
        self,
        output_dir: str = DEFAULT_OUTPUT_DIR,
        on_incident_created: Optional[Callable[[str, str], None]] = None,
        auto_flush_interval: float = INCIDENT_FLUSH_INTERVAL,
        include_layer_d: bool = True,
    ):
        """
        Args:
            output_dir:            Thư mục lưu báo cáo và script.
            on_incident_created:   Callback(report_path, script_path) khi tạo xong file.
            auto_flush_interval:   Tự động flush incident sau N giây không có event mới (0 = tắt).
            include_layer_d:       Thu thập cả Layer D vào incident report.
        """
        self.output_dir = output_dir
        self.on_incident_created = on_incident_created
        self.auto_flush_interval = auto_flush_interval
        self.include_layer_d = include_layer_d

        self._lock = threading.Lock()
        self._current_incident: Optional[IncidentRecord] = None
        self._flush_timer: Optional[threading.Timer] = None

        self._stats = {
            "total_received": 0,
            "total_incidents_created": 0,
            "total_layer_e": 0,
        }

        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"OperationCenter khởi tạo | Output: {output_dir}/")

    # ── Public API ────────────────────────────────────────────────────
    def receive(self, intel: Intelligence):
        """
        Điểm đầu vào từ LogicEngine.
        Gọi hàm này như callback: engine = LogicEngine(on_intelligence=center.receive)
        """
        with self._lock:
            self._stats["total_received"] += 1

            trigger_layers = [RiskLayer.E]
            if self.include_layer_d:
                trigger_layers.append(RiskLayer.D)

            if intel.risk_layer in trigger_layers:
                if intel.risk_layer == RiskLayer.E:
                    self._stats["total_layer_e"] += 1

                # Tạo incident mới nếu chưa có
                if self._current_incident is None:
                    self._current_incident = IncidentRecord(
                        incident_id=self._new_incident_id(),
                        created_at=intel.source_event.timestamp or
                                   datetime.now(timezone.utc).isoformat(),
                    )
                    logger.warning(
                        f"[OperationCenter] 🚨 Incident mới: {self._current_incident.incident_id}"
                    )

                self._current_incident.add(intel)
                logger.warning(
                    f"[OperationCenter] Layer {intel.risk_layer.value} event thêm vào "
                    f"incident {self._current_incident.incident_id} "
                    f"(tổng: {self._current_incident.total_events})"
                )

                # Reset auto-flush timer
                self._reset_flush_timer()

            # Không phải Layer D/E: chỉ log nhẹ
            else:
                logger.debug(f"[OperationCenter] Layer {intel.risk_layer.value} – không tạo incident")

    def flush(self) -> Optional[tuple]:
        """
        Tạo ngay báo cáo và script từ incident đang tích lũy.

        Returns:
            (report_path, script_path) hoặc None nếu không có incident.
        """
        with self._lock:
            return self._flush_locked()

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            current_size = self._current_incident.total_events if self._current_incident else 0
            return {**self._stats, "current_incident_events": current_size}

    # ── Internal ─────────────────────────────────────────────────────
    def _flush_locked(self) -> Optional[tuple]:
        """Flush không lock (gọi từ bên trong lock)."""
        if self._current_incident is None or self._current_incident.total_events == 0:
            logger.info("[OperationCenter] Không có incident để flush.")
            return None

        incident = self._current_incident
        self._current_incident = None

        # Hủy timer nếu có
        if self._flush_timer:
            self._flush_timer.cancel()
            self._flush_timer = None

        # Tạo tên file
        safe_id = incident.incident_id.replace(":", "-")
        report_path = os.path.join(self.output_dir, f"incident_{safe_id}.md")
        script_path = os.path.join(self.output_dir, f"remedy_{safe_id}.sh")

        # Sinh file
        IncidentReportGenerator.generate(incident, report_path)
        RemediationScriptGenerator.generate(incident, script_path)

        self._stats["total_incidents_created"] += 1

        logger.warning(
            f"[OperationCenter] ✅ Incident {incident.incident_id} đã flush:\n"
            f"  📄 Report : {report_path}\n"
            f"  🛠️  Script : {script_path}"
        )

        # Notify callback
        if self.on_incident_created:
            try:
                self.on_incident_created(report_path, script_path)
            except Exception as e:
                logger.error(f"Lỗi on_incident_created callback: {e}")

        return report_path, script_path

    def _reset_flush_timer(self):
        """Khởi động lại timer auto-flush."""
        if self.auto_flush_interval <= 0:
            return
        if self._flush_timer:
            self._flush_timer.cancel()
        self._flush_timer = threading.Timer(
            self.auto_flush_interval,
            self._auto_flush,
        )
        self._flush_timer.daemon = True
        self._flush_timer.start()

    def _auto_flush(self):
        """Được gọi tự động khi timer hết hạn."""
        logger.info(f"[OperationCenter] Auto-flush sau {self.auto_flush_interval}s không hoạt động.")
        with self._lock:
            self._flush_locked()

    @staticmethod
    def _new_incident_id() -> str:
        """Tạo ID duy nhất cho incident."""
        return datetime.now(timezone.utc).strftime("INC-%Y%m%d-%H%M%S")


# ─────────────────────────────────────────────
# Full Pipeline Builder
# ─────────────────────────────────────────────
def build_full_kos_pipeline(
    alerts_path: str,
    reputation_db_path: str = "reputation_db.json",
    output_dir: str = DEFAULT_OUTPUT_DIR,
    on_incident_created: Optional[Callable[[str, str], None]] = None,
):
    """
    Khởi tạo pipeline KOS 3 tầng hoàn chỉnh:
      PerceptionLayer → LogicEngine → OperationCenter

    Args:
        alerts_path:          Đường dẫn alerts.json Wazuh.
        reputation_db_path:   File reputation DB.
        output_dir:           Thư mục xuất báo cáo.
        on_incident_created:  Callback khi có báo cáo mới.

    Returns:
        (perception_layer, logic_engine, operation_center)
    """
    try:
        from src.logic_engine import LogicEngine
        from src.kos_kernel import PerceptionLayer
    except ImportError as e:
        raise ImportError(f"Thiếu module KOS: {e}. Đảm bảo kos_kernel.py và logic_engine.py cùng thư mục.")

    center = OperationCenter(
        output_dir=output_dir,
        on_incident_created=on_incident_created,
    )
    engine = LogicEngine(
        reputation_db_path=reputation_db_path,
        on_intelligence=center.receive,
    )
    perception = PerceptionLayer(
        alerts_path=alerts_path,
        on_event=engine.process,
    )

    return perception, engine, center


# ─────────────────────────────────────────────
# Entry Point – Demo
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    argp = argparse.ArgumentParser(description="KOS Operation Center – Operation Layer")
    argp.add_argument("--output", default="kos_reports", help="Thư mục xuất báo cáo")
    argp.add_argument("--demo",   action="store_true",   help="Chạy demo với dữ liệu mẫu")
    args = argp.parse_args()

    if not args.demo:
        print("Dùng --demo để chạy thử.")
        print("Ví dụ: python operation_center.py --demo --output ./reports")
        exit(0)

    # ── Tạo dữ liệu mẫu Intelligence ──────────────────────────────────────
    print(f"\n{'═'*65}")
    print("  KOS Operation Center – DEMO MODE")
    print(f"{'═'*65}\n")

    try:
        from src.logic_engine import (
            Intelligence, RiskLayer, ThreatCategory,
            REPUTATION_BLOCKED_THRESHOLD
        )
    except ImportError:
        pass  # Dùng fallback đã định nghĩa ở đầu file

    def _mk_event(ts, rule_id, level, desc, agent, ip):
        return AlertEvent(
            timestamp=ts, rule_id=rule_id, rule_level=level,
            rule_description=desc, agent_name=agent, srcip=ip,
        )

    def _mk_intel(ev, layer, cat, score, label, e_hits, action, notes):
        return Intelligence(
            source_event=ev,
            risk_layer=layer,
            threat_category=cat,
            ip_reputation_score=score,
            ip_reputation_label=label,
            ip_total_layer_e_hits=e_hits,
            analyzed_at=datetime.now(timezone.utc).isoformat(),
            recommended_action=action,
            notes=notes,
        )

    DEMO_INTELS = [
        _mk_intel(
            _mk_event("2025-04-11T08:00:00Z", "5712", 10,
                      "SSH brute force attack detected", "web-server-01", "185.220.101.45"),
            RiskLayer.E, ThreatCategory.BRUTE_FORCE, 55, "SUSPICIOUS", 1,
            "🚨 PHẢN ỨNG NGAY – Cô lập agent, thu thập forensics | Kiểm tra chính sách lockout",
            ["⚡ Layer E kích hoạt – rule level 10", "🔐 Nghi ngờ tấn công Brute Force"],
        ),
        _mk_intel(
            _mk_event("2025-04-11T08:02:00Z", "5712", 11,
                      "SSH brute force – multiple failed logins", "web-server-02", "185.220.101.45"),
            RiskLayer.E, ThreatCategory.BRUTE_FORCE, 40, "DANGEROUS", 2,
            "🚨 PHẢN ỨNG NGAY | Kiểm tra chính sách lockout, xem xét block IP",
            ["🔁 IP xuất hiện 2 lần ở Layer E – hành vi tái diễn"],
        ),
        _mk_intel(
            _mk_event("2025-04-11T08:05:00Z", "31151", 13,
                      "Web server exploit attempt – LFI detected", "nginx-prod", "91.108.56.170"),
            RiskLayer.E, ThreatCategory.EXPLOIT, 70, "SUSPICIOUS", 1,
            "🚨 PHẢN ỨNG NGAY – Cô lập agent | Patch ngay lập tức, rà soát IOC",
            ["⚡ Layer E kích hoạt – rule level 13"],
        ),
        _mk_intel(
            _mk_event("2025-04-11T08:07:00Z", "87002", 15,
                      "Rootkit detection: hidden process found", "db-server", "172.16.0.200"),
            RiskLayer.E, ThreatCategory.MALWARE, 25, "BLOCKED", 3,
            "🚨 PHẢN ỨNG NGAY | Cô lập máy, chạy AV scan toàn bộ",
            ["⚡ Layer E kích hoạt – rule level 15", "☣️ Dấu hiệu Malware/Rootkit",
             "🔴 IP uy tín cực thấp (25/100) – khuyến nghị BLOCK",
             "🔁 IP xuất hiện 3 lần ở Layer E"],
        ),
        _mk_intel(
            _mk_event("2025-04-11T08:10:00Z", "40111", 8,
                      "Unauthorized privilege escalation attempt", "app-server", "10.0.0.55"),
            RiskLayer.D, ThreatCategory.POLICY, 78, "TRUSTED", 0,
            "⚠️ Điều tra ngay, tạo ticket phân tích | Xem xét quyền truy cập",
            ["Layer D – cần điều tra"],
        ),
        _mk_intel(
            _mk_event("2025-04-11T08:12:00Z", "5712", 10,
                      "SSH brute force attack detected", "web-server-03", "185.220.101.45"),
            RiskLayer.E, ThreatCategory.BRUTE_FORCE, 25, "BLOCKED", 3,
            "🚫 BLOCK IP ngay lập tức – Điểm uy tín cực thấp",
            ["🔴 IP uy tín cực thấp (25/100)", "🔁 IP xuất hiện 3 lần ở Layer E"],
        ),
    ]

    # Khởi tạo OperationCenter
    def notify(report_path, script_path):
        print(f"\n  📢 NOTIFICATION:")
        print(f"     📄 Báo cáo : {report_path}")
        print(f"     🛠️  Script  : {script_path}")

    center = OperationCenter(
        output_dir=args.output,
        on_incident_created=notify,
        auto_flush_interval=0,   # Tắt auto-flush cho demo
    )

    print(f"  Đang gửi {len(DEMO_INTELS)} Intelligence events vào OperationCenter...\n")
    for intel in DEMO_INTELS:
        layer_icon = {"A": "🟢", "B": "🔵", "C": "🟡", "D": "🟠", "E": "🔴"}.get(intel.risk_layer.value, "⚪")
        print(f"  {layer_icon} [{intel.risk_layer.value}] {intel.threat_category.value} | "
              f"IP: {intel.source_event.srcip} | {intel.source_event.rule_description[:50]}")
        center.receive(intel)

    # Flush thủ công
    print(f"\n  [*] Flush incident → tạo báo cáo và kịch bản ứng phó...")
    result = center.flush()

    if result:
        report_path, script_path = result
        print(f"\n{'═'*65}")
        print("  ✅ KOS Operation Center – Hoàn tất Demo")
        print(f"{'═'*65}")
        print(f"  📄 Báo cáo sự cố : {report_path}")
        print(f"  🛠️  Kịch bản ứng phó: {script_path}")
        print(f"  📊 Thống kê       : {center.get_stats()}")
        print(f"\n  ⚠️  Script được tạo với chmod 640 (chỉ đọc – chưa executable).")
        print(f"  ⚠️  Để chạy: sudo chmod +x {script_path} && sudo ./{script_path}")
        print(f"{'═'*65}")
    else:
        print("  Không có incident nào được tạo.")
