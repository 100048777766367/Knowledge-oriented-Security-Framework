"""
KOS Kernel - Perception Layer
==============================
Module: kos_kernel.py
Purpose: Giám sát và trích xuất dữ liệu alert từ Wazuh SIEM (alerts.json)
         cho hệ thống Knowledge Operating System (KOS).

Architecture:
  Wazuh alerts.json → PerceptionLayer → Processing Layer (tiếp theo)

Yêu cầu:
  pip install watchdog
"""

import json
import time
import logging
import os
from datetime import datetime
from typing import Callable, Optional, Dict, Any, List
from dataclasses import dataclass, field, asdict
from threading import Thread, Event

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileModifiedEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    print("[KOS] watchdog chưa được cài. Dùng chế độ polling (kiểm tra định kỳ).")


# ─────────────────────────────────────────────
# Logging setup
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("KOS.Kernel")


# ─────────────────────────────────────────────
# Data Model: Alert Event
# ─────────────────────────────────────────────
@dataclass
class AlertEvent:
    """
    Chuẩn hóa dữ liệu alert trích xuất từ Wazuh.
    Đây là đơn vị dữ liệu được truyền sang Processing Layer.
    """
    timestamp: str          # Thời điểm xảy ra alert
    rule_id: str            # ID rule Wazuh
    rule_level: int         # Mức độ nghiêm trọng (1–15)
    rule_description: str   # Mô tả ngắn của rule
    agent_name: str         # Tên agent/máy chủ bị ảnh hưởng
    srcip: str              # IP nguồn (nếu có)
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)  # Dữ liệu gốc

    def to_dict(self) -> Dict[str, Any]:
        """Chuyển sang dict, loại bỏ trường raw."""
        d = asdict(self)
        d.pop("raw", None)
        return d

    @property
    def severity_label(self) -> str:
        """Phân loại mức độ theo thang Wazuh."""
        if self.rule_level >= 12:
            return "CRITICAL"
        elif self.rule_level >= 9:
            return "HIGH"
        elif self.rule_level >= 6:
            return "MEDIUM"
        elif self.rule_level >= 3:
            return "LOW"
        return "INFO"

    def __str__(self) -> str:
        return (
            f"[{self.severity_label}] {self.timestamp} | "
            f"Rule {self.rule_id} (lvl {self.rule_level}) | "
            f"Agent: {self.agent_name} | SrcIP: {self.srcip} | "
            f"{self.rule_description}"
        )


# ─────────────────────────────────────────────
# Alert Parser
# ─────────────────────────────────────────────
class AlertParser:
    """
    Chịu trách nhiệm parse và chuẩn hóa dòng JSON từ alerts.json của Wazuh.
    Wazuh ghi mỗi alert thành 1 dòng JSON (NDJSON format).
    """

    @staticmethod
    def parse_line(raw_line: str) -> Optional[AlertEvent]:
        """
        Parse một dòng JSON thành AlertEvent.
        Trả về None nếu dòng không hợp lệ hoặc thiếu trường bắt buộc.
        """
        raw_line = raw_line.strip()
        if not raw_line:
            return None

        try:
            data = json.loads(raw_line)
        except json.JSONDecodeError as e:
            logger.warning(f"JSON parse lỗi: {e} | Dòng: {raw_line[:80]}...")
            return None

        try:
            # Trích xuất các trường bắt buộc
            timestamp = (
                data.get("timestamp")
                or data.get("@timestamp")
                or datetime.utcnow().isoformat()
            )

            rule       = data.get("rule", {})
            rule_id    = str(rule.get("id", "unknown"))
            rule_level = int(rule.get("level", 0))
            rule_desc  = rule.get("description", "No description")

            agent      = data.get("agent", {})
            agent_name = agent.get("name", "unknown-agent")

            # srcip có thể nằm ở nhiều vị trí tùy version Wazuh
            srcip = (
                data.get("data", {}).get("srcip")
                or data.get("data", {}).get("src_ip")
                or data.get("srcip")
                or "N/A"
            )

            return AlertEvent(
                timestamp=timestamp,
                rule_id=rule_id,
                rule_level=rule_level,
                rule_description=rule_desc,
                agent_name=agent_name,
                srcip=srcip,
                raw=data,
            )

        except (TypeError, ValueError, KeyError) as e:
            logger.warning(f"Trích xuất trường thất bại: {e}")
            return None

    @staticmethod
    def parse_file_chunk(lines: List[str]) -> List[AlertEvent]:
        """Parse nhiều dòng cùng lúc, lọc bỏ dòng lỗi."""
        events = []
        for line in lines:
            event = AlertParser.parse_line(line)
            if event:
                events.append(event)
        return events


# ─────────────────────────────────────────────
# Watchdog Handler (nếu watchdog khả dụng)
# ─────────────────────────────────────────────
if WATCHDOG_AVAILABLE:
    class _WazuhFileHandler(FileSystemEventHandler):
        """Nhận sự kiện thay đổi file từ watchdog và chuyển cho PerceptionLayer."""

        def __init__(self, target_path: str, on_change: Callable):
            super().__init__()
            self._target = os.path.abspath(target_path)
            self._on_change = on_change

        def on_modified(self, event):
            if not event.is_directory and os.path.abspath(event.src_path) == self._target:
                self._on_change()


# ─────────────────────────────────────────────
# Perception Layer – Core Class
# ─────────────────────────────────────────────
class PerceptionLayer:
    """
    KOS Perception Layer – Cổng tiếp nhận dữ liệu thô từ Wazuh.

    Nhiệm vụ:
      1. Giám sát file alerts.json theo thời gian thực (watchdog hoặc polling)
      2. Trích xuất và chuẩn hóa AlertEvent từ mỗi dòng mới
      3. Gọi callback để chuyển dữ liệu sang Processing Layer

    Ví dụ sử dụng:
      def my_processor(event: AlertEvent):
          print(event)

      layer = PerceptionLayer("/var/ossec/logs/alerts/alerts.json", my_processor)
      layer.listen()
    """

    def __init__(
        self,
        alerts_path: str,
        on_event: Optional[Callable[[AlertEvent], None]] = None,
        poll_interval: float = 1.0,
        batch_size: int = 100,
    ):
        """
        Khởi tạo Perception Layer.

        Args:
            alerts_path:   Đường dẫn đến file alerts.json của Wazuh.
            on_event:      Callback nhận AlertEvent, truyền sang Processing Layer.
            poll_interval: Chu kỳ kiểm tra file (giây) khi dùng chế độ polling.
            batch_size:    Số dòng tối đa đọc mỗi lần để tránh quá tải.
        """
        self.alerts_path = os.path.abspath(alerts_path)
        self.on_event = on_event or self._default_handler
        self.poll_interval = poll_interval
        self.batch_size = batch_size

        self._parser = AlertParser()
        self._stop_event = Event()
        self._file_position = 0          # Con trỏ vị trí đọc file
        self._stats = {
            "total_read": 0,
            "total_parsed": 0,
            "total_errors": 0,
            "started_at": None,
        }
        self._thread: Optional[Thread] = None

        logger.info(f"PerceptionLayer khởi tạo | File: {self.alerts_path}")
        logger.info(f"Chế độ: {'watchdog' if WATCHDOG_AVAILABLE else 'polling'}")

    # ── Khởi tạo vị trí đọc ────────────────────────────────────────────────
    def _initialize_position(self):
        """
        Đặt con trỏ về cuối file hiện tại để chỉ đọc alert MỚI.
        (Bỏ qua dữ liệu lịch sử có sẵn khi khởi động)
        """
        if os.path.exists(self.alerts_path):
            self._file_position = 0
            logger.info(f"Đang quét toàn bộ file log từ đầu...")
        else:
            self._file_position = 0
           
    # ── Đọc dòng mới từ file ───────────────────────────────────────────────
    def _read_new_lines(self) -> List[str]:
        """Đọc các dòng mới được ghi vào file kể từ lần đọc cuối."""
        if not os.path.exists(self.alerts_path):
            return []

        current_size = os.path.getsize(self.alerts_path)

        # Xử lý trường hợp file bị rotate (kích thước giảm)
        if current_size < self._file_position:
            logger.info("Phát hiện file rotation. Reset con trỏ về 0.")
            self._file_position = 0

        if current_size == self._file_position:
            return []  # Không có dữ liệu mới

        try:
            with open(self.alerts_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self._file_position)
                lines = []
                for _ in range(self.batch_size):
                    line = f.readline()
                    if not line:
                        break
                    lines.append(line)
                self._file_position = f.tell()
            return lines
        except OSError as e:
            logger.error(f"Lỗi đọc file: {e}")
            return []

    # ── Xử lý khi có thay đổi ─────────────────────────────────────────────
    def _process_new_data(self):
        """Đọc dòng mới → parse → gọi callback."""
        lines = self._read_new_lines()
        if not lines:
            return

        self._stats["total_read"] += len(lines)
        events = self._parser.parse_file_chunk(lines)
        self._stats["total_errors"] += len(lines) - len(events)
        self._stats["total_parsed"] += len(events)

        for event in events:
            try:
                self.on_event(event)
            except Exception as e:
                logger.error(f"Lỗi trong on_event callback: {e}")

    # ── Vòng lặp polling ───────────────────────────────────────────────────
    def _polling_loop(self):
        """Chế độ dự phòng: kiểm tra file định kỳ theo poll_interval."""
        logger.info(f"Polling mode: kiểm tra mỗi {self.poll_interval}s")
        while not self._stop_event.is_set():
            self._process_new_data()
            self._stop_event.wait(timeout=self.poll_interval)

    # ── Vòng lặp watchdog ──────────────────────────────────────────────────
    def _watchdog_loop(self):
        """Chế độ watchdog: phản ứng ngay khi file thay đổi."""
        watch_dir = os.path.dirname(self.alerts_path) or "."
        handler = _WazuhFileHandler(self.alerts_path, self._process_new_data)
        observer = Observer()
        observer.schedule(handler, path=watch_dir, recursive=False)
        observer.start()
        logger.info(f"Watchdog đang giám sát thư mục: {watch_dir}")

        try:
            while not self._stop_event.is_set():
                self._stop_event.wait(timeout=1.0)
        finally:
            observer.stop()
            observer.join()

    # ── Public API ────────────────────────────────────────────────────────
    def listen(self, blocking: bool = True):
        """
        Bắt đầu lắng nghe alert mới từ Wazuh.

        Args:
            blocking: True = chặn thread hiện tại (dùng cho production).
                      False = chạy nền (non-blocking, dùng để tích hợp).
        """
        self._initialize_position()
        self._stats["started_at"] = datetime.utcnow().isoformat()
        self._stop_event.clear()
        logger.info("🚀 KOS PerceptionLayer BẮT ĐẦU LẮNG NGHE...")

        loop_fn = self._watchdog_loop if WATCHDOG_AVAILABLE else self._polling_loop

        if blocking:
            try:
                loop_fn()
            except KeyboardInterrupt:
                logger.info("Nhận tín hiệu dừng (Ctrl+C).")
                self.stop()
        else:
            self._thread = Thread(target=loop_fn, daemon=True, name="KOS-Perception")
            self._thread.start()
            logger.info("PerceptionLayer chạy nền (non-blocking).")

    def stop(self):
        """Dừng PerceptionLayer một cách an toàn."""
        logger.info("Đang dừng PerceptionLayer...")
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        logger.info(f"Đã dừng. Thống kê: {self.get_stats()}")

    def get_stats(self) -> Dict[str, Any]:
        """Trả về thống kê hoạt động."""
        return dict(self._stats)

    @staticmethod
    def _default_handler(event: AlertEvent):
        """Handler mặc định: in ra console (dùng khi chưa kết nối Processing Layer)."""
        print(f"[ALERT] {event}")


# ─────────────────────────────────────────────
# Processing Layer Interface (Placeholder)
# ─────────────────────────────────────────────
class ProcessingLayerInterface:
    """
    Interface mẫu cho Processing Layer.
    Thay thế bằng implementation thực tế của bạn.

    Cách dùng:
        processor = ProcessingLayerInterface()
        layer = PerceptionLayer(alerts_path, on_event=processor.receive)
        layer.listen()
    """

    def __init__(self):
        self._queue: List[AlertEvent] = []

    def receive(self, event: AlertEvent):
        """Nhận AlertEvent từ PerceptionLayer."""
        self._queue.append(event)
        self._dispatch(event)

    def _dispatch(self, event: AlertEvent):
        """Phân loại và định tuyến event sang module xử lý phù hợp."""
        label = event.severity_label
        logger.info(f"[Processing] Nhận {label} alert: Rule {event.rule_id} từ {event.agent_name}")

        if label in ("CRITICAL", "HIGH"):
            self._handle_high_severity(event)
        elif label == "MEDIUM":
            self._handle_medium_severity(event)
        else:
            self._handle_low_severity(event)

    def _handle_high_severity(self, event: AlertEvent):
        logger.warning(f"🔴 HIGH/CRITICAL → Kích hoạt cảnh báo ngay: {event.rule_description}")
        # TODO: Gửi notification, tạo incident ticket, ...

    def _handle_medium_severity(self, event: AlertEvent):
        logger.info(f"🟡 MEDIUM → Đưa vào hàng đợi phân tích: {event.rule_description}")
        # TODO: Enqueue cho correlation engine, ...

    def _handle_low_severity(self, event: AlertEvent):
        logger.debug(f"🟢 LOW/INFO → Ghi log: {event.rule_description}")
        # TODO: Lưu vào database, update baseline, ...

    def get_queue(self) -> List[AlertEvent]:
        return list(self._queue)


# ─────────────────────────────────────────────
# Entry Point – Demo / Standalone Test
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="KOS Kernel – Perception Layer")
    parser.add_argument(
        "--alerts",
        default="/var/ossec/logs/alerts/alerts.json",
        help="Đường dẫn đến alerts.json của Wazuh",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Chạy chế độ demo với file giả lập",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Chu kỳ polling (giây)",
    )
    args = parser.parse_args()

    if args.demo:
        # ── Tạo file alerts.json giả để test ──────────────────────────────
        DEMO_FILE = "/tmp/kos_demo_alerts.json"
        logger.info(f"Chế độ DEMO | File test: {DEMO_FILE}")

        # Tạo file rỗng nếu chưa có
        open(DEMO_FILE, "a").close()

        processor = ProcessingLayerInterface()
        layer = PerceptionLayer(
            alerts_path=DEMO_FILE,
            on_event=processor.receive,
            poll_interval=args.interval,
        )

        # Chạy layer ở background
        layer.listen(blocking=False)
        time.sleep(0.5)

        # Giả lập Wazuh ghi alert vào file
        SAMPLE_ALERTS = [
            {
                "timestamp": "2025-01-15T10:23:45.123+0700",
                "rule": {"id": "5712", "level": 10, "description": "SSH authentication failed"},
                "agent": {"name": "web-server-01"},
                "data": {"srcip": "192.168.1.105"},
            },
            {
                "timestamp": "2025-01-15T10:23:50.456+0700",
                "rule": {"id": "31151", "level": 13, "description": "Multiple web server 400 error codes from same source ip"},
                "agent": {"name": "nginx-prod"},
                "data": {"srcip": "10.0.0.55"},
            },
            {
                "timestamp": "2025-01-15T10:24:01.789+0700",
                "rule": {"id": "1002", "level": 3, "description": "Unknown problem somewhere in the system"},
                "agent": {"name": "db-server-02"},
                "data": {"srcip": "N/A"},
            },
            {
                "timestamp": "2025-01-15T10:24:15.000+0700",
                "rule": {"id": "87002", "level": 15, "description": "Rootkit detection: hidden process"},
                "agent": {"name": "critical-host"},
                "data": {"srcip": "172.16.0.200"},
            },
        ]

        print("\n" + "═" * 60)
        print("  KOS Kernel – Demo: Giả lập Wazuh ghi alerts...")
        print("═" * 60)

        for i, alert in enumerate(SAMPLE_ALERTS, 1):
            time.sleep(1.5)
            with open(DEMO_FILE, "a") as f:
                f.write(json.dumps(alert) + "\n")
            print(f"\n  → Đã ghi alert #{i} vào {DEMO_FILE}")

        time.sleep(2)
        layer.stop()

        print("\n" + "═" * 60)
        print(f"  Thống kê: {layer.get_stats()}")
        print(f"  Tổng events xử lý: {len(processor.get_queue())}")
        print("═" * 60)

    else:
        # ── Production mode ────────────────────────────────────────────────
        processor = ProcessingLayerInterface()
        layer = PerceptionLayer(
            alerts_path=args.alerts,
            on_event=processor.receive,
            poll_interval=args.interval,
        )
        layer.listen(blocking=True)  # Chặn, chạy mãi đến khi Ctrl+C
