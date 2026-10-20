"""PostgreSQL persistence for the DefectDojo-inspired Module 1 schema."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

from exceptions import PersistenceError, ToolUnavailableError
from models import RawFinding, Target, TestRecord


def compute_hash_code(
    product_id: int,
    title: str,
    cwe: int | None,
    host: str,
    port: int,
    path: str,
) -> str:
    """Implement the handoff's exact SHA-256 deduplication formula."""

    material = f"{product_id}{title}{cwe or ''}{host}{port}{path}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class DefectDojoStore:
    """Persistence adapter that retains scanner evidence and relational links."""

    def __init__(self, dsn: str) -> None:
        try:
            import psycopg2
            from psycopg2.extras import Json
        except ImportError as exc:
            raise ToolUnavailableError(
                "PostgreSQL persistence requires psycopg2-binary. Install project requirements."
            ) from exc
        try:
            self.connection = psycopg2.connect(dsn)
        except psycopg2.Error as exc:
            raise PersistenceError(f"Could not connect to PostgreSQL: {exc}") from exc
        self._json = Json

    def close(self) -> None:
        self.connection.close()

    def ensure_schema(self) -> None:
        schema = Path(__file__).with_name("schema.sql").read_text(encoding="utf-8")
        try:
            with self.connection:
                with self.connection.cursor() as cursor:
                    cursor.execute(schema)
        except Exception as exc:
            raise PersistenceError(f"Could not initialize the PostgreSQL schema: {exc}") from exc

    def _upsert_product(self, cursor: Any, name: str, description: str) -> int:
        cursor.execute(
            """
            INSERT INTO product (name, description)
            VALUES (%s, %s)
            ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description
            RETURNING id
            """,
            (name, description),
        )
        return int(cursor.fetchone()[0])

    def _endpoint_parts(self, finding: RawFinding, target: Target) -> tuple[str, str, int, str, str]:
        parsed = urlsplit(finding.endpoint_url or target.url)
        scheme = parsed.scheme or target.scheme
        host = (parsed.hostname or target.host).lower()
        default_port = 443 if scheme == "https" else 80
        port = parsed.port or default_port
        return scheme, host, port, parsed.path or "/", parsed.query or ""

    def _upsert_endpoint(
        self, cursor: Any, product_id: int, finding: RawFinding, target: Target
    ) -> tuple[int, str, int, str]:
        protocol, host, port, path, query = self._endpoint_parts(finding, target)
        cursor.execute(
            """
            INSERT INTO endpoint (product_id, protocol, host, port, path, query)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (protocol, host, port, path, query)
            DO UPDATE SET product_id = EXCLUDED.product_id
            RETURNING id
            """,
            (product_id, protocol, host, port, path, query),
        )
        return int(cursor.fetchone()[0]), host, port, path

    def persist_scan(
        self,
        product_name: str,
        target: Target,
        tests: Iterable[TestRecord],
        product_description: str = "CyberSentinel Module 1 managed target",
    ) -> dict[str, int]:
        """Persist all scanner executions atomically and preserve scan history."""

        records = list(tests)
        try:
            with self.connection:
                with self.connection.cursor() as cursor:
                    product_id = self._upsert_product(cursor, product_name, product_description)
                    cursor.execute(
                        """
                        INSERT INTO engagement (product_id, name, status, target_url)
                        VALUES (%s, %s, 'In Progress', %s)
                        RETURNING id
                        """,
                        (product_id, f"CyberSentinel Module 1 - {target.host}", target.url),
                    )
                    engagement_id = int(cursor.fetchone()[0])
                    persisted = 0
                    duplicates = 0

                    for record in records:
                        cursor.execute(
                            """
                            INSERT INTO test (engagement_id, test_type, raw_output)
                            VALUES (%s, %s, %s)
                            RETURNING id
                            """,
                            (engagement_id, record.test_type, self._json(record.raw_output)),
                        )
                        test_id = int(cursor.fetchone()[0])

                        for finding in record.findings:
                            endpoint_id, host, port, path = self._upsert_endpoint(
                                cursor, product_id, finding, target
                            )
                            hash_code = compute_hash_code(
                                product_id, finding.title, finding.cwe, host, port, path
                            )
                            cursor.execute(
                                "SELECT 1 FROM finding WHERE hash_code = %s LIMIT 1", (hash_code,)
                            )
                            duplicate = cursor.fetchone() is not None
                            cursor.execute(
                                """
                                INSERT INTO finding
                                    (test_id, title, severity, cwe, description, mitigation, payload, hash_code, duplicate)
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                                RETURNING id
                                """,
                                (
                                    test_id,
                                    finding.title,
                                    finding.severity,
                                    finding.cwe,
                                    finding.description,
                                    finding.mitigation,
                                    finding.payload,
                                    hash_code,
                                    duplicate,
                                ),
                            )
                            finding_id = int(cursor.fetchone()[0])
                            cursor.execute(
                                """
                                INSERT INTO endpoint_status (finding_id, endpoint_id)
                                VALUES (%s, %s)
                                ON CONFLICT (finding_id, endpoint_id)
                                DO UPDATE SET last_seen = NOW()
                                """,
                                (finding_id, endpoint_id),
                            )
                            persisted += 1
                            duplicates += int(duplicate)

                    cursor.execute(
                        """
                        UPDATE engagement
                        SET status = 'Completed', end_time = NOW()
                        WHERE id = %s
                        """,
                        (engagement_id,),
                    )
        except Exception as exc:
            raise PersistenceError(f"Could not persist scan results: {exc}") from exc
        return {
            "product_id": product_id,
            "engagement_id": engagement_id,
            "persisted_findings": persisted,
            "duplicate_findings": duplicates,
        }
