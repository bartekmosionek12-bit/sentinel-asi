"""P1: usunięcie modułów spoza briefu AGH, role własne i nadania ról

Usuwa organizację (działy, lokalizacje, pracownicy, przypisania), metrykę pokrycia, prośby
menedżera o skan i nieużywane tabele compliance. Zostają segmenty sieci (widok sieci) i źródła
inwentarza. Dodaje edytor ról: `iam_custom_role` i `iam_role_grant`.
Downgrade odtwarza strukturę (bez danych).

Revision ID: 0013
Revises: 0012
Create Date: 2026-11-21
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    op.drop_index(op.f("ix_scan_request_status"), table_name="scan_request")
    op.drop_index(op.f("ix_scan_request_requested_by"), table_name="scan_request")
    op.drop_table("scan_request")
    op.drop_table("coverage_snapshot")
    op.drop_index(op.f("ix_compliance_result_rule_id"), table_name="compliance_result")
    op.drop_index(op.f("ix_compliance_result_asset_id"), table_name="compliance_result")
    op.drop_table("compliance_result")
    op.drop_table("compliance_rule")
    op.drop_index(op.f("ix_asset_assignment_person_id"), table_name="asset_assignment")
    op.drop_index(op.f("ix_asset_assignment_asset_id"), table_name="asset_assignment")
    op.drop_table("asset_assignment")
    op.drop_index(op.f("ix_person_org_unit_id"), table_name="person")
    op.drop_table("person")
    op.drop_constraint(op.f("fk_asset_org_unit_id_org_unit"), "asset", type_="foreignkey")
    op.drop_constraint(op.f("fk_asset_location_id_location"), "asset", type_="foreignkey")
    op.drop_index(op.f("ix_asset_org_unit_id"), table_name="asset")
    op.drop_index(op.f("ix_asset_location_id"), table_name="asset")
    op.drop_column("asset", "confirmed")
    op.drop_column("asset", "in_cmdb")
    op.drop_column("asset", "location_id")
    op.drop_column("asset", "org_unit_id")
    op.drop_constraint(
        op.f("fk_network_segment_location_id_location"), "network_segment", type_="foreignkey"
    )
    op.drop_index(op.f("ix_network_segment_location_id"), table_name="network_segment")
    op.drop_column("network_segment", "location_id")
    op.drop_index(op.f("ix_org_unit_parent_id"), table_name="org_unit")
    op.drop_table("org_unit")
    op.drop_table("location")

    op.create_table(
        "iam_custom_role",
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("permissions", JSON, nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.String(length=255), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("name", name=op.f("pk_iam_custom_role")),
    )
    op.create_table(
        "iam_role_grant",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("role_name", sa.String(length=64), nullable=False),
        sa.Column("granted_by", sa.String(length=255), nullable=False),
        sa.Column("granted_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["iam_user.id"],
            name=op.f("fk_iam_role_grant_user_id_iam_user"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_iam_role_grant")),
        sa.UniqueConstraint("user_id", "role_name", name=op.f("uq_iam_role_grant_user_id_role_name")),
    )
    op.create_index(
        op.f("ix_iam_role_grant_user_id"), "iam_role_grant", ["user_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_iam_role_grant_user_id"), table_name="iam_role_grant")
    op.drop_table("iam_role_grant")
    op.drop_table("iam_custom_role")

    op.create_table(
        "location",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=False),
        sa.Column("address", sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_location")),
        sa.UniqueConstraint("external_id", name=op.f("uq_location_external_id")),
    )
    op.create_table(
        "org_unit",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=False),
        sa.Column("parent_id", sa.Uuid(), nullable=True),
        sa.ForeignKeyConstraint(
            ["parent_id"],
            ["org_unit.id"],
            name=op.f("fk_org_unit_parent_id_org_unit"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_org_unit")),
        sa.UniqueConstraint("external_id", name=op.f("uq_org_unit_external_id")),
    )
    op.create_index(op.f("ix_org_unit_parent_id"), "org_unit", ["parent_id"], unique=False)
    op.create_table(
        "person",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("full_name", sa.String(length=255), nullable=False),
        sa.Column("job_title", sa.String(length=255), nullable=True),
        sa.Column("org_unit_id", sa.Uuid(), nullable=True),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=False),
        sa.Column("pseudonym_no", sa.Integer(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("left_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "source IN ('ad', 'entra', 'mdm', 'import')", name=op.f("ck_person_source_valid")
        ),
        sa.ForeignKeyConstraint(
            ["org_unit_id"],
            ["org_unit.id"],
            name=op.f("fk_person_org_unit_id_org_unit"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_person")),
        sa.UniqueConstraint("pseudonym_no", name=op.f("uq_person_pseudonym_no")),
        sa.UniqueConstraint("source", "external_id", name=op.f("uq_person_source_external_id")),
    )
    op.create_index(op.f("ix_person_org_unit_id"), "person", ["org_unit_id"], unique=False)
    op.create_table(
        "asset_assignment",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("person_id", sa.Uuid(), nullable=False),
        sa.Column("role", sa.String(length=8), nullable=False),
        sa.Column("valid_from", sa.Date(), nullable=True),
        sa.Column("valid_to", sa.Date(), nullable=True),
        sa.CheckConstraint(
            "role IN ('user', 'owner')", name=op.f("ck_asset_assignment_role_valid")
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["asset.id"],
            name=op.f("fk_asset_assignment_asset_id_asset"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["person_id"],
            ["person.id"],
            name=op.f("fk_asset_assignment_person_id_person"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_asset_assignment")),
        sa.UniqueConstraint(
            "asset_id",
            "person_id",
            "role",
            name=op.f("uq_asset_assignment_asset_id_person_id_role"),
        ),
    )
    op.create_index(
        op.f("ix_asset_assignment_asset_id"), "asset_assignment", ["asset_id"], unique=False
    )
    op.create_index(
        op.f("ix_asset_assignment_person_id"), "asset_assignment", ["person_id"], unique=False
    )
    op.create_table(
        "coverage_snapshot",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("assets_total", sa.Integer(), nullable=False),
        sa.Column("with_owner", sa.Integer(), nullable=False),
        sa.Column("scanned_recently", sa.Integer(), nullable=False),
        sa.Column("known_version", sa.Integer(), nullable=False),
        sa.Column("unknown_devices", sa.Integer(), nullable=False),
        sa.Column("open_findings", sa.Integer(), nullable=False),
        sa.Column("critical_findings", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_coverage_snapshot")),
        sa.UniqueConstraint("day", name=op.f("uq_coverage_snapshot_day")),
    )
    op.create_table('compliance_rule',
    sa.Column('id', sa.String(length=64), nullable=False),
    sa.Column('framework', sa.String(length=20), nullable=False),
    sa.Column('mappings', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('check', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('remediation', sa.Text(), nullable=False),
    sa.Column('severity', sa.String(length=20), nullable=False),
    sa.CheckConstraint("framework IN ('CIS', 'NIS2', 'ISO27001')", name=op.f('ck_compliance_rule_framework_valid')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_compliance_rule'))
    )
    op.create_table('compliance_result',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('asset_id', sa.Uuid(), nullable=False),
    sa.Column('rule_id', sa.String(length=64), nullable=False),
    sa.Column('result', sa.String(length=8), nullable=False),
    sa.Column('evidence', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('checked_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("result IN ('pass', 'fail', 'na')", name=op.f('ck_compliance_result_result_valid')),
    sa.ForeignKeyConstraint(['asset_id'], ['asset.id'], name=op.f('fk_compliance_result_asset_id_asset'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['rule_id'], ['compliance_rule.id'], name=op.f('fk_compliance_result_rule_id_compliance_rule'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_compliance_result'))
    )
    op.create_index(
        op.f("ix_compliance_result_asset_id"), "compliance_result", ["asset_id"], unique=False
    )
    op.create_index(
        op.f("ix_compliance_result_rule_id"), "compliance_result", ["rule_id"], unique=False
    )
    op.create_table('scan_request',
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('requested_by', sa.String(length=255), nullable=False),
    sa.Column('scope_kind', sa.String(length=16), nullable=False),
    sa.Column('scope_ref', sa.Uuid(), nullable=True),
    sa.Column('scope_label', sa.String(length=255), nullable=False),
    sa.Column('reason', sa.Text(), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('decided_by', sa.String(length=255), nullable=True),
    sa.Column('decision_reason', sa.Text(), nullable=True),
    sa.Column('decided_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('scan_run_id', sa.Uuid(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint("scope_kind IN ('organization', 'unit', 'device')", name=op.f('ck_scan_request_scope_kind_valid')),
    sa.CheckConstraint("status IN ('pending', 'approved', 'rejected', 'done', 'failed')", name=op.f('ck_scan_request_status_valid')),
    sa.ForeignKeyConstraint(['scan_run_id'], ['scan_run.id'], name=op.f('fk_scan_request_scan_run_id_scan_run'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_scan_request'))
    )
    op.create_index(op.f('ix_scan_request_requested_by'), 'scan_request', ['requested_by'], unique=False)
    op.create_index(op.f('ix_scan_request_status'), 'scan_request', ['status'], unique=False)


    op.add_column("network_segment", sa.Column("location_id", sa.Uuid(), nullable=True))
    op.create_index(
        op.f("ix_network_segment_location_id"), "network_segment", ["location_id"], unique=False
    )
    op.create_foreign_key(
        op.f("fk_network_segment_location_id_location"),
        "network_segment",
        "location",
        ["location_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.add_column("asset", sa.Column("org_unit_id", sa.Uuid(), nullable=True))
    op.add_column("asset", sa.Column("location_id", sa.Uuid(), nullable=True))
    op.add_column(
        "asset", sa.Column("in_cmdb", sa.Boolean(), nullable=False, server_default=sa.false())
    )
    op.add_column(
        "asset", sa.Column("confirmed", sa.Boolean(), nullable=False, server_default=sa.false())
    )
    op.create_index(op.f("ix_asset_location_id"), "asset", ["location_id"], unique=False)
    op.create_index(op.f("ix_asset_org_unit_id"), "asset", ["org_unit_id"], unique=False)
    op.create_foreign_key(
        op.f("fk_asset_location_id_location"),
        "asset",
        "location",
        ["location_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        op.f("fk_asset_org_unit_id_org_unit"),
        "asset",
        "org_unit",
        ["org_unit_id"],
        ["id"],
        ondelete="SET NULL",
    )
