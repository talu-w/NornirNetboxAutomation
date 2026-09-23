"""``netbox import-device-type`` — create a NetBox device type from a Device Type Library YAML file.

Reads one YAML file in the NetBox Device Type Library format — the format used
by both the community `devicetype-library
<https://github.com/netbox-community/devicetype-library>`_ and NetBox Labs'
NDX (https://netboxlabs.com/ndx/). Same schema either way: top-level scalar
fields (``manufacturer``, ``model``, ``slug``, ``part_number``, ``u_height``,
``is_full_depth``, ``weight``/``weight_unit``, ``airflow``, ``subdevice_role``,
``comments``) plus lists of child templates (``interfaces``,
``console-ports``, ``console-server-ports``, ``power-ports``,
``power-outlets``, ``rear-ports``, ``front-ports``, ``device-bays``,
``module-bays``) whose item fields already match the NetBox
``*Template`` API field names, so they are passed straight through.

* **Manufacturer** — created if NetBox has none with the matching slug
  (derived from the YAML's manufacturer name).
* **Device type** — created if missing (by slug). If NetBox already has a
  device type with that slug, its top-level fields are **never touched** —
  same "don't clobber what's already there" rule as ``create-interfaces``.
* **Child templates** — for a device type this run creates, every template in
  the YAML is created. For a device type that already existed, only
  templates NetBox is missing (matched by name) are created; existing ones
  are left alone.
* **Cross-referencing templates** (``power-outlets`` → ``power_port``,
  ``front-ports`` → ``rear_port``) are resolved by name against the other
  templates in the same file/device type. A name that resolves to nothing is
  reported and skipped — never silently dropped or guessed.

Front/rear image files referenced by the schema (``front_image``/
``rear_image``) are not part of the YAML's data and are never uploaded —
noted, not applied.

Plans by default; ``--apply`` writes. Touches only NetBox, so
``needs_devices = False``.
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from bunnyauto.errors import ToolError
from bunnyauto.tools.base import Status, ToolResult

if TYPE_CHECKING:
    from bunnyauto.context import Context

# yaml list key -> (pynetbox endpoint attribute, cross-ref field -> referenced list key)
_CATEGORIES: tuple[tuple[str, str, tuple[str, str] | None], ...] = (
    ("console-ports", "console_port_templates", None),
    ("console-server-ports", "console_server_port_templates", None),
    ("power-ports", "power_port_templates", None),
    ("power-outlets", "power_outlet_templates", ("power_port", "power-ports")),
    ("rear-ports", "rear_port_templates", None),
    ("front-ports", "front_port_templates", ("rear_port", "rear-ports")),
    ("device-bays", "device_bay_templates", None),
    ("module-bays", "module_bay_templates", None),
    ("interfaces", "interface_templates", None),
)

_DEVICE_TYPE_SCALAR_FIELDS = (
    "part_number",
    "u_height",
    "is_full_depth",
    "subdevice_role",
    "weight",
    "weight_unit",
    "airflow",
    "comments",
)


def slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.strip().casefold()).strip("-")
    if not slug:
        raise ToolError(f"{text!r} cannot be turned into a NetBox slug")
    return slug


def load_device_type_yaml(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text()
    except OSError as exc:
        raise ToolError(f"could not read {path}: {exc}") from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ToolError(f"{path} is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ToolError(f"{path} does not look like a device-type YAML file (no top-level mapping)")

    for field_name in ("manufacturer", "model", "slug"):
        value = data.get(field_name)
        if not isinstance(value, str) or not value.strip():
            raise ToolError(f"{path} is missing required field {field_name!r}")

    for key, _endpoint, _cross_ref in _CATEGORIES:
        items = data.get(key)
        if items is None:
            continue
        if not isinstance(items, list):
            raise ToolError(f"{path}: {key!r} should be a list")
        for index, item in enumerate(items):
            if not isinstance(item, dict) or not str(item.get("name") or "").strip():
                raise ToolError(f"{path}: {key}[{index}] is missing a 'name'")
    return data


@dataclass(slots=True)
class ImportDeviceType:
    name: str = "import-device-type"
    summary: str = (
        "Create a NetBox device type (and its templates) from a Device Type Library YAML file"
    )
    writes: bool = True
    category: str = "netbox"
    needs_devices: bool = False

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "file",
            type=Path,
            help="path to the device-type YAML file (NetBox Device Type Library / NDX format)",
        )

    def run(self, ctx: Context, args: argparse.Namespace) -> ToolResult:
        path: Path = args.file
        data = load_device_type_yaml(path)
        nb = ctx.netbox()
        apply = ctx.settings.apply

        manufacturer_name = data["manufacturer"].strip()
        mfr_slug = slugify(manufacturer_name)
        model = data["model"].strip()
        dt_slug = data["slug"].strip()

        changes: list[str] = []
        blocked_total: list[str] = []
        failures: list[str] = []
        created_counts: dict[str, int] = {}

        manufacturer = nb.dcim.manufacturers.get(slug=mfr_slug)
        manufacturer_id: int | None = int(manufacturer.id) if manufacturer is not None else None
        if manufacturer is None:
            verb = "create" if apply else "would create"
            changes.append(f"{verb} manufacturer {manufacturer_name!r} (slug {mfr_slug!r})")
            if apply:
                try:
                    manufacturer = nb.dcim.manufacturers.create(
                        {"name": manufacturer_name, "slug": mfr_slug}
                    )
                    manufacturer_id = int(manufacturer.id)
                    ctx.reporter.success(f"created manufacturer {manufacturer_name!r}")
                except Exception as exc:  # pynetbox RequestError etc.
                    raise ToolError(
                        f"could not create manufacturer {manufacturer_name!r}: {exc}"
                    ) from exc

        device_type = nb.dcim.device_types.get(slug=dt_slug)
        device_type_existed = device_type is not None
        device_type_id: int | None = int(device_type.id) if device_type is not None else None

        if device_type is None:
            verb = "create" if apply else "would create"
            changes.append(
                f"{verb} device type {model!r} (slug {dt_slug!r}, "
                f"manufacturer {manufacturer_name!r})"
            )
            if apply:
                body: dict[str, Any] = {
                    "manufacturer": manufacturer_id,
                    "model": model,
                    "slug": dt_slug,
                }
                for key in _DEVICE_TYPE_SCALAR_FIELDS:
                    if key in data:
                        body[key] = data[key]
                try:
                    device_type = nb.dcim.device_types.create(body)
                    device_type_id = int(device_type.id)
                    ctx.reporter.success(f"created device type {model!r}")
                except Exception as exc:
                    raise ToolError(f"could not create device type {model!r}: {exc}") from exc
        else:
            ctx.reporter.info(
                f"device type {model!r} already exists in NetBox — leaving its fields as-is"
            )

        for image_field in ("front_image", "rear_image"):
            if data.get(image_field):
                ctx.reporter.info(
                    f"note: {path.name} references {image_field.replace('_', ' ')} — "
                    "image files are not part of this YAML and must be uploaded to NetBox manually"
                )

        # -- child templates -------------------------------------------
        name_maps: dict[str, dict[str, int]] = {}
        for category, endpoint_attr, _cross_ref in _CATEGORIES:
            endpoint = getattr(nb.dcim, endpoint_attr)
            existing_by_name: dict[str, int] = {}
            if device_type_existed and device_type_id is not None:
                for template in endpoint.filter(device_type_id=device_type_id):
                    existing_by_name[str(template.name).casefold()] = int(template.id)
            name_maps[category] = existing_by_name

        for category, endpoint_attr, cross_ref in _CATEGORIES:
            items = data.get(category) or []
            if not items:
                continue
            endpoint = getattr(nb.dcim, endpoint_attr)
            existing_by_name = name_maps[category]

            for item in items:
                item_name = str(item["name"])
                if item_name.casefold() in existing_by_name:
                    continue  # already in NetBox

                if cross_ref is not None:
                    ref_field, ref_category = cross_ref
                    ref_name = item.get(ref_field)
                    if ref_name:
                        ref_known = set(name_maps[ref_category]) | {
                            str(i["name"]).casefold() for i in (data.get(ref_category) or [])
                        }
                        if str(ref_name).casefold() not in ref_known:
                            reason = (
                                f"references unknown {ref_category[:-1]} {ref_name!r} — not "
                                f"found in this YAML file or NetBox"
                            )
                            blocked_total.append(f"{category}: {item_name!r} {reason}")
                            ctx.reporter.warn(f"{category}: {item_name!r} {reason}")
                            continue

                verb = "create" if apply else "would create"
                changes.append(f"{category}: {verb} {item_name!r}")

                if not apply:
                    continue

                body = {k: v for k, v in item.items()}
                body["device_type"] = device_type_id
                if cross_ref is not None:
                    ref_field, ref_category = cross_ref
                    ref_name = item.get(ref_field)
                    if ref_name:
                        ref_id = name_maps[ref_category].get(str(ref_name).casefold())
                        if ref_id is None:
                            reason = (
                                f"its referenced {ref_category[:-1]} {ref_name!r} was not "
                                f"created — skipping"
                            )
                            blocked_total.append(f"{category}: {item_name!r} {reason}")
                            ctx.reporter.error(f"{category}: {item_name!r} {reason}")
                            continue
                        body[ref_field] = ref_id

                try:
                    created = endpoint.create(body)
                    name_maps[category][item_name.casefold()] = int(created.id)
                    created_counts[category] = created_counts.get(category, 0) + 1
                    ctx.reporter.success(f"{category}: created {item_name!r}")
                except Exception as exc:
                    failures.append(f"{category}:{item_name}")
                    ctx.reporter.error(f"{category}: create {item_name!r} failed — {exc}")

        return _result(
            path=path,
            apply=apply,
            changes=changes,
            blocked=blocked_total,
            failures=failures,
            created_counts=created_counts,
        )


def _result(
    *,
    path: Path,
    apply: bool,
    changes: list[str],
    blocked: list[str],
    failures: list[str],
    created_counts: dict[str, int],
) -> ToolResult:
    data: dict[str, Any] = {
        "file": str(path),
        "changes": list(changes),
        "blocked": list(blocked),
        "failures": list(failures),
        "created": dict(created_counts),
    }
    total_created = sum(created_counts.values())
    progressed = bool(changes)

    if failures or blocked:
        status = Status.PARTIAL if progressed else Status.ERROR
    elif apply and changes:
        status = Status.CHANGED
    elif changes:
        status = Status.DRIFT
    else:
        status = Status.OK

    if apply:
        summary = f"{path.name}: created {total_created} object(s)"
    elif changes:
        summary = f"{path.name}: {len(changes)} object(s) to create — run with --apply"
    else:
        summary = f"{path.name}: NetBox already matches this file"
    if blocked:
        summary += f" ({len(blocked)} skipped — see notes)"
    if failures:
        summary += f" ({len(failures)} failed)"

    return ToolResult(status=status, summary=summary, changes=changes, data=data)


TOOL = ImportDeviceType()
