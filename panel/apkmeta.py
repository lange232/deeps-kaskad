#!/usr/bin/env python3
"""Read the package metadata of an Android APK without external tools.

`aapt` and `apkanalyzer` are not installed on the panel hosts, and the APK is
the only thing the deploy actually has. AndroidManifest.xml inside an APK is
binary XML, so this module parses the small part of it that names the app:
package, versionCode, versionName and minSdk.

CLI:
    apkmeta.py app.apk > app.json
"""
from __future__ import annotations

import hashlib
import json
import struct
import sys
import zipfile
from pathlib import Path

RES_XML = 0x0003
RES_STRING_POOL = 0x0001
RES_XML_RESOURCE_MAP = 0x0180
RES_XML_START_ELEMENT = 0x0102

TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

# android:versionCode, android:versionName, android:minSdkVersion
ATTR_VERSION_CODE = 0x0101021B
ATTR_VERSION_NAME = 0x0101021C
ATTR_MIN_SDK = 0x0101020C


class ApkError(ValueError):
    """The file is not an APK this parser understands."""


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _length8(data: bytes, offset: int) -> tuple[int, int]:
    """UTF-8 pool length: one byte, or two when the high bit is set."""
    first = data[offset]
    if first & 0x80:
        return ((first & 0x7F) << 8) | data[offset + 1], 2
    return first, 1


def _length16(data: bytes, offset: int) -> tuple[int, int]:
    first = _u16(data, offset)
    if first & 0x8000:
        return ((first & 0x7FFF) << 16) | _u16(data, offset + 2), 4
    return first, 2


def _string_pool(chunk: bytes) -> list[str]:
    count = _u32(chunk, 8)
    flags = _u32(chunk, 16)
    start = _u32(chunk, 20)
    header = _u16(chunk, 2)
    utf8 = bool(flags & 0x0100)
    pool = []
    for index in range(count):
        offset = start + _u32(chunk, header + index * 4)
        if utf8:
            _, used = _length8(chunk, offset)
            size, used2 = _length8(chunk, offset + used)
            begin = offset + used + used2
            pool.append(chunk[begin:begin + size].decode("utf-8", "replace"))
        else:
            size, used = _length16(chunk, offset)
            begin = offset + used
            pool.append(chunk[begin:begin + size * 2].decode("utf-16-le", "replace"))
    return pool


def _typed_value(pool: list[str], data_type: int, data: int, raw: int):
    if data_type == TYPE_STRING:
        return pool[data] if data < len(pool) else None
    if data_type in (TYPE_INT_DEC, TYPE_INT_HEX):
        return struct.unpack("<i", struct.pack("<I", data))[0]
    if data_type == TYPE_INT_BOOLEAN:
        return bool(data)
    if raw != 0xFFFFFFFF and raw < len(pool):
        return pool[raw]
    return None


def _start_element(chunk: bytes, pool: list[str], resource_map: list[int]):
    header = _u16(chunk, 2)
    name_index = _u32(chunk, header + 4)
    name = pool[name_index] if name_index < len(pool) else ""
    attribute_start = _u16(chunk, header + 8)
    attribute_size = _u16(chunk, header + 10)
    attribute_count = _u16(chunk, header + 12)
    attributes = {}
    for index in range(attribute_count):
        offset = header + attribute_start + index * attribute_size
        attr_name_index = _u32(chunk, offset + 4)
        raw = _u32(chunk, offset + 8)
        data_type = chunk[offset + 15]
        data = _u32(chunk, offset + 16)
        attr_name = pool[attr_name_index] if attr_name_index < len(pool) else ""
        resource_id = (resource_map[attr_name_index]
                       if attr_name_index < len(resource_map) else 0)
        value = _typed_value(pool, data_type, data, raw)
        attributes[attr_name] = value
        if resource_id:
            attributes[resource_id] = value
    return name, attributes


def manifest_elements(data: bytes):
    """Yield (element name, attributes) for each start element in the XML."""
    if _u16(data, 0) != RES_XML:
        raise ApkError("AndroidManifest.xml is not binary XML")
    end = min(_u32(data, 4), len(data))
    position = _u16(data, 2)
    pool: list[str] = []
    resource_map: list[int] = []
    while position + 8 <= end:
        chunk_type = _u16(data, position)
        chunk_size = _u32(data, position + 4)
        if chunk_size <= 0:
            break
        chunk = data[position:position + chunk_size]
        if chunk_type == RES_STRING_POOL:
            pool = _string_pool(chunk)
        elif chunk_type == RES_XML_RESOURCE_MAP:
            resource_map = [_u32(chunk, 8 + i * 4)
                            for i in range((chunk_size - 8) // 4)]
        elif chunk_type == RES_XML_START_ELEMENT:
            yield _start_element(chunk, pool, resource_map)
        position += chunk_size


def read_meta(path: Path) -> dict:
    """Package metadata plus the digest of the file itself."""
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
            size += len(block)
    try:
        with zipfile.ZipFile(path) as apk:
            manifest = apk.read("AndroidManifest.xml")
    except zipfile.BadZipFile as exc:
        raise ApkError("the file is not a zip archive") from exc
    except KeyError as exc:
        raise ApkError("the APK has no AndroidManifest.xml") from exc
    root = None
    min_sdk = None
    for name, attributes in manifest_elements(manifest):
        if name == "manifest" and root is None:
            root = attributes
        elif name == "uses-sdk" and min_sdk is None:
            min_sdk = attributes.get(ATTR_MIN_SDK, attributes.get("minSdkVersion"))
    if root is None:
        raise ApkError("AndroidManifest.xml has no <manifest> element")
    package = root.get("package")
    version_code = root.get(ATTR_VERSION_CODE, root.get("versionCode"))
    version_name = root.get(ATTR_VERSION_NAME, root.get("versionName"))
    if not package or version_code is None or version_name is None:
        raise ApkError("the manifest has no package, versionCode or versionName")
    meta = {
        "package": str(package),
        "versionCode": int(version_code),
        "versionName": str(version_name),
        "sha256": digest.hexdigest(),
        "size": size,
    }
    if min_sdk is not None:
        meta["minSdk"] = int(min_sdk)
    return meta


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: apkmeta.py <app.apk>", file=sys.stderr)
        return 2
    try:
        meta = read_meta(Path(argv[1]))
    except (OSError, ApkError, zipfile.BadZipFile) as exc:
        print(f"apkmeta: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(meta, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
