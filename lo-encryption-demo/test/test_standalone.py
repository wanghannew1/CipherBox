"""Standalone check of the pure-Python parts: CNG AES-256-CBC, PBKDF2, stream layouts.

Runs under LibreOffice's bundled python.exe but does not touch the UNO component loader.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import cipherbox as cb  # noqa: E402

FAILURES = []


def check(label, condition, detail=""):
    if condition:
        print("PASS  %s %s" % (label, detail))
    else:
        print("FAIL  %s %s" % (label, detail))
        FAILURES.append(label)


def main():
    # --- key derivation is deterministic and 32 bytes -------------------
    k1 = cb.derive_key("hunter2")
    k2 = cb.derive_key("hunter2")
    k3 = cb.derive_key("hunter3")
    check("pbkdf2 deterministic", k1 == k2, "%d bytes" % len(k1))
    check("pbkdf2 salt-sensitive", k1 != k3)
    check("key length == 32", len(k1) == 32)

    # --- CNG AES round trip over several sizes -------------------------
    for size in (0, 1, 15, 16, 17, 4096, 100000):
        plain = os.urandom(size)
        iv = os.urandom(cb.IV_LEN)
        ct = cb.aes_cbc(k1, iv, plain, encrypt=True)
        check(
            "cbc round trip %d" % size,
            cb.aes_cbc(k1, iv, ct, encrypt=False) == plain,
            "ct=%d" % len(ct),
        )
        if size:
            check("pkcs7 pads %d" % size, len(ct) % 16 == 0 and len(ct) > size)

    # --- wrong key must not round trip ---------------------------------
    plain = os.urandom(64)
    iv = os.urandom(cb.IV_LEN)
    ct = cb.aes_cbc(k1, iv, plain, encrypt=True)
    try:
        bad = cb.aes_cbc(k3, iv, ct, encrypt=False)
        check("wrong key rejected", False, "got %d bytes back" % len(bad))
    except (OSError, ValueError) as exc:
        check("wrong key rejected", True, str(exc)[:48])

    # --- stream layouts, byte-for-byte against the reference sample ----
    # Every UTF-16 string is preceded by an int32 byte-length prefix.
    def le32(value):
        return int(value).to_bytes(4, "little", signed=False)

    dsm = cb.data_space_map()
    check("DataSpaceMap length", len(dsm) == 96, "%d" % len(dsm))
    check("DataSpaceMap header length field", dsm[0:4] == le32(8))
    check("DataSpaceMap entries count", dsm[4:8] == le32(1))
    check("DataSpaceMap entry length field", dsm[8:12] == le32(0x60))
    check("DataSpaceMap references count", dsm[12:16] == le32(1))
    check("DataSpaceMap component type", dsm[16:20] == le32(0))
    check("DataSpaceMap ref name prefix", dsm[20:24] == le32(32))
    check("DataSpaceMap ref name", dsm[24:56].decode("utf-16-le") == "EncryptedPackage")
    check("DataSpaceMap space name prefix", dsm[56:60] == le32(36))
    check("DataSpaceMap space name", dsm[60:96].decode("utf-16-le") == cb.DATASPACE_NAME)

    ver = cb.version()
    check("Version length", len(ver) == 76, "%d" % len(ver))
    check("Version feature prefix", ver[0:4] == le32(60))
    check("Version feature identifier", ver[4:64].decode("utf-16-le") == cb.FEATURE_IDENTIFIER)
    check("Version writer versions", ver[64:76] == le32(1) + le32(1) + le32(1))

    dsi = cb.data_space_info()
    check("DataSpaceInfo length", len(dsi) == 48, "%d" % len(dsi))
    check("DataSpaceInfo header length", dsi[0:4] == le32(8))
    check("DataSpaceInfo entries count", dsi[4:8] == le32(1))
    check("DataSpaceInfo name prefix", dsi[8:12] == le32(36))
    check("DataSpaceInfo transform name", dsi[12:48].decode("utf-16-le") == cb.TRANSFORM_NAME)

    ti = cb.transform_info()
    guid_utf16 = cb.TRANSFORM_GUID.encode("utf-16-le")
    name_utf16 = cb.TRANSFORM_INFO_NAME.encode("utf-16-le")
    check("TransformInfo length", len(ti) == 184, "%d" % len(ti))
    check("TransformInfo TransformLength", ti[0:4] == le32(88), "got %d" % int.from_bytes(ti[0:4], "little"))
    check("TransformInfo TransformType", ti[4:8] == le32(1))
    check("TransformInfo GUID prefix", ti[8:12] == le32(len(guid_utf16)))
    check("TransformInfo GUID", ti[12 : 12 + len(guid_utf16)] == guid_utf16)
    off = 12 + len(guid_utf16)
    check("TransformInfo name prefix", ti[off : off + 4] == le32(len(name_utf16)))
    off += 4
    check("TransformInfo name", ti[off : off + len(name_utf16)] == name_utf16)
    off += len(name_utf16)
    check("TransformInfo name padding", ti[off : off + 2] == b"\x00\x00")
    off += 2
    check(
        "TransformInfo versions + extensibility",
        ti[off:] == le32(1) + le32(1) + le32(1) + le32(4),
    )

    # --- EncryptedPackage framing --------------------------------------
    header = cb._i64(1234) + b"\xAB" * 16
    check("payload header is 24 bytes", len(header) == 24)
    check("payload length prefix LE", int.from_bytes(header[0:8], "little") == 1234)

    # --- password verifier trailer -------------------------------------
    # oox decides whether a candidate password is correct solely from the boolean
    # returned by generateEncryptionKey(), so these helpers are what stop
    # "VelvetSweatshop" from always being accepted.
    salt, vhash = cb.make_verifier("hunter2")
    check("verifier salt length", len(salt) == cb.VERIFIER_SALT_LEN, "%d" % len(salt))
    check("verifier hash length", len(vhash) == cb.VERIFIER_HASH_LEN, "%d" % len(vhash))

    salt2, vhash2 = cb.make_verifier("hunter2")
    check("verifier salt is random per file", salt != salt2)
    check("verifier hash tracks salt", vhash != vhash2)

    with_v = cb.data_space_info(salt, vhash)
    check(
        "DataSpaceInfo grows by the trailer",
        len(with_v) == 48 + 4 + 4 + cb.VERIFIER_SALT_LEN + 4 + cb.VERIFIER_HASH_LEN,
        "%d" % len(with_v),
    )
    check(
        "DataSpaceInfo base is preserved",
        with_v[:48] == dsi,
    )
    got_salt, got_hash = cb._parse_verifier(with_v)
    check("verifier trailer round-trips salt", got_salt == salt)
    check("verifier trailer round-trips hash", got_hash == vhash)

    check("verifier accepts the right password", cb.verifier_matches("hunter2", salt, vhash))
    check("verifier rejects a wrong password", not cb.verifier_matches("hunter3", salt, vhash))
    check("verifier rejects the LibreOffice default probe",
          not cb.verifier_matches("VelvetSweatshop", salt, vhash))
    check("verifier rejects empty password", not cb.verifier_matches("", salt, vhash))
    check("verifier tolerates unicode passwords",
          cb.verifier_matches("pässwörd-é", *cb.make_verifier("pässwörd-é")))

    # A file written before the verifier existed has no trailer; it must stay readable
    # rather than bricking the load path.
    check("no trailer parses as no verifier", cb._parse_verifier(cb.data_space_info()) == (None, None))
    check("no verifier accepts any password (back-compat)",
          cb.verifier_matches("anything", None, None))
    for bad in (b"", b"CBPV", b"\x00" * 8, b"\xff" * 200):
        check("garbage stream %r yields no verifier" % bad[:6],
              cb._parse_verifier(bad) == (None, None))
    truncated = with_v[:-1]
    check("truncated trailer yields no verifier", cb._parse_verifier(truncated) == (None, None))

    print("")
    if FAILURES:
        print("RESULT: FAIL (%d) -> %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("RESULT: PASS (all standalone checks)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
