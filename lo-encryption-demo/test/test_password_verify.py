"""Password-verification test for CipherBoxDataSpace.

This is the test that pins down the fix for the "any password works" bug.

oox decides whether a candidate password is correct from one thing only: the boolean
returned by XPackageEncryption::generateEncryptionKey().  In
oox/source/core/filterdetect.cxx, PasswordVerifier::verifyPassword() looks like:

    if (mDecryptor.generateEncryptionKey(rPassword))
        rEncryptionData = mDecryptor.createEncryptionData(rPassword);
    return rEncryptionData.hasElements() ? OK : WrongPassword;

Because the component used to return a hardcoded true, every candidate matched, so
LibreOffice's built-in "VelvetSweatshop" default probe always won and the password the
user actually typed was never consulted.

test_e2e.py cannot catch this: it goes through createEncryptionData()/setupEncryption() with
a CipherBoxKey, which is the *no-password* route and mints no verifier.  This test instead
uses the route real oox uses on save -- setupEncryption() with a Password NamedValue.

Runs against a live soffice (see start_soffice.ps1).
"""

import hashlib
import os
import sys
import time

import uno
from com.sun.star.connection import NoConnectException

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.normpath(os.path.join(HERE, "..", "src", "cipherbox.py"))
DEPLOYED = os.path.join(
    os.environ.get("APPDATA", ""),
    "LibreOffice", "4", "user", "Scripts", "python", "cipherbox.py",
)

SERVICE = "com.sun.star.comp.oox.crypto.CipherBoxDataSpace"
URL = "uno:socket,host=127.0.0.1,port=2002;urp;StarOffice.ComponentContext"

T_PASSWORD = "correct horse battery staple"
# LibreOffice always tries this built-in default *before* consulting the media descriptor
# password (FilterDetect::extractUnencryptedPackage), so it is the probe that must fail.
VELVET = "VelvetSweatshop"

DATA_SPACE_INFO = "\006DataSpaces/DataSpaceInfo/CipherBoxDataSpace"
BASE_DATA_SPACE_INFO_LEN = 48

FAILURES = []


def check(label, condition, detail=""):
    if condition:
        print("PASS  %s %s" % (label, detail))
    else:
        print("FAIL  %s %s" % (label, detail))
        FAILURES.append(label)
    return bool(condition)


def connect(timeout=60):
    local = uno.getComponentContext()
    resolver = local.ServiceManager.createInstanceWithContext(
        "com.sun.star.bridge.UnoUrlResolver", local)
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            return resolver.resolve(URL)
        except NoConnectException as exc:
            last = exc
            time.sleep(1)
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(1)
    raise SystemExit("could not connect to soffice: %s" % last)


def as_bytes(value):
    if isinstance(value, bytes):
        return value
    return bytes(bytearray(value))


def as_input_stream(ctx, data):
    return ctx.ServiceManager.createInstanceWithArgumentsAndContext(
        "com.sun.star.io.SequenceInputStream", (uno.ByteSequence(data),), ctx)


def named(name, value):
    nv = uno.createUnoStruct("com.sun.star.beans.NamedValue")
    nv.Name = name
    nv.Value = value
    return nv


def sha256(path):
    try:
        with open(path, "rb") as handle:
            return hashlib.sha256(handle.read()).hexdigest()
    except OSError:
        return None


def main():
    # -- 0. the module under test is what we think it is -----------------
    if not check("deployed component exists", os.path.isfile(DEPLOYED), DEPLOYED):
        return 1
    if not check("deployed component matches src", sha256(DEPLOYED) == sha256(SRC)):
        print("       deployed %s" % sha256(DEPLOYED))
        print("       src      %s" % sha256(SRC))
        return 1

    sys.path.insert(0, os.path.dirname(SRC))
    import cipherbox as cb  # noqa: E402

    ctx = connect()
    smgr = ctx.ServiceManager
    print("connected\n")

    def new_component():
        return smgr.createInstanceWithContext(SERVICE, ctx).queryInterface(
            uno.getTypeByName("com.sun.star.packages.XPackageEncryption"))

    # -- 1. save the way oox does: setupEncryption with a Password -------
    writer = new_component()
    if not check("writer instantiated", writer is not None):
        return 1
    writer.setupEncryption((
        named("CryptoType", "CipherBoxDataSpace"),
        named("Password", T_PASSWORD),
    ))

    plaintext = b"password-verification payload\x00\x01\x02" + os.urandom(2000)
    streams = writer.encrypt(as_input_stream(ctx, plaintext))
    if not check("encrypt() returns 5 streams", streams is not None and len(streams) == 5,
                 "%d" % (len(streams) if streams else -1)):
        return 1
    payloads = {s.Name: as_bytes(s.Value) for s in streams}

    # -- 2. the verifier must actually be in the file --------------------
    dsi = payloads[DATA_SPACE_INFO]
    expected_len = BASE_DATA_SPACE_INFO_LEN + cb.VERIFIER_TRAILER_LEN
    check("DataSpaceInfo carries the verifier trailer", len(dsi) == expected_len,
          "%d bytes (expected %d)" % (len(dsi), expected_len))
    check("DataSpaceInfo base is untouched",
          dsi[:BASE_DATA_SPACE_INFO_LEN] == cb.data_space_info())

    salt, digest = cb._parse_verifier(dsi)
    if not check("verifier parses back out of the stream", salt is not None):
        return 1
    check("verifier salt length", len(salt) == cb.VERIFIER_SALT_LEN, "%d" % len(salt))
    check("verifier hash length", len(digest) == cb.VERIFIER_HASH_LEN, "%d" % len(digest))
    check("verifier matches the password used on save",
          cb.verifier_matches(T_PASSWORD, salt, digest))
    check("verifier rejects the LibreOffice default probe",
          not cb.verifier_matches(VELVET, salt, digest))
    print()

    # -- 3. reload: a fresh component must reject the wrong passwords ----
    reader = new_component()
    if not check("reader instantiated", reader is not None):
        return 1
    check("readEncryptionInfo() succeeds", bool(reader.readEncryptionInfo(streams)))
    check("checkDataIntegrity() is false before a key is verified",
          not bool(reader.checkDataIntegrity()))

    # This is the assertion that used to fail the other way round.
    check("generateEncryptionKey() REJECTS '%s'" % VELVET,
          not bool(reader.generateEncryptionKey(VELVET)))
    check("generateEncryptionKey() rejects an empty password",
          not bool(reader.generateEncryptionKey("")))
    check("generateEncryptionKey() rejects a near-miss password",
          not bool(reader.generateEncryptionKey(T_PASSWORD + "!")))
    check("generateEncryptionKey() rejects a case-changed password",
          not bool(reader.generateEncryptionKey(T_PASSWORD.upper())))
    check("checkDataIntegrity() still false after wrong passwords",
          not bool(reader.checkDataIntegrity()))

    check("generateEncryptionKey() ACCEPTS the real password",
          bool(reader.generateEncryptionKey(T_PASSWORD)))
    check("checkDataIntegrity() true after the correct password",
          bool(reader.checkDataIntegrity()))
    print()

    # -- 4. and the file still decrypts with the accepted key -------------
    result = reader.decrypt(as_input_stream(ctx, payloads["EncryptedPackage"]), ())
    ok = result[0] if isinstance(result, tuple) else result
    check("decrypt() succeeds with the verified key", bool(ok), str(result)[:50])
    print()

    # -- 5. back-compat: a file with no verifier still loads --------------
    legacy = new_component()
    legacy.setupEncryption((named("CryptoType", "CipherBoxDataSpace"),
                            named("CipherBoxKey", uno.ByteSequence(cb.derive_key("")))))
    legacy_streams = legacy.encrypt(as_input_stream(ctx, b"legacy"))
    legacy_dsi = {s.Name: as_bytes(s.Value) for s in legacy_streams}[DATA_SPACE_INFO]
    check("no-verifier file has a plain DataSpaceInfo",
          len(legacy_dsi) == BASE_DATA_SPACE_INFO_LEN, "%d bytes" % len(legacy_dsi))
    check("no-verifier file parses to no verifier",
          cb._parse_verifier(legacy_dsi) == (None, None))
    legacy_reader = new_component()
    legacy_reader.readEncryptionInfo(legacy_streams)
    check("no-verifier file still accepts any password (back-compat)",
          bool(legacy_reader.generateEncryptionKey("whatever")))
    print()

    if FAILURES:
        print("RESULT: FAIL (%d) -> %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("RESULT: PASS (password verification rejects wrong passwords)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
