"""Fail-closed gate test for CipherBoxDataSpace.encrypt() (Wave 2 todo 10).

encrypt() must REFUSE to run unless the key came from a trusted provenance:
  * the CipherBoxKey NamedValue in setupEncryption(), or
  * a NON-EMPTY Password in setupEncryption(), or
  * a verifier-verified generateEncryptionKey(), or
  * a non-empty password in createEncryptionData() (oox load-path shape, kept green).

Empty/missing password -> RuntimeError, no "fake ciphertext" is ever minted.
The load/decrypt paths are unchanged: decrypt() must still work with the historical
demo-key fallback (derive_key("")) and with no key material at all.

Runs OFFLINE (no soffice needed) with the bundled python:
    "C:\\Program Files\\LibreOffice\\program\\python.exe" test_encrypt_failclosed.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.normpath(os.path.join(HERE, "..", "src"))
sys.path.insert(0, SRC)

import cipherbox as cb  # noqa: E402

T_PASSWORD = "correct horse battery staple"
WRONG_PASSWORD = "wrong password entirely"
DATA_SPACE_INFO = "\006DataSpaces/DataSpaceInfo/CipherBoxDataSpace"

FAILURES = []


def check(label, condition, detail=""):
    print("%s  %s %s" % ("PASS" if condition else "FAIL", label, detail))
    if not condition:
        FAILURES.append(label)
    return bool(condition)


class FakeInputStream:
    """Duck-typed XInputStream good enough for cipherbox._read_all()."""

    def __init__(self, data):
        self._data = bytes(data)

    def available(self):
        return len(self._data)

    def readBytes(self, holder, want):
        chunk = self._data[:want]
        self._data = self._data[want:]
        return len(chunk), chunk


class FakeOutputStream:
    """Duck-typed XOutputStream for decrypt()'s caller-provided stream branch."""

    def __init__(self):
        self.data = b""
        self.flushed = False

    def writeBytes(self, value):
        self.data += value if isinstance(value, bytes) else bytes(bytearray(value))

    def flush(self):
        self.flushed = True


class NV:
    def __init__(self, name, value):
        self.Name = name
        self.Value = value


def new_component():
    return cb.CipherBoxDataSpace(None, None)


def expect_refused(label, fn):
    try:
        fn()
    except RuntimeError as exc:
        return check("%s refused (fail-closed)" % label, True, str(exc)[:50])
    except Exception as exc:  # noqa: BLE001
        return check("%s refused (fail-closed)" % label, False,
                     "wrong exception %r" % (exc,))
    return check("%s refused (fail-closed)" % label, False, "encrypt() SUCCEEDED")


def expect_ok(label, fn):
    streams = fn()
    names = [s.Name for s in streams] if streams else None
    ok = names == [
        "\006DataSpaces/DataSpaceMap",
        "\006DataSpaces/Version",
        DATA_SPACE_INFO,
        "\006DataSpaces/TransformInfo/CipherBoxTransform/\006Primary",
        "EncryptedPackage",
    ]
    check("%s allowed (trusted key)" % label, ok, str(names)[:60])
    return {s.Name: bytes(bytearray(s.Value)) for s in streams} if ok else {}


def main():
    payload_in = FakeInputStream(b"fail-closed gate payload\x00\x01" + os.urandom(500))

    # -- 1. no key at all -> refuse -------------------------------------
    comp = new_component()
    expect_refused("encrypt() with no key ever set",
                   lambda: comp.encrypt(FakeInputStream(b"x" * 64)))

    # -- 2. setupEncryption with neither key nor password -> refuse ------
    comp = new_component()
    check("setupEncryption(CryptoType only) still returns True (load path unchanged)",
          bool(comp.setupEncryption((NV("CryptoType", "CipherBoxDataSpace"),))))
    expect_refused("encrypt() after empty setupEncryption fallback",
                   lambda: comp.encrypt(FakeInputStream(b"x" * 64)))

    # -- 3. setupEncryption with EMPTY password -> refuse -----------------
    comp = new_component()
    comp.setupEncryption((NV("CryptoType", "CipherBoxDataSpace"), NV("Password", "")))
    expect_refused("encrypt() after empty-string Password",
                   lambda: comp.encrypt(FakeInputStream(b"x" * 64)))

    # -- 4. trusted path: non-empty Password ------------------------------
    comp = new_component()
    comp.setupEncryption(
        (NV("CryptoType", "CipherBoxDataSpace"), NV("Password", T_PASSWORD)))
    streams = expect_ok("encrypt() with non-empty Password",
                        lambda: comp.encrypt(payload_in))
    check("Password path still mints a verifier",
          cb._parse_verifier(streams.get(DATA_SPACE_INFO, b"")) != (None, None))

    # -- 5. trusted path: CipherBoxKey ------------------------------------
    comp = new_component()
    comp.setupEncryption((NV("CryptoType", "CipherBoxDataSpace"),
                          NV("CipherBoxKey", cb.derive_key(T_PASSWORD))))
    expect_ok("encrypt() with CipherBoxKey", lambda: comp.encrypt(payload_in))

    # -- 6. trusted path: verifier-verified generateEncryptionKey ---------
    reader = new_component()
    check("readEncryptionInfo accepts the Password-path container",
          bool(reader.readEncryptionInfo(
              tuple(NV(name, value) for name, value in streams.items()))))
    check("wrong password still rejected by verifier",
          not bool(reader.generateEncryptionKey(WRONG_PASSWORD)))
    expect_refused("encrypt() after a REJECTED password",
                   lambda: reader.encrypt(FakeInputStream(b"x" * 64)))
    check("correct password accepted by verifier",
          bool(reader.generateEncryptionKey(T_PASSWORD)))
    expect_ok("encrypt() after verifier-verified generateEncryptionKey",
              lambda: reader.encrypt(payload_in))

    # -- 7. trusted path: createEncryptionData (oox load-path shape) ------
    comp = new_component()
    comp.createEncryptionData(T_PASSWORD)
    expect_ok("encrypt() after createEncryptionData(non-empty)",
              lambda: comp.encrypt(payload_in))
    comp = new_component()
    comp.createEncryptionData("")
    expect_refused("encrypt() after createEncryptionData(empty)",
                   lambda: comp.encrypt(FakeInputStream(b"x" * 64)))

    # -- 8. decrypt path UNCHANGED: demo-key fallback still works ---------
    # Build a payload encrypted with the historical demo key (derive_key("")) the way
    # pre-gate files were produced, then decrypt with a fresh key-less component.
    plaintext = b"legacy demo-key payload" + os.urandom(200)
    iv = os.urandom(cb.IV_LEN)
    legacy = cb._i64(len(plaintext)) + iv + cb.aes_cbc(
        cb.derive_key(""), iv, plaintext, encrypt=True)
    comp = new_component()
    out = FakeOutputStream()
    check("decrypt() with no key still succeeds (demo-key fallback, load path intact)",
          bool(comp.decrypt(FakeInputStream(legacy), out)))
    check("decrypted bytes are the original plaintext", out.data == plaintext,
          "%d bytes" % len(out.data))

    # -- 9. and a verified-key decrypt still round trips -------------------
    comp = new_component()
    comp.setupEncryption(
        (NV("CryptoType", "CipherBoxDataSpace"), NV("Password", T_PASSWORD)))
    streams = expect_ok("encrypt() for decrypt round trip",
                        lambda: comp.encrypt(FakeInputStream(plaintext)))
    payload = streams["EncryptedPackage"]
    reader = new_component()
    reader.readEncryptionInfo(
        tuple(NV(name, value) for name, value in streams.items()))
    reader.generateEncryptionKey(T_PASSWORD)
    out = FakeOutputStream()
    check("decrypt() with verified key succeeds", bool(reader.decrypt(FakeInputStream(payload), out)))
    check("round-trip plaintext byte-identical", out.data == plaintext)

    print()
    if FAILURES:
        print("RESULT: FAIL (%d) -> %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("RESULT: PASS (fail-closed gate refuses fake ciphertext; load/decrypt unchanged)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
