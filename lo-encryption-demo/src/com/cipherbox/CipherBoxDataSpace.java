package com.cipherbox;

import com.sun.star.beans.NamedValue;
import com.sun.star.io.SequenceInputStream;
import com.sun.star.io.SequenceOutputStream;
import com.sun.star.io.XInputStream;
import com.sun.star.io.XOutputStream;
import com.sun.star.lang.XInitialization;
import com.sun.star.lang.XServiceInfo;
import com.sun.star.lang.XSingleServiceFactory;
import com.sun.star.packages.XPackageEncryption;
import com.sun.star.uno.XComponentContext;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

/**
 * Custom LibreOffice {@code XPackageEncryption} provider.
 *
 * <p>Registered as service {@code com.sun.star.comp.oox.crypto.CipherBoxDataSpace}; oox resolves
 * that name by prepending {@code com.sun.star.comp.oox.crypto.} to the {@code CryptoType} value
 * returned from {@link #createEncryptionData(String)}.
 *
 * <p>The MS-OFFCRYPTO container layout is reproduced byte-for-byte from the reference sample
 * (bzzzil/lo_custom_encryption); only the payload cipher is upgraded from XOR to AES-256-CBC.
 */
public final class CipherBoxDataSpace
        implements XPackageEncryption, XServiceInfo, XInitialization {

    public static final String SERVICE_NAME = "com.sun.star.comp.oox.crypto.CipherBoxDataSpace";
    public static final String IMPL_NAME = "com.sun.star.comp.oox.crypto.IMPL.CipherBoxDataSpace";

    static final String CRYPTO_TYPE = "CipherBoxDataSpace";
    static final String DATASPACE_NAME = "CipherBoxDataSpace";
    static final String TRANSFORM_NAME = "CipherBoxTransform";

    private static final String TRANSFORM_GUID = "{C73DFACD-061F-43B0-8B64-AC620D2A8B50}";
    private static final String TRANSFORM_INFO_NAME = "Microsoft.Metadata.CipherBoxTransform";
    private static final String FEATURE_IDENTIFIER = "Microsoft.Container.DataSpaces";
    private static final String REFERENCE_COMPONENT = "EncryptedPackage";

    private static final String NV_CRYPTO_TYPE = "CryptoType";
    private static final String NV_KEY = "CipherBoxKey";

    private static final String STREAM_DATASPACEMAP = "\006DataSpaces/DataSpaceMap";
    private static final String STREAM_VERSION = "\006DataSpaces/Version";
    private static final String STREAM_DATASPACEINFO = "\006DataSpaces/DataSpaceInfo/" + DATASPACE_NAME;
    private static final String STREAM_TRANSFORMINFO =
            "\006DataSpaces/TransformInfo/" + TRANSFORM_NAME + "/\006Primary";
    private static final String STREAM_ENCRYPTEDPACKAGE = "EncryptedPackage";

    private static final int IV_LEN = 16;
    private static final int PBKDF2_ITERATIONS = 20000;
    private static final byte[] PBKDF2_SALT = "CipherBoxDataSpace-v1".getBytes(StandardCharsets.UTF_8);

    private static final Logger LOG = Logger.getLogger("CipherBoxDataSpace");

    static {
        try {
            FileHandler fh = new FileHandler(
                    System.getProperty("java.io.tmpdir") + "/cipherbox-encryption.log", true);
            fh.setFormatter(new SimpleFormatter());
            fh.setLevel(Level.ALL);
            LOG.addHandler(fh);
            LOG.setLevel(Level.ALL);
            LOG.setUseParentHandlers(false);
        } catch (Exception ignored) {
            // logging is best-effort only
        }
    }

    private XComponentContext ctx;
    private SecretKey key;

    public CipherBoxDataSpace(XComponentContext context) {
        this.ctx = context;
        log("instance created, context=" + (context != null));
    }

    // ------------------------------------------------------------------
    // XInitialization
    // ------------------------------------------------------------------

    @Override
    public void initialize(Object[] args) {
        // oox passes no meaningful arguments here.
        if (args != null && args.length > 0 && args[0] instanceof XComponentContext) {
            this.ctx = (XComponentContext) args[0];
        }
    }

    // ------------------------------------------------------------------
    // XServiceInfo
    // ------------------------------------------------------------------

    @Override
    public String getImplementationName() {
        return IMPL_NAME;
    }

    @Override
    public boolean supportsService(String serviceName) {
        return SERVICE_NAME.equals(serviceName);
    }

    @Override
    public String[] getSupportedServiceNames() {
        return new String[] { SERVICE_NAME };
    }

    // ------------------------------------------------------------------
    // XPackageEncryption
    // ------------------------------------------------------------------

    @Override
    public NamedValue[] createEncryptionData(String password) {
        log("createEncryptionData(password=" + (password == null ? "null" : mask(password)) + ")");
        this.key = deriveKey(password == null ? "" : password);
        return new NamedValue[] {
                new NamedValue(NV_CRYPTO_TYPE, CRYPTO_TYPE),
                new NamedValue(NV_KEY, this.key.getEncoded()),
        };
    }

    @Override
    public boolean setupEncryption(NamedValue[] mediaEncData) {
        log("setupEncryption(names=" + names(mediaEncData) + ")");
        if (mediaEncData != null) {
            for (NamedValue nv : mediaEncData) {
                if (NV_KEY.equals(nv.Name) && nv.Value instanceof byte[]) {
                    this.key = new SecretKeySpec((byte[]) nv.Value, "AES");
                    log("key recovered from media encryption data (" + ((byte[]) nv.Value).length + " bytes)");
                    return true;
                }
            }
        }
        log("WARN: no " + NV_KEY + " in media encryption data; falling back to fixed demo key");
        this.key = deriveKey("");
        return true;
    }

    @Override
    public NamedValue[] encrypt(XInputStream xInputStream) {
        byte[] plain = readAll(xInputStream);
        log("encrypt(): plaintext " + plain.length + " bytes, key=" + describeKey());

        byte[] payload = encryptPayload(plain);

        NamedValue[] streams = new NamedValue[5];
        streams[0] = new NamedValue(STREAM_DATASPACEMAP, dataSpaceMap());
        streams[1] = new NamedValue(STREAM_VERSION, version());
        streams[2] = new NamedValue(STREAM_DATASPACEINFO, dataSpaceInfo());
        streams[3] = new NamedValue(STREAM_TRANSFORMINFO, transformInfo());
        streams[4] = new NamedValue(STREAM_ENCRYPTEDPACKAGE, payload);

        log("encrypt(): returning 5 streams, EncryptedPackage " + payload.length + " bytes");
        return streams;
    }

    @Override
    public boolean decrypt(XInputStream xInputStream, XOutputStream[] outStream) {
        try {
            byte[] container = readAll(xInputStream);
            if (container.length < 8 + IV_LEN) {
                log("decrypt(): container too short (" + container.length + " bytes)");
                return false;
            }
            long plainLength = LE.readI64(container, 0);
            byte[] iv = Arrays.copyOfRange(container, 8, 8 + IV_LEN);
            byte[] cipherText = Arrays.copyOfRange(container, 8 + IV_LEN, container.length);

            byte[] plain = decryptPayload(iv, cipherText);
            log("decrypt(): cipherText " + cipherText.length + " -> plaintext " + plain.length
                    + " bytes (declared " + plainLength + "), key=" + describeKey());

            XOutputStream target = createSequenceOutputStream();
            target.writeBytes(plain);
            target.flush();
            outStream[0] = target;
            return true;
        } catch (Exception e) {
            log("decrypt(): FAILED " + e);
            e.printStackTrace();
            return false;
        }
    }

    @Override
    public boolean readEncryptionInfo(NamedValue[] streams) {
        log("readEncryptionInfo(names=" + names(streams) + ")");
        return true;
    }

    @Override
    public boolean generateEncryptionKey(String password) {
        log("generateEncryptionKey(password=" + mask(password) + ")");
        this.key = deriveKey(password == null ? "" : password);
        return true;
    }

    @Override
    public boolean checkDataIntegrity() {
        log("checkDataIntegrity()");
        return true;
    }

    // ------------------------------------------------------------------
    // Crypto
    // ------------------------------------------------------------------

    private byte[] encryptPayload(byte[] plain) {
        try {
            byte[] iv = new byte[IV_LEN];
            new java.security.SecureRandom().nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, requireKey(), new IvParameterSpec(iv));
            byte[] cipherText = cipher.doFinal(plain);

            ByteArrayOutputStream out = new ByteArrayOutputStream(8 + IV_LEN + cipherText.length);
            LE.i64(out, plain.length);
            out.write(iv, 0, IV_LEN);
            out.write(cipherText, 0, cipherText.length);
            return out.toByteArray();
        } catch (Exception e) {
            throw new IllegalStateException("AES-256-CBC encryption failed", e);
        }
    }

    private byte[] decryptPayload(byte[] iv, byte[] cipherText) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, requireKey(), new IvParameterSpec(iv));
        return cipher.doFinal(cipherText);
    }

    private SecretKey requireKey() {
        if (key == null) {
            log("WARN: no key available, using fixed demo key");
            key = deriveKey("");
        }
        return key;
    }

    private static SecretKey deriveKey(String password) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            SecretKey derived = factory.generateSecret(
                    new PBEKeySpec(password.toCharArray(), PBKDF2_SALT, PBKDF2_ITERATIONS, 256));
            return new SecretKeySpec(derived.getEncoded(), "AES");
        } catch (Exception e) {
            throw new IllegalStateException("PBKDF2 key derivation failed", e);
        }
    }

    // ------------------------------------------------------------------
    // MS-OFFCRYPTO DataSpaces container streams (mirrors reference sample)
    // ------------------------------------------------------------------

    /** {@code \006DataSpaces/DataSpaceMap} */
    private static byte[] dataSpaceMap() {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        LE.i32(o, 8);        // header length
        LE.i32(o, 1);        // entry count
        LE.i32(o, 0x60);     // entry length
        LE.i32(o, 1);        // reference count
        LE.i32(o, 0);        // reference component type
        LE.utf16(o, REFERENCE_COMPONENT);
        LE.utf16(o, DATASPACE_NAME);
        return o.toByteArray();
    }

    /** {@code \006DataSpaces/Version} */
    private static byte[] version() {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        LE.utf16(o, FEATURE_IDENTIFIER);
        LE.i32(o, 1);        // reader version
        LE.i32(o, 1);        // updater version
        LE.i32(o, 1);        // writer version
        return o.toByteArray();
    }

    /** {@code \006DataSpaces/DataSpaceInfo/<DataSpaceName>} */
    private static byte[] dataSpaceInfo() {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        LE.i32(o, 8);        // header length
        LE.i32(o, 1);        // entry count
        LE.utf16(o, TRANSFORM_NAME);
        return o.toByteArray();
    }

    /** {@code \006DataSpaces/TransformInfo/<TransformName>/\006Primary} */
    private static byte[] transformInfo() {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        int idLen = TRANSFORM_GUID.length() * 2;
        int idPad = (4 - (TRANSFORM_GUID.length() & 3)) & 3;

        // MS-OFFCRYPTO 2.1.8 TransformInfoHeader
        LE.i32(o, idLen + idPad + 10);   // TransformLength
        LE.i32(o, 1);                    // TransformType
        LE.utf16(o, TRANSFORM_GUID);
        LE.utf16(o, TRANSFORM_INFO_NAME);
        LE.i32(o, 1);                    // ReaderVersion
        LE.i32(o, 1);                    // UpdateVersion
        LE.i32(o, 1);                    // WriterVersion
        LE.i32(o, 4);                    // ExtensibilityHeader
        return o.toByteArray();
    }

    // ------------------------------------------------------------------
    // UNO stream helpers
    // ------------------------------------------------------------------

    private XOutputStream createSequenceOutputStream() throws Exception {
        if (ctx == null) {
            throw new IllegalStateException("no XComponentContext available");
        }
        return (XOutputStream) ctx.getServiceManager()
                .createInstanceWithContext("com.sun.star.io.SequenceOutputStream", ctx);
    }

    private static XInputStream createSequenceInputStream(XComponentContext context, byte[] data)
            throws Exception {
        return (XInputStream) SequenceInputStream.createStreamFromSequence(context, data);
    }

    /**
     * Reads an {@link XInputStream} fully. {@code readBytes} takes a boxed out-parameter, so the
     * buffer is handed over in a one-element holder and read back after the call.
     */
    private static byte[] readAll(XInputStream in) {
        int size;
        try {
            size = in.available();
        } catch (Exception e) {
            size = 0;
        }
        if (size <= 0) {
            return new byte[0];
        }
        ByteArrayOutputStream bos = new ByteArrayOutputStream(size);
        int total = 0;
        while (total < size) {
            int want = Math.min(64 * 1024, size - total);
            byte[][] holder = new byte[][] { new byte[want] };
            int n;
            try {
                n = in.readBytes(holder, want);
            } catch (Exception e) {
                break;
            }
            if (n <= 0) {
                break;
            }
            bos.write(holder[0], 0, n);
            total += n;
        }
        return bos.toByteArray();
    }

    // ------------------------------------------------------------------
    // JURT Java component loader entry points
    // ------------------------------------------------------------------

    /** Required by {@code com.sun.star.loader.Java2} to obtain the component factory. */
    public static XSingleServiceFactory __getComponentFactory(String implementationName) {
        log("__getComponentFactory(\"" + implementationName + "\")");
        return new ComponentFactory();
    }

    private static final class ComponentFactory implements XSingleServiceFactory {
        @Override
        public Object createInstance() throws com.sun.star.uno.Exception {
            return new CipherBoxDataSpace(null);
        }

        @Override
        public Object createInstanceWithArguments(Object[] args) throws com.sun.star.uno.Exception {
            XComponentContext context = null;
            if (args != null) {
                for (Object a : args) {
                    if (a instanceof XComponentContext) {
                        context = (XComponentContext) a;
                        break;
                    }
                }
            }
            return new CipherBoxDataSpace(context);
        }
    }

    // ------------------------------------------------------------------
    // Small helpers
    // ------------------------------------------------------------------

    /** Little-endian binary writer, matching LibreOffice's BinaryXOutputStream semantics. */
    private static final class LE {
        static void i32(ByteArrayOutputStream o, int v) {
            o.write(v & 0xFF);
            o.write((v >>> 8) & 0xFF);
            o.write((v >>> 16) & 0xFF);
            o.write((v >>> 24) & 0xFF);
        }

        static void i64(ByteArrayOutputStream o, long v) {
            for (int i = 0; i < 8; i++) {
                o.write((int) ((v >>> (8 * i)) & 0xFF));
            }
        }

        /** UTF-16LE string padded to a 4-byte boundary. */
        static void utf16(ByteArrayOutputStream o, String s) {
            byte[] b = s.getBytes(StandardCharsets.UTF_16LE);
            o.write(b, 0, b.length);
            int pad = (4 - (b.length & 3)) & 3;
            for (int i = 0; i < pad; i++) {
                o.write(0);
            }
        }

        static long readI64(byte[] d, int off) {
            long v = 0;
            for (int i = 7; i >= 0; i--) {
                v = (v << 8) | (d[off + i] & 0xFFL);
            }
            return v;
        }
    }

    private static String names(NamedValue[] a) {
        if (a == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < a.length; i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(a[i].Name);
        }
        return sb.append("]").toString();
    }

    private static String mask(String s) {
        if (s == null) {
            return "";
        }
        return s.isEmpty() ? "(empty)" : "***len=" + s.length() + "***";
    }

    private String describeKey() {
        return key == null ? "none" : "AES/" + (key.getEncoded().length * 8) + "bits";
    }

    private static void log(String msg) {
        LOG.info(msg);
        System.out.println("[CipherBoxDataSpace] " + msg);
    }
}
