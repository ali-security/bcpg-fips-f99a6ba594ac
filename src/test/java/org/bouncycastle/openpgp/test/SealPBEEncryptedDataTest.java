package org.bouncycastle.openpgp.test;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPDataValidationException;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.PGPSessionKeyEncryptedData;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PGPKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.SessionKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEKeyEncryptionMethodGenerator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Password-based (SKESK) encryption round trips through PGPEncryptedDataList, PGPPBEEncryptedData,
 * PGPSymmetricKeyEncryptedData/PGPSessionKeyEncryptedData and the JcePBE* operators.
 */
public class SealPBEEncryptedDataTest
{
    private static final char[] PASS = "hello world, this is a passphrase".toCharArray();

    @BeforeClass
    public static void setUp()
    {
        SealTestUtil.installProvider();
    }

    private PBEDataDecryptorFactory pbeDecryptor(char[] pass)
        throws Exception
    {
        return new JcePBEDataDecryptorFactoryBuilder(SealTestUtil.digestProvider())
            .setProvider(SealTestUtil.PROVIDER).build(pass);
    }

    private byte[] encryptWithPassword(byte[] message, int symAlg, boolean integrity)
        throws Exception
    {
        JcePBEKeyEncryptionMethodGenerator method = new JcePBEKeyEncryptionMethodGenerator(PASS,
            SealTestUtil.digestProvider().get(HashAlgorithmTags.SHA256));
        method.setProvider(SealTestUtil.PROVIDER);
        return SealTestUtil.encrypt(message, symAlg, integrity, new PGPKeyEncryptionMethodGenerator[] { method });
    }

    @Test
    public void testIntegrityProtectedRoundTripAes256()
        throws Exception
    {
        checkRoundTrip(SymmetricKeyAlgorithmTags.AES_256, true, 1000);
    }

    @Test
    public void testIntegrityProtectedRoundTripAes128()
        throws Exception
    {
        checkRoundTrip(SymmetricKeyAlgorithmTags.AES_128, true, 1);
    }

    @Test
    public void testIntegrityProtectedRoundTripLargeMessage()
        throws Exception
    {
        // larger than the 4096-byte partial-length buffer, so the data spans several partial packets
        checkRoundTrip(SymmetricKeyAlgorithmTags.AES_192, true, 50000);
    }

    @Test
    public void testIntegrityProtectedRoundTripEmptyMessage()
        throws Exception
    {
        checkRoundTrip(SymmetricKeyAlgorithmTags.AES_256, true, 0);
    }

    private void checkRoundTrip(int symAlg, boolean integrity, int length)
        throws Exception
    {
        byte[] message = SealTestUtil.randomMessage(length);
        byte[] encrypted = encryptWithPassword(message, symAlg, integrity);

        PGPEncryptedDataList list = SealTestUtil.readEncryptedDataList(encrypted);
        assertEquals(1, list.size());
        assertFalse(list.isEmpty());
        assertEquals(integrity, list.isIntegrityProtected());

        PGPEncryptedData data = list.get(0);
        assertTrue(data instanceof PGPPBEEncryptedData);
        PGPPBEEncryptedData pbeData = (PGPPBEEncryptedData)data;
        assertEquals(integrity, pbeData.isIntegrityProtected());

        PBEDataDecryptorFactory decryptor = pbeDecryptor(PASS);
        assertEquals(symAlg, pbeData.getSymmetricAlgorithm(decryptor));

        InputStream clear = pbeData.getDataStream(decryptor);
        assertArrayEquals(message, SealTestUtil.readLiteral(clear));
        if (integrity)
        {
            assertTrue("integrity check must pass", pbeData.verify());
        }
    }

    @Test
    public void testWrongPassphraseRejected()
        throws Exception
    {
        byte[] encrypted = encryptWithPassword(SealTestUtil.randomMessage(100), SymmetricKeyAlgorithmTags.AES_256, true);
        PGPPBEEncryptedData pbeData = (PGPPBEEncryptedData)SealTestUtil.readEncryptedDataList(encrypted).get(0);

        try
        {
            pbeData.getDataStream(pbeDecryptor("not the passphrase".toCharArray()));
            fail("wrong passphrase must not decrypt");
        }
        catch (PGPDataValidationException e)
        {
            // quick check of the encrypted prefix failed
        }
    }

    @Test
    public void testTamperedCiphertextDetected()
        throws Exception
    {
        byte[] message = SealTestUtil.randomMessage(2000);
        byte[] encrypted = encryptWithPassword(message, SymmetricKeyAlgorithmTags.AES_256, true);
        // flip a bit inside the encrypted literal body (well after the packet headers)
        encrypted[encrypted.length - 500] ^= 0x01;

        PGPPBEEncryptedData pbeData = (PGPPBEEncryptedData)SealTestUtil.readEncryptedDataList(encrypted).get(0);
        try
        {
            byte[] out = SealTestUtil.readLiteral(pbeData.getDataStream(pbeDecryptor(PASS)));
            assertFalse("tampered message must not decrypt to the original", Arrays.areEqual(message, out));
            assertFalse("modification detection code must fail", pbeData.verify());
        }
        catch (PGPException e)
        {
            // detected during decryption
        }
        catch (java.io.IOException e)
        {
            // detected while parsing the decrypted stream
        }
    }

    /**
     * CVE-2026-85515: a SEIPD v1 message cut short (the enclosing packet length still claiming the dropped
     * bytes) must not pass as intact. BCPGInputStream.nextPacketTag() reads the resulting EOFException as a
     * clean end of message, so a truncation landing after a complete packet ends the packet walk early; the
     * MDC check run by verify() must then report it.
     */
    @Test
    public void testTruncatedIntegrityProtectedMessageRejected()
        throws Exception
    {
        // two literal data packets, so the stream can be cut right after a complete one
        byte[] first = SealTestUtil.randomMessage(100);
        byte[] second = SealTestUtil.randomMessage(40);

        JcePBEKeyEncryptionMethodGenerator method = new JcePBEKeyEncryptionMethodGenerator(PASS,
            SealTestUtil.digestProvider().get(HashAlgorithmTags.SHA256));
        method.setProvider(SealTestUtil.PROVIDER);
        byte[] encrypted = SealTestUtil.encryptLiterals(new byte[][] { first, second },
            SymmetricKeyAlgorithmTags.AES_256, true, new PGPKeyEncryptionMethodGenerator[] { method });

        // the intact message decrypts to both packets and passes the MDC
        PGPPBEEncryptedData pbeData = (PGPPBEEncryptedData)SealTestUtil.readEncryptedDataList(encrypted).get(0);
        List literals = readAllLiterals(pbeData.getDataStream(pbeDecryptor(PASS)));
        assertEquals(2, literals.size());
        assertArrayEquals(first, (byte[])literals.get(0));
        assertArrayEquals(second, (byte[])literals.get(1));
        assertTrue("integrity check must pass", pbeData.verify());

        // drop the MDC packet (22 octets), the second literal packet (19 octet header + 40 octets of data)
        // and some of the first
        for (int drop = 1; drop <= 22 + 59 + 16; drop++)
        {
            byte[] truncated = new byte[encrypted.length - drop];
            System.arraycopy(encrypted, 0, truncated, 0, truncated.length);

            assertTrue("truncated SEIPD v1 message accepted (drop=" + drop + ")", truncatedMessageRejected(truncated));
        }
    }

    private boolean truncatedMessageRejected(byte[] truncated)
        throws Exception
    {
        try
        {
            PGPPBEEncryptedData pbeData = (PGPPBEEncryptedData)SealTestUtil.readEncryptedDataList(truncated).get(0);
            readAllLiterals(pbeData.getDataStream(pbeDecryptor(PASS)));

            return !pbeData.verify();
        }
        catch (IOException e)
        {
            return true;
        }
        catch (PGPException e)
        {
            return true;
        }
    }

    private static List readAllLiterals(InputStream clear)
        throws Exception
    {
        JcaPGPObjectFactory factory = new JcaPGPObjectFactory(clear);

        List literals = new ArrayList();
        Object o;
        while ((o = factory.nextObject()) != null)
        {
            literals.add(Streams.readAll(((PGPLiteralData)o).getInputStream()));
        }
        return literals;
    }

    @Test
    public void testSessionKeyExtractionAndSessionKeyDecryption()
        throws Exception
    {
        byte[] message = SealTestUtil.randomMessage(777);
        byte[] encrypted = encryptWithPassword(message, SymmetricKeyAlgorithmTags.AES_256, true);

        PGPEncryptedDataList list = SealTestUtil.readEncryptedDataList(encrypted);
        PGPPBEEncryptedData pbeData = (PGPPBEEncryptedData)list.get(0);
        final PGPSessionKey sessionKey = pbeData.getSessionKey(pbeDecryptor(PASS));
        assertNotNull(sessionKey);
        assertEquals(SymmetricKeyAlgorithmTags.AES_256, sessionKey.getAlgorithm());
        assertEquals(32, sessionKey.getKey().length);

        // decrypt again, this time from the session key alone
        PGPEncryptedDataList list2 = SealTestUtil.readEncryptedDataList(encrypted);
        PGPSessionKeyEncryptedData skData = list2.extractSessionKeyEncryptedData();
        assertTrue(skData.isIntegrityProtected());

        SessionKeyDataDecryptorFactory skFactory = sessionKeyDecryptor(sessionKey);

        assertArrayEquals(message, SealTestUtil.readLiteral(skData.getDataStream(skFactory)));
        assertTrue(skData.verify());
    }

    /**
     * CVE-2026-59640: decrypting a SEIPD v1 packet from an already-recovered session key must not report
     * the legacy CFB "quick check" on the two repeated prefix bytes - an early, distinguishable
     * PGPDataValidationException("data check failed.") is the Mister-Zuccherato oracle. Integrity is
     * left to the MDC.
     */
    @Test
    public void testSessionKeyDecryptionSuppressesQuickCheckOracle()
        throws Exception
    {
        byte[] encrypted = encryptWithPassword(SealTestUtil.randomMessage(100), SymmetricKeyAlgorithmTags.AES_256, true);
        PGPSessionKey sessionKey = ((PGPPBEEncryptedData)SealTestUtil.readEncryptedDataList(encrypted).get(0))
            .getSessionKey(pbeDecryptor(PASS));

        // a WRONG session key decrypts the prefix to garbage, so the quick check bytes mismatch
        PGPSessionKeyEncryptedData skData = SealTestUtil.readEncryptedDataList(encrypted).extractSessionKeyEncryptedData();
        try
        {
            InputStream decrypted = skData.getDataStream(sessionKeyDecryptor(wrongSessionKey(sessionKey, 0)));
            // reading the (garbage) stream may fail later (MDC / parse) - that is not an early quick-check signal
            try
            {
                Streams.readAll(decrypted);
                assertFalse("wrong session key must not pass the MDC", skData.verify());
            }
            catch (IOException e)
            {
                // acceptable: a wrong key surfaces as a later failure, not an early quick-check throw
            }
        }
        catch (PGPDataValidationException e)
        {
            fail("session-key decryption must not expose the CFB quick-check oracle (early data check)");
        }
    }

    /**
     * CVE-2026-59640 exploit: an attacker able to submit modified ciphertexts to a party decrypting with
     * the (correct) session key flips bits of the encrypted CFB check bytes and watches for the early
     * "data check failed." - the Mister-Zuccherato oracle. The session-key path must give no such early
     * signal; the tampering is caught by the MDC instead.
     */
    @Test
    public void testSessionKeyDecryptionOfTamperedCheckBytesGivesNoOracle()
        throws Exception
    {
        byte[] message = SealTestUtil.randomMessage(100);
        byte[] encrypted = encryptWithPassword(message, SymmetricKeyAlgorithmTags.AES_256, true);
        PGPSessionKey sessionKey = ((PGPPBEEncryptedData)SealTestUtil.readEncryptedDataList(encrypted).get(0))
            .getSessionKey(pbeDecryptor(PASS));

        int checkBytesOffset = quickCheckBytesOffset(encrypted, sessionKey);

        // two different masks on the second check byte: at most one of them can turn the check bytes into
        // the all-zero form the quick check also accepts, so at least one is a guaranteed check failure.
        boolean reportedWhenRequested = false;
        for (int mask = 1; mask <= 2; mask++)
        {
            byte[] tampered = Arrays.clone(encrypted);
            tampered[checkBytesOffset + 1] ^= (byte)mask;

            PGPSessionKeyEncryptedData skData = SealTestUtil.readEncryptedDataList(tampered).extractSessionKeyEncryptedData();
            InputStream decrypted;
            try
            {
                decrypted = skData.getDataStream(sessionKeyDecryptor(sessionKey));
            }
            catch (PGPDataValidationException e)
            {
                fail("session-key decryption must not expose the CFB quick-check oracle on tampered check bytes");
                return;
            }

            Streams.readAll(decrypted);
            assertFalse("tampered message must fail the MDC", skData.verify());

            // the same tampering IS reported when the quick check is explicitly requested for a password
            // derived session key - the early, distinguishable signal the default path must not give.
            try
            {
                SealTestUtil.readEncryptedDataList(tampered).extractSessionKeyEncryptedData(true)
                    .getDataStream(sessionKeyDecryptor(sessionKey));
            }
            catch (PGPDataValidationException e)
            {
                assertEquals("data check failed.", e.getMessage());
                reportedWhenRequested = true;
            }
        }
        assertTrue("tampered check bytes must be detected when the quick check is requested", reportedWhenRequested);
    }

    /**
     * A SKESK packet which derives the session key from the S2K output directly (no encrypted session key, the
     * shape a single password method produces) hands back a well formed session key for any passphrase, so on
     * the SEIPD v1 packet that follows it only the CFB quick check tells a wrong passphrase from a right one.
     * Decrypting in two steps has to be able to get that back, without turning it on for a session key that
     * came from a public key operation.
     */
    @Test
    public void testPasswordDerivedSessionKeyIsQuickChecked()
        throws Exception
    {
        byte[] message = SealTestUtil.randomMessage(100);
        byte[] encrypted = encryptWithPassword(message, SymmetricKeyAlgorithmTags.AES_256, true);

        // stating the session key came from a password gets the wrong one reported, as the one step
        // PGPPBEEncryptedData path reports it. A wrong key passes the two byte check by chance with
        // probability ~2^-15, so a few wrong passphrases are tried rather than relying on a single one.
        boolean reported = false;
        for (int i = 0; i != 4 && !reported; i++)
        {
            try
            {
                openSessionKeyStream(encrypted, ("wrong passphrase " + i).toCharArray(), true);
            }
            catch (PGPDataValidationException e)
            {
                assertEquals("data check failed.", e.getMessage());
                reported = true;
            }
        }
        assertTrue("no exception on quick check of wrong password derived session key", reported);

        // the default stays as it was: no early, distinguishable failure to serve as an oracle.
        for (int i = 0; i != 4; i++)
        {
            openSessionKeyStream(encrypted, ("wrong passphrase " + i).toCharArray(), false);
        }

        // and the right passphrase still decrypts with the check in place.
        assertArrayEquals(message, SealTestUtil.readLiteral(openSessionKeyStream(encrypted, PASS, true)));
    }

    private InputStream openSessionKeyStream(byte[] encrypted, char[] passphrase, boolean passwordDerivedSessionKey)
        throws Exception
    {
        PGPEncryptedDataList list = SealTestUtil.readEncryptedDataList(encrypted);
        PGPSessionKey sessionKey = ((PGPPBEEncryptedData)list.get(0)).getSessionKey(pbeDecryptor(passphrase));

        return list.extractSessionKeyEncryptedData(passwordDerivedSessionKey)
            .getDataStream(sessionKeyDecryptor(sessionKey));
    }

    /**
     * Return the offset in the encoded message of the two encrypted CFB "quick check" bytes. The SEIPD packet
     * is the last packet, and its encrypted body is the block-size random prefix, the 2 check bytes, the
     * decrypted content and the 22-byte MDC packet.
     */
    private int quickCheckBytesOffset(byte[] encrypted, PGPSessionKey sessionKey)
        throws Exception
    {
        PGPSessionKeyEncryptedData skData = SealTestUtil.readEncryptedDataList(encrypted).extractSessionKeyEncryptedData();
        int contentLength = Streams.readAll(skData.getDataStream(sessionKeyDecryptor(sessionKey))).length;
        assertTrue(skData.verify());

        int blockSize = 16; // AES
        int offset = encrypted.length - (blockSize + 2 + contentLength + 22) + blockSize;
        assertTrue(offset > 0);
        return offset;
    }

    private static PGPSessionKey wrongSessionKey(PGPSessionKey sessionKey, int index)
    {
        byte[] key = Arrays.clone(sessionKey.getKey());
        key[index] ^= 0x01;
        return new PGPSessionKey(sessionKey.getAlgorithm(), key);
    }

    private SessionKeyDataDecryptorFactory sessionKeyDecryptor(final PGPSessionKey sessionKey)
        throws Exception
    {
        final PBEDataDecryptorFactory delegate = pbeDecryptor(new char[0]);
        return new SessionKeyDataDecryptorFactory()
        {
            public PGPSessionKey getSessionKey()
            {
                return sessionKey;
            }

            public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key)
                throws PGPException
            {
                return delegate.createDataDecryptor(withIntegrityPacket, encAlgorithm, key);
            }

            public PGPDataDecryptor createDataDecryptor(int aeadAlgorithm, byte[] iv, int chunkSize, int encAlgorithm, byte[] key)
                throws PGPException
            {
                return delegate.createDataDecryptor(aeadAlgorithm, iv, chunkSize, encAlgorithm, key);
            }
        };
    }

    @Test
    public void testMultiplePasswordsEitherDecrypts()
        throws Exception
    {
        byte[] message = SealTestUtil.randomMessage(300);
        char[] otherPass = "second passphrase".toCharArray();
        JcePBEKeyEncryptionMethodGenerator m1 = new JcePBEKeyEncryptionMethodGenerator(PASS);
        m1.setProvider(SealTestUtil.PROVIDER);
        JcePBEKeyEncryptionMethodGenerator m2 = new JcePBEKeyEncryptionMethodGenerator(otherPass);
        m2.setProvider(SealTestUtil.PROVIDER);
        byte[] encrypted = SealTestUtil.encrypt(message, SymmetricKeyAlgorithmTags.AES_128, true,
            new PGPKeyEncryptionMethodGenerator[] { m1, m2 });

        PGPEncryptedDataList list = SealTestUtil.readEncryptedDataList(encrypted);
        assertEquals(2, list.size());

        PGPPBEEncryptedData second = (PGPPBEEncryptedData)list.get(1);
        assertArrayEquals(message, SealTestUtil.readLiteral(second.getDataStream(pbeDecryptor(otherPass))));
        assertTrue(second.verify());

        PGPPBEEncryptedData first = (PGPPBEEncryptedData)SealTestUtil.readEncryptedDataList(encrypted).get(0);
        assertArrayEquals(message, SealTestUtil.readLiteral(first.getDataStream(pbeDecryptor(PASS))));
        assertTrue(first.verify());
    }
}
