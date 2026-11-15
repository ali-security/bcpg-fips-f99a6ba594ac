package org.bouncycastle.openpgp.test;

import java.io.InputStream;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPDataValidationException;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.PGPSessionKeyEncryptedData;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PGPKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.SessionKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEKeyEncryptionMethodGenerator;
import org.bouncycastle.util.Arrays;
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

        final PBEDataDecryptorFactory delegate = pbeDecryptor(new char[0]);
        SessionKeyDataDecryptorFactory skFactory = new SessionKeyDataDecryptorFactory()
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

        assertArrayEquals(message, SealTestUtil.readLiteral(skData.getDataStream(skFactory)));
        assertTrue(skData.verify());
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
