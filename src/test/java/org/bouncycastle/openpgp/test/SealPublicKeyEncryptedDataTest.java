package org.bouncycastle.openpgp.test;

import java.security.KeyPairGenerator;
import java.util.Date;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.operator.PGPKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Public-key (PKESK) encryption round trips through PGPEncryptedDataList and PGPPublicKeyEncryptedData,
 * including a message carrying both a PKESK and an SKESK.
 */
public class SealPublicKeyEncryptedDataTest
{
    private static PGPKeyPair rsaKeyPair;
    private static PGPKeyPair otherRsaKeyPair;

    @BeforeClass
    public static void setUp()
        throws Exception
    {
        SealTestUtil.installProvider();
        rsaKeyPair = generateRsa();
        otherRsaKeyPair = generateRsa();
    }

    static PGPKeyPair generateRsa()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", SealTestUtil.PROVIDER);
        kpg.initialize(2048);
        return new JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, kpg.generateKeyPair(), new Date());
    }

    private static PGPKeyEncryptionMethodGenerator pkMethod(PGPKeyPair keyPair)
    {
        return new JcePublicKeyKeyEncryptionMethodGenerator(keyPair.getPublicKey()).setProvider(SealTestUtil.PROVIDER);
    }

    private static PublicKeyDataDecryptorFactory pkDecryptor(PGPKeyPair keyPair)
    {
        return new JcePublicKeyDataDecryptorFactoryBuilder().setProvider(SealTestUtil.PROVIDER)
            .setContentProvider(SealTestUtil.PROVIDER).build(keyPair.getPrivateKey());
    }

    @Test
    public void testRsaRoundTrip()
        throws Exception
    {
        byte[] message = SealTestUtil.randomMessage(5000);
        byte[] encrypted = SealTestUtil.encrypt(message, SymmetricKeyAlgorithmTags.AES_256, true,
            new PGPKeyEncryptionMethodGenerator[] { pkMethod(rsaKeyPair) });

        PGPEncryptedDataList list = SealTestUtil.readEncryptedDataList(encrypted);
        assertEquals(1, list.size());
        assertTrue(list.isIntegrityProtected());
        PGPPublicKeyEncryptedData pkData = (PGPPublicKeyEncryptedData)list.get(0);
        assertEquals(rsaKeyPair.getKeyID(), pkData.getKeyID());
        assertEquals(PublicKeyAlgorithmTags.RSA_GENERAL, pkData.getAlgorithm());

        PublicKeyDataDecryptorFactory decryptor = pkDecryptor(rsaKeyPair);
        assertEquals(SymmetricKeyAlgorithmTags.AES_256, pkData.getSymmetricAlgorithm(decryptor));

        PGPSessionKey sessionKey = pkData.getSessionKey(decryptor);
        assertEquals(SymmetricKeyAlgorithmTags.AES_256, sessionKey.getAlgorithm());
        assertEquals(32, sessionKey.getKey().length);

        PGPPublicKeyEncryptedData pkData2 = (PGPPublicKeyEncryptedData)SealTestUtil.readEncryptedDataList(encrypted).get(0);
        assertArrayEquals(message, SealTestUtil.readLiteral(pkData2.getDataStream(pkDecryptor(rsaKeyPair))));
        assertTrue(pkData2.verify());
    }

    @Test
    public void testWrongPrivateKeyRejected()
        throws Exception
    {
        byte[] encrypted = SealTestUtil.encrypt(SealTestUtil.randomMessage(64), SymmetricKeyAlgorithmTags.AES_128, true,
            new PGPKeyEncryptionMethodGenerator[] { pkMethod(rsaKeyPair) });

        PGPPublicKeyEncryptedData pkData = (PGPPublicKeyEncryptedData)SealTestUtil.readEncryptedDataList(encrypted).get(0);
        try
        {
            pkData.getDataStream(pkDecryptor(otherRsaKeyPair));
            fail("decryption with the wrong private key must fail");
        }
        catch (PGPException e)
        {
            // expected: the session key cannot be recovered
        }
    }

    @Test
    public void testMixedRecipientsMessage()
        throws Exception
    {
        byte[] message = SealTestUtil.randomMessage(1234);
        char[] pass = "shared secret".toCharArray();
        JcePBEKeyEncryptionMethodGenerator pbeMethod = new JcePBEKeyEncryptionMethodGenerator(pass);
        pbeMethod.setProvider(SealTestUtil.PROVIDER);
        byte[] encrypted = SealTestUtil.encrypt(message, SymmetricKeyAlgorithmTags.AES_256, true,
            new PGPKeyEncryptionMethodGenerator[] { pkMethod(rsaKeyPair), pkMethod(otherRsaKeyPair), pbeMethod });

        PGPEncryptedDataList list = SealTestUtil.readEncryptedDataList(encrypted);
        assertEquals(3, list.size());

        int pk = 0;
        int pbe = 0;
        for (java.util.Iterator it = list.getEncryptedDataObjects(); it.hasNext();)
        {
            PGPEncryptedData ed = (PGPEncryptedData)it.next();
            if (ed instanceof PGPPublicKeyEncryptedData)
            {
                pk++;
            }
            else if (ed instanceof PGPPBEEncryptedData)
            {
                pbe++;
            }
        }
        assertEquals(2, pk);
        assertEquals(1, pbe);

        PGPPublicKeyEncryptedData forOther = (PGPPublicKeyEncryptedData)list.get(1);
        assertEquals(otherRsaKeyPair.getKeyID(), forOther.getKeyID());
        assertArrayEquals(message, SealTestUtil.readLiteral(forOther.getDataStream(pkDecryptor(otherRsaKeyPair))));
        assertTrue(forOther.verify());

        PGPPBEEncryptedData pbeData = (PGPPBEEncryptedData)SealTestUtil.readEncryptedDataList(encrypted).get(2);
        assertArrayEquals(message, SealTestUtil.readLiteral(pbeData.getDataStream(
            new JcePBEDataDecryptorFactoryBuilder(SealTestUtil.digestProvider()).setProvider(SealTestUtil.PROVIDER).build(pass))));
        assertTrue(pbeData.verify());
    }
}
