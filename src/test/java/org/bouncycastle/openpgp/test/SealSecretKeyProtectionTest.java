package org.bouncycastle.openpgp.test;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.jcajce.JcaPGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.PGPSecretKeyDecryptorWithAAD;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEProtectionRemoverFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Passphrase protection of secret keys: JcePBESecretKeyEncryptorBuilder / JcePBESecretKeyDecryptorBuilder
 * (PBESecretKeyEncryptor / PBESecretKeyDecryptor) and JcePBEProtectionRemoverFactory.
 */
public class SealSecretKeyProtectionTest
{
    private static final char[] PASS = "secret key passphrase".toCharArray();

    @BeforeClass
    public static void setUp()
        throws Exception
    {
        SealTestUtil.installProvider();
    }

    /**
     * Wraps a fresh RSA encryption key (the FIPS provider forbids using one RSA modulus for both signing and
     * encryption, so the key is not self-certified) in a passphrase-protected secret key packet.
     */
    private PGPSecretKey protect(PGPKeyPair keyPair, int symAlg, int s2kCount)
        throws Exception
    {
        PBESecretKeyEncryptor encryptor = new JcePBESecretKeyEncryptorBuilder(symAlg,
            SealTestUtil.digestProvider().get(HashAlgorithmTags.SHA256), s2kCount)
            .setProvider(SealTestUtil.PROVIDER).setSecureRandom(new SecureRandom()).build(PASS);

        return new PGPSecretKey(keyPair.getPrivateKey(), keyPair.getPublicKey(), SealTestUtil.sha1Calculator(),
            true, encryptor);
    }

    private PGPSecretKey protect(int symAlg, int s2kCount)
        throws Exception
    {
        return protect(SealPublicKeyEncryptedDataTest.generateRsa(), symAlg, s2kCount);
    }

    private PBESecretKeyDecryptor decryptor(char[] pass)
        throws Exception
    {
        return new JcePBESecretKeyDecryptorBuilder(SealTestUtil.digestProvider())
            .setProvider(SealTestUtil.PROVIDER).build(pass);
    }

    @Test
    public void testProtectedKeyRoundTripAes256()
        throws Exception
    {
        checkProtectedKey(SymmetricKeyAlgorithmTags.AES_256, 0x60);
    }

    @Test
    public void testProtectedKeyRoundTripAes128()
        throws Exception
    {
        checkProtectedKey(SymmetricKeyAlgorithmTags.AES_128, 0xff);
    }

    private void checkProtectedKey(int symAlg, int s2kCount)
        throws Exception
    {
        PGPKeyPair keyPair = SealPublicKeyEncryptedDataTest.generateRsa();
        PGPSecretKey secretKey = protect(keyPair, symAlg, s2kCount);
        assertEquals(symAlg, secretKey.getKeyEncryptionAlgorithm());
        assertNotNull(secretKey.getS2K());
        assertFalse(secretKey.isPrivateKeyEmpty());

        // serialise and re-parse as a secret key ring, then unlock with the passphrase
        PGPSecretKeyRing ring = new JcaPGPSecretKeyRing(secretKey.getEncoded());
        PGPSecretKey parsed = ring.getSecretKey();
        assertEquals(keyPair.getKeyID(), parsed.getKeyID());

        PGPPrivateKey privateKey = parsed.extractPrivateKey(decryptor(PASS));
        assertNotNull(privateKey);
        assertEquals(keyPair.getKeyID(), privateKey.getKeyID());

        // the recovered private key must decrypt a message encrypted to the public key
        byte[] message = SealTestUtil.randomMessage(512);
        byte[] encrypted = SealTestUtil.encrypt(message, SymmetricKeyAlgorithmTags.AES_256, true,
            new PGPKeyEncryptionMethodGenerator[] {
                new JcePublicKeyKeyEncryptionMethodGenerator(parsed.getPublicKey()).setProvider(SealTestUtil.PROVIDER) });
        PGPPublicKeyEncryptedData pkData = (PGPPublicKeyEncryptedData)SealTestUtil.readEncryptedDataList(encrypted).get(0);
        assertArrayEquals(message, SealTestUtil.readLiteral(pkData.getDataStream(
            new JcePublicKeyDataDecryptorFactoryBuilder().setProvider(SealTestUtil.PROVIDER).build(privateKey))));
        assertTrue(pkData.verify());
    }

    @Test
    public void testWrongPassphraseRejected()
        throws Exception
    {
        PGPSecretKey secretKey = protect(SymmetricKeyAlgorithmTags.AES_256, 0x60);
        try
        {
            secretKey.extractPrivateKey(decryptor("wrong passphrase".toCharArray()));
            fail("wrong passphrase must not unlock the key");
        }
        catch (PGPException e)
        {
            // expected: checksum mismatch / bad key data
        }
    }

    @Test
    public void testCopyWithNewPassword()
        throws Exception
    {
        PGPSecretKey secretKey = protect(SymmetricKeyAlgorithmTags.AES_256, 0x60);
        char[] newPass = "a different passphrase".toCharArray();
        PGPSecretKey rekeyed = PGPSecretKey.copyWithNewPassword(secretKey, decryptor(PASS),
            new JcePBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_192, SealTestUtil.sha1Calculator())
                .setProvider(SealTestUtil.PROVIDER).build(newPass));

        assertEquals(SymmetricKeyAlgorithmTags.AES_192, rekeyed.getKeyEncryptionAlgorithm());
        assertNotNull(rekeyed.extractPrivateKey(decryptor(newPass)));
        try
        {
            rekeyed.extractPrivateKey(decryptor(PASS));
            fail("old passphrase must no longer unlock the key");
        }
        catch (PGPException e)
        {
            // expected
        }
    }

    @Test
    public void testProtectionRemoverFactoryCbc()
        throws Exception
    {
        JcePBEProtectionRemoverFactory factory = new JcePBEProtectionRemoverFactory(PASS, SealTestUtil.digestProvider())
            .setProvider(SealTestUtil.PROVIDER);

        PBESecretKeyDecryptor cbc = factory.createDecryptor("openpgp-s2k3-sha1-aes-cbc");
        assertFalse(cbc instanceof PGPSecretKeyDecryptorWithAAD);

        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        byte[] plain = new byte[48];
        SecureRandom random = new SecureRandom();
        random.nextBytes(key);
        random.nextBytes(iv);
        random.nextBytes(plain);

        Cipher c = Cipher.getInstance("AES/CBC/NoPadding", SealTestUtil.PROVIDER);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] encrypted = c.doFinal(plain);

        byte[] recovered = cbc.recoverKeyData(SymmetricKeyAlgorithmTags.AES_128, key, iv, encrypted, 0, encrypted.length);
        assertArrayEquals(plain, recovered);
    }

    @Test
    public void testProtectionRemoverFactoryOcbSelectsAADDecryptor()
        throws Exception
    {
        JcePBEProtectionRemoverFactory factory = new JcePBEProtectionRemoverFactory(PASS, SealTestUtil.digestProvider())
            .setProvider(SealTestUtil.PROVIDER);

        assertTrue(factory.createDecryptor("openpgp-s2k3-ocb-aes") instanceof PGPSecretKeyDecryptorWithAAD);
    }
}
