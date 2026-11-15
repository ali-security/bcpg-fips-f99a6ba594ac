package org.bouncycastle.openpgp.test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.PGPKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.util.io.Streams;

/**
 * Shared helpers for the bcpg-fips OpenPGP encryption/decryption tests (run against the BCFIPS provider).
 */
final class SealTestUtil
{
    static final String PROVIDER = "BCFIPS";

    private SealTestUtil()
    {
    }

    static void installProvider()
    {
        if (Security.getProvider(PROVIDER) == null)
        {
            Security.addProvider(new BouncyCastleFipsProvider());
        }
    }

    static PGPDigestCalculatorProvider digestProvider()
        throws Exception
    {
        return new JcaPGPDigestCalculatorProviderBuilder().setProvider(PROVIDER).build();
    }

    static PGPDigestCalculator sha1Calculator()
        throws Exception
    {
        return digestProvider().get(HashAlgorithmTags.SHA1);
    }

    static byte[] encrypt(byte[] message, int symAlg, boolean integrity, PGPKeyEncryptionMethodGenerator[] methods)
        throws Exception
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
            new JcePGPDataEncryptorBuilder(symAlg)
                .setWithIntegrityPacket(integrity)
                .setSecureRandom(new SecureRandom())
                .setProvider(PROVIDER));
        for (int i = 0; i != methods.length; i++)
        {
            encGen.addMethod(methods[i]);
        }

        OutputStream cOut = encGen.open(bOut, new byte[1 << 12]);
        PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();
        OutputStream lOut = litGen.open(cOut, PGPLiteralData.BINARY, "message.bin", message.length, new Date());
        lOut.write(message);
        litGen.close();
        encGen.close();

        return bOut.toByteArray();
    }

    static PGPEncryptedDataList readEncryptedDataList(byte[] encoded)
        throws Exception
    {
        JcaPGPObjectFactory factory = new JcaPGPObjectFactory(encoded);
        Object o = factory.nextObject();
        return (PGPEncryptedDataList)o;
    }

    static byte[] readLiteral(InputStream clear)
        throws Exception
    {
        JcaPGPObjectFactory factory = new JcaPGPObjectFactory(clear);
        PGPLiteralData literal = (PGPLiteralData)factory.nextObject();
        return Streams.readAll(literal.getInputStream());
    }

    static byte[] randomMessage(int length)
    {
        byte[] message = new byte[length];
        new SecureRandom().nextBytes(message);
        return message;
    }
}
