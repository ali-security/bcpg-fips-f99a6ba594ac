package org.bouncycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * AEAD (v5 AEAD encrypted data packet) message tag handling.
 * <p>
 * The trailing AEAD message tag authenticates the total plaintext length and so lets the recipient
 * detect truncation at a chunk boundary (CVE-2026-12817). It used to be verified only when the final
 * data chunk was shorter than chunkLength. For a chunk-aligned message (plaintext an exact multiple of
 * chunkLength) every chunk is full-size, so the final tag was pre-read into the look-ahead, never
 * checked, and the decrypting stream returned a clean EOF - a corrupted final tag went undetected, and
 * an attacker could strip trailing chunks (fixing up the un-authenticated outer packet length) and
 * have the recipient accept the truncated plaintext as authentic.
 * </p>
 * <p>
 * A stream cut short without fixing up the outer packet length must likewise be reported
 * (CVE-2026-85515): the packet stream signals the missing bytes with an EOFException, which
 * BCPGInputStream.nextPacketTag() reads as a clean end of message, so it must not escape the AEAD
 * stream as one - otherwise a truncation landing on a packet boundary skipped the final tag check
 * and the truncated message was accepted.
 * </p>
 */
public class SealAEADEncryptedDataTest
{
    private static final char[] PASS = "hello world, this is a passphrase".toCharArray();

    private static final int CHUNK_SIZE_OCTET = 6;   // chunkLength == 64, the minimum
    private static final int CHUNK_LENGTH = 64;
    private static final int TAG_LENGTH = 16;
    private static final int SYM_ALG = SymmetricKeyAlgorithmTags.AES_128;

    private static final int[] AEAD_ALGS = new int[]{ AEADAlgorithmTags.GCM, AEADAlgorithmTags.EAX, AEADAlgorithmTags.OCB };

    @BeforeClass
    public static void setUp()
    {
        SealTestUtil.installProvider();
    }

    @Test
    public void testChunkAlignedMessagesRoundTrip()
        throws Exception
    {
        int[] aeadAlgs = supportedAeadAlgorithms();
        for (int a = 0; a != aeadAlgs.length; a++)
        {
            int alignedSeen = 0;
            for (int n = 0; n <= 200; n++)
            {
                byte[] content = sequentialBytes(n);
                byte[] literal = encodeLiteral(content);
                byte[] message = encryptRaw(aeadAlgs[a], literal);
                String desc = describe(aeadAlgs[a], n);

                // the fix must not break untampered messages, aligned or not
                assertArrayEquals("round-trip failed " + desc, content, decryptLiteral(message));
                assertArrayEquals("raw round-trip failed " + desc, literal, decryptRaw(message));

                if (literal.length % CHUNK_LENGTH == 0)
                {
                    alignedSeen++;
                }
            }
            assertTrue("sweep must include chunk-aligned messages for " + aeadName(aeadAlgs[a]), alignedSeen >= 2);
        }
    }

    @Test
    public void testCorruptedFinalTagRejected()
        throws Exception
    {
        int[] aeadAlgs = supportedAeadAlgorithms();
        for (int a = 0; a != aeadAlgs.length; a++)
        {
            int alignedSeen = 0;
            for (int n = 0; n <= 200; n++)
            {
                byte[] literal = encodeLiteral(sequentialBytes(n));
                byte[] message = encryptRaw(aeadAlgs[a], literal);
                String desc = describe(aeadAlgs[a], n);

                if (literal.length % CHUNK_LENGTH == 0)
                {
                    alignedSeen++;
                }

                // corrupt the final message tag (the last 16 bytes end the AEAD packet body and the stream)
                byte[] tampered = Arrays.clone(message);
                tampered[tampered.length - 1] ^= 0x01;

                assertTrue("corrupted final tag accepted " + desc, literalDecryptRejected(tampered));
                assertTrue("corrupted final tag accepted on raw read " + desc, rawDecryptRejected(tampered));
            }
            assertTrue("sweep must include chunk-aligned messages for " + aeadName(aeadAlgs[a]), alignedSeen >= 2);
        }
    }

    @Test
    public void testCorruptedFinalTagRejectedOnChunkAlignedContent()
        throws Exception
    {
        int[] aeadAlgs = supportedAeadAlgorithms();
        for (int a = 0; a != aeadAlgs.length; a++)
        {
            for (int chunks = 0; chunks <= 3; chunks++)
            {
                byte[] content = SealTestUtil.randomMessage(chunks * CHUNK_LENGTH);
                byte[] message = encryptRaw(aeadAlgs[a], content);
                String desc = "(" + aeadName(aeadAlgs[a]) + ", chunks=" + chunks + ")";

                assertArrayEquals("round-trip failed " + desc, content, decryptRaw(message));

                for (int i = 1; i <= TAG_LENGTH; i++)
                {
                    byte[] tampered = Arrays.clone(message);
                    tampered[tampered.length - i] ^= 0x80;

                    assertTrue("corrupted final tag byte " + i + " accepted " + desc, rawDecryptRejected(tampered));
                }
            }
        }
    }

    @Test
    public void testTruncationAtChunkBoundaryRejected()
        throws Exception
    {
        int[] aeadAlgs = supportedAeadAlgorithms();
        for (int a = 0; a != aeadAlgs.length; a++)
        {
            for (int chunks = 1; chunks <= 4; chunks++)
            {
                byte[] content = SealTestUtil.randomMessage(chunks * CHUNK_LENGTH);
                byte[] message = encryptRaw(aeadAlgs[a], content);

                // control: re-encoding the untouched message with a fixed-up packet length still decrypts
                byte[] reencoded = truncateAtChunkBoundary(message, chunks);
                assertArrayEquals("re-encoded message must still decrypt (" + aeadName(aeadAlgs[a]) + ")",
                    content, decryptRaw(reencoded));

                for (int kept = 0; kept < chunks; kept++)
                {
                    String desc = "(" + aeadName(aeadAlgs[a]) + ", chunks=" + chunks + ", kept=" + kept + ")";

                    // drop the trailing chunks but keep the original final tag, fixing the outer length
                    byte[] truncated = truncateAtChunkBoundary(message, kept);

                    assertTrue("truncated message accepted " + desc, rawDecryptRejected(truncated));
                }
            }
        }
    }

    @Test
    public void testTruncatedLiteralMessageRejected()
        throws Exception
    {
        int[] aeadAlgs = supportedAeadAlgorithms();
        for (int a = 0; a != aeadAlgs.length; a++)
        {
            // two literal data packets, each exactly one chunk long (8 octet header + 56 octets of data)
            byte[] first = sequentialBytes(CHUNK_LENGTH - 8);
            byte[] second = SealTestUtil.randomMessage(CHUNK_LENGTH - 8);

            ByteArrayOutputStream plain = new ByteArrayOutputStream();
            writeLiteral(plain, first);
            writeLiteral(plain, second);
            assertEquals(2 * CHUNK_LENGTH, plain.size());

            byte[] message = encryptRaw(aeadAlgs[a], plain.toByteArray());
            String desc = "(" + aeadName(aeadAlgs[a]) + ")";

            List literals = decryptAllLiterals(message);
            assertEquals(2, literals.size());
            assertArrayEquals(first, (byte[])literals.get(0));
            assertArrayEquals(second, (byte[])literals.get(1));

            // strip the second chunk (the second literal packet) - the first packet is still complete
            byte[] truncated = truncateAtChunkBoundary(message, 1);
            try
            {
                decryptAllLiterals(truncated);
                fail("message truncated at a chunk boundary accepted " + desc);
            }
            catch (IOException e)
            {
                // final tag check failed
            }
            catch (PGPException e)
            {
                // final tag check failed
            }
        }
    }

    @Test
    public void testTruncatedStreamNotReportedAsCleanEndOfMessage()
        throws Exception
    {
        int[] aeadAlgs = supportedAeadAlgorithms();
        // reading the literal data a byte at a time never looks past its end, so the read that runs into
        // the truncation is the next-packet look-ahead; larger reads can run into it from the literal data
        int[] readSizes = new int[]{ 1, 16, 64, 4096 };

        for (int a = 0; a != aeadAlgs.length; a++)
        {
            // two literal data packets, each exactly one chunk long, so the first one ends on a chunk boundary
            byte[] first = sequentialBytes(CHUNK_LENGTH - 8);
            byte[] second = SealTestUtil.randomMessage(CHUNK_LENGTH - 8);

            ByteArrayOutputStream plain = new ByteArrayOutputStream();
            writeLiteral(plain, first);
            writeLiteral(plain, second);
            assertEquals(2 * CHUNK_LENGTH, plain.size());

            byte[] message = encryptRaw(aeadAlgs[a], plain.toByteArray());

            for (int r = 0; r != readSizes.length; r++)
            {
                int readSize = readSizes[r];

                List literals = drainLiterals(message, readSize);
                assertEquals(2, literals.size());
                assertArrayEquals(first, (byte[])literals.get(0));
                assertArrayEquals(second, (byte[])literals.get(1));

                // cut anywhere inside the AEAD packet body (2 chunks + 2 chunk tags + final tag), leaving the
                // enclosing packet length claiming the dropped bytes. Dropping up to CHUNK_LENGTH bytes keeps
                // the first chunk - and so the whole first literal packet - intact, which is what let the
                // next-packet look-ahead swallow the truncation and end the message cleanly.
                int bodyLength = 2 * (CHUNK_LENGTH + TAG_LENGTH) + TAG_LENGTH;
                for (int drop = 1; drop < bodyLength; drop++)
                {
                    assertTruncationReported("(" + aeadName(aeadAlgs[a]) + ", drop=" + drop + ", readSize=" + readSize + ")",
                        truncate(message, drop), readSize);
                }
            }
        }
    }

    @Test
    public void testTruncationSignalled()
        throws Exception
    {
        int[] aeadAlgs = supportedAeadAlgorithms();
        int[] readSizes = new int[]{ 1, 16, 64, 4096 };

        // a packet follows the literal data, as a signature does in a signed message
        byte[] trailer = new byte[32];

        for (int a = 0; a != aeadAlgs.length; a++)
        {
            for (int n = 0; n <= 96; n++)
            {
                byte[] content = sequentialBytes(n);

                ByteArrayOutputStream plain = new ByteArrayOutputStream();
                writeLiteral(plain, content);
                writeLiteral(plain, trailer);

                byte[] message = encryptRaw(aeadAlgs[a], plain.toByteArray());
                String desc = describe(aeadAlgs[a], n);

                for (int r = 0; r != readSizes.length; r++)
                {
                    int readSize = readSizes[r];

                    // the intact message must still stream cleanly at every read size
                    List literals = drainLiterals(message, readSize);
                    assertEquals("round-trip failed " + desc + " readSize=" + readSize, 2, literals.size());
                    assertArrayEquals("round-trip failed " + desc + " readSize=" + readSize,
                        content, (byte[])literals.get(0));
                    assertArrayEquals("round-trip failed " + desc + " readSize=" + readSize,
                        trailer, (byte[])literals.get(1));

                    // truncate the ciphertext, leaving the enclosing packet length claiming the dropped bytes
                    for (int drop = 1; drop <= TAG_LENGTH; drop++)
                    {
                        assertTruncationReported(desc + " drop=" + drop + " readSize=" + readSize,
                            truncate(message, drop), readSize);
                    }
                }
            }
        }
    }

    private static void assertTruncationReported(String desc, byte[] truncated, int readSize)
        throws Exception
    {
        List literals;
        try
        {
            literals = drainLiterals(truncated, readSize);
        }
        catch (EOFException e)
        {
            fail("truncation reported as a clean end of stream " + desc + ": " + e.getMessage());
            return;
        }
        catch (IOException e)
        {
            // truncation reported while reading the decrypted stream
            return;
        }
        catch (PGPException e)
        {
            // truncation early enough to hit the AEAD stream set-up, reported when opening it
            return;
        }

        fail("truncated message accepted " + desc + ", " + literals.size() + " literal packet(s) returned");
    }

    // the message with its last drop octets cut off
    private static byte[] truncate(byte[] message, int drop)
    {
        byte[] truncated = new byte[message.length - drop];
        System.arraycopy(message, 0, truncated, 0, truncated.length);
        return truncated;
    }

    private static int[] supportedAeadAlgorithms()
    {
        List supported = new ArrayList();
        for (int i = 0; i != AEAD_ALGS.length; i++)
        {
            if (isSupported(AEAD_ALGS[i]))
            {
                supported.add(Integer.valueOf(AEAD_ALGS[i]));
            }
            else
            {
                System.out.println("SealAEADEncryptedDataTest: " + aeadName(AEAD_ALGS[i]) + " not available from "
                    + SealTestUtil.PROVIDER + ", skipped");
            }
        }

        assertTrue("GCM must be available", supported.contains(Integer.valueOf(AEADAlgorithmTags.GCM)));

        int[] algs = new int[supported.size()];
        for (int i = 0; i != algs.length; i++)
        {
            algs[i] = ((Integer)supported.get(i)).intValue();
        }
        return algs;
    }

    private static boolean isSupported(int aeadAlg)
    {
        try
        {
            Cipher c = Cipher.getInstance("AES/" + aeadName(aeadAlg) + "/NoPadding", SealTestUtil.PROVIDER);
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "AES"),
                new GCMParameterSpec(128, new byte[AEADEncDataPacket.getIVLength((byte)aeadAlg)]));
            return true;
        }
        catch (GeneralSecurityException e)
        {
            return false;
        }
        catch (IllegalArgumentException e)
        {
            return false;
        }
    }

    private static String aeadName(int aeadAlg)
    {
        switch (aeadAlg)
        {
        case AEADAlgorithmTags.EAX:
            return "EAX";
        case AEADAlgorithmTags.OCB:
            return "OCB";
        case AEADAlgorithmTags.GCM:
            return "GCM";
        default:
            throw new IllegalArgumentException("unknown AEAD algorithm: " + aeadAlg);
        }
    }

    private static String describe(int aeadAlg, int n)
    {
        return "(n=" + n + ", " + aeadName(aeadAlg) + ")";
    }

    private static byte[] sequentialBytes(int n)
    {
        byte[] data = new byte[n];
        for (int i = 0; i != n; i++)
        {
            data[i] = (byte)i;
        }
        return data;
    }

    private static PGPEncryptedDataGenerator aeadGenerator(int aeadAlg)
        throws Exception
    {
        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
            new JcePGPDataEncryptorBuilder(SYM_ALG)
                .setWithAEAD(aeadAlg, CHUNK_SIZE_OCTET)
                .setSecureRandom(new SecureRandom())
                .setProvider(SealTestUtil.PROVIDER));

        JcePBEKeyEncryptionMethodGenerator method = new JcePBEKeyEncryptionMethodGenerator(PASS,
            SealTestUtil.digestProvider().get(HashAlgorithmTags.SHA256));
        method.setProvider(SealTestUtil.PROVIDER);
        encGen.addMethod(method);

        return encGen;
    }

    // the encoding of a literal data packet holding content
    private static byte[] encodeLiteral(byte[] content)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        writeLiteral(bOut, content);
        return bOut.toByteArray();
    }

    // content (raw bytes or encoded packets) in an AEAD packet of definite length
    private static byte[] encryptRaw(int aeadAlg, byte[] content)
        throws Exception
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPEncryptedDataGenerator encGen = aeadGenerator(aeadAlg);

        OutputStream cOut = encGen.open(bOut, content.length);
        cOut.write(content);
        encGen.close();

        return bOut.toByteArray();
    }

    private static void writeLiteral(OutputStream out, byte[] content)
        throws IOException
    {
        PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();
        OutputStream lOut = litGen.open(out, PGPLiteralData.BINARY, "", content.length, new Date());
        lOut.write(content);
        litGen.close();
    }

    /**
     * Rebuild the message keeping only the first {@code keptChunks} encrypted chunks followed by the
     * original final tag, with the (un-authenticated) outer AEAD packet length fixed up to match.
     */
    private static byte[] truncateAtChunkBoundary(byte[] message, int keptChunks)
        throws IOException
    {
        BCPGInputStream pIn = new BCPGInputStream(new ByteArrayInputStream(message));
        SymmetricKeyEncSessionPacket skesk = (SymmetricKeyEncSessionPacket)pIn.readPacket();
        AEADEncDataPacket aead = (AEADEncDataPacket)pIn.readPacket();
        byte[] body = Streams.readAll(aead.getInputStream());

        int keptLen = keptChunks * (CHUNK_LENGTH + TAG_LENGTH);
        assertTrue("not enough chunks in message", keptLen + TAG_LENGTH <= body.length);

        byte[] newBody = new byte[keptLen + TAG_LENGTH];
        System.arraycopy(body, 0, newBody, 0, keptLen);
        System.arraycopy(body, body.length - TAG_LENGTH, newBody, keptLen, TAG_LENGTH);

        byte[] iv = aead.getIV();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        bOut.write(skesk.getEncoded());

        BCPGOutputStream pOut = new BCPGOutputStream(bOut, PacketTags.AEAD_ENC_DATA, 4 + iv.length + newBody.length);
        pOut.write(aead.getVersion());
        pOut.write(aead.getAlgorithm());
        pOut.write(aead.getAEADAlgorithm());
        pOut.write(aead.getChunkSize());
        pOut.write(iv);
        pOut.write(newBody);
        pOut.close();

        return bOut.toByteArray();
    }

    private static InputStream openDataStream(byte[] message)
        throws Exception
    {
        PGPPBEEncryptedData pbeData = (PGPPBEEncryptedData)SealTestUtil.readEncryptedDataList(message).get(0);
        PBEDataDecryptorFactory decryptor = new JcePBEDataDecryptorFactoryBuilder(SealTestUtil.digestProvider())
            .setProvider(SealTestUtil.PROVIDER).build(PASS);
        return pbeData.getDataStream(decryptor);
    }

    // the whole decrypted data stream, read to EOF
    private static byte[] decryptRaw(byte[] message)
        throws Exception
    {
        return Streams.readAll(openDataStream(message));
    }

    // the literal data, after which the rest of the decrypted stream is read to EOF
    private static byte[] decryptLiteral(byte[] message)
        throws Exception
    {
        InputStream clear = openDataStream(message);
        byte[] literal = SealTestUtil.readLiteral(clear);
        Streams.readAll(clear);
        return literal;
    }

    private static List decryptAllLiterals(byte[] message)
        throws Exception
    {
        JcaPGPObjectFactory factory = new JcaPGPObjectFactory(openDataStream(message));

        List literals = new ArrayList();
        Object o;
        while ((o = factory.nextObject()) != null)
        {
            literals.add(Streams.readAll(((PGPLiteralData)o).getInputStream()));
        }
        return literals;
    }

    // walks the decrypted packet stream to its end, reading each literal in readSize increments
    private static List drainLiterals(byte[] message, int readSize)
        throws Exception
    {
        JcaPGPObjectFactory factory = new JcaPGPObjectFactory(openDataStream(message));

        List literals = new ArrayList();
        byte[] buf = new byte[readSize];
        Object o;
        while ((o = factory.nextObject()) != null)
        {
            InputStream lIn = ((PGPLiteralData)o).getInputStream();
            ByteArrayOutputStream lOut = new ByteArrayOutputStream();
            int len;
            while ((len = lIn.read(buf, 0, readSize)) >= 0)
            {
                lOut.write(buf, 0, len);
            }
            literals.add(lOut.toByteArray());
        }
        return literals;
    }

    private static boolean literalDecryptRejected(byte[] message)
        throws Exception
    {
        try
        {
            decryptLiteral(message);
            return false;
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

    private static boolean rawDecryptRejected(byte[] message)
        throws Exception
    {
        try
        {
            decryptRaw(message);
            return false;
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
}
