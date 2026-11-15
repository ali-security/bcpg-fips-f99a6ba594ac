package org.bouncycastle.openpgp;

import java.io.EOFException;
import java.io.InputStream;

import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.InputStreamPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PGPDataDecryptorFactory;
import org.bouncycastle.util.io.TeeInputStream;

public class PGPSymmetricKeyEncryptedData
    extends PGPEncryptedData
{
    protected PGPSymmetricKeyEncryptedData(InputStreamPacket encData)
    {
        super(encData);
    }

    protected InputStream createDecryptionStream(PGPDataDecryptorFactory dataDecryptorFactory, PGPSessionKey sessionKey)
        throws PGPException
    {
        if (encData instanceof AEADEncDataPacket)
        {
            AEADEncDataPacket aeadData = (AEADEncDataPacket)encData;

            if (aeadData.getAlgorithm() != sessionKey.getAlgorithm())
            {
                throw new PGPException("session key and AEAD algorithm mismatch");
            }

            PGPDataDecryptor dataDecryptor = dataDecryptorFactory.createDataDecryptor(aeadData.getAEADAlgorithm(), aeadData.getIV(), aeadData.getChunkSize(), sessionKey.getAlgorithm(), sessionKey.getKey());

            BCPGInputStream encIn = encData.getInputStream();

            return new BCPGInputStream(dataDecryptor.getInputStream(encIn));
        }
        else
        {
            boolean withIntegrityPacket = encData instanceof SymmetricEncIntegrityPacket;
            PGPDataDecryptor dataDecryptor = dataDecryptorFactory.createDataDecryptor(withIntegrityPacket, sessionKey.getAlgorithm(), sessionKey.getKey());

            return getDataStream(withIntegrityPacket, dataDecryptor);
        }
    }

    private InputStream getDataStream(
        boolean withIntegrityPacket,
        PGPDataDecryptor dataDecryptor)
        throws PGPException
    {
        try
        {
            BCPGInputStream encIn = encData.getInputStream();
            encIn.mark(dataDecryptor.getBlockSize() + 2); // iv + 2 octets checksum

            encStream = new BCPGInputStream(dataDecryptor.getInputStream(encIn));

            if (withIntegrityPacket)
            {
                truncStream = new TruncatedStream(encStream);

                integrityCalculator = dataDecryptor.getIntegrityCalculator();

                encStream = new TeeInputStream(truncStream, integrityCalculator.getOutputStream());
            }

            byte[] iv = new byte[dataDecryptor.getBlockSize()];
            for (int i = 0; i != iv.length; i++)
            {
                int ch = encStream.read();

                if (ch < 0)
                {
                    throw new EOFException("unexpected end of stream.");
                }

                iv[i] = (byte)ch;
            }

            int v1 = encStream.read();
            int v2 = encStream.read();

            if (v1 < 0 || v2 < 0)
            {
                throw new EOFException("unexpected end of stream.");
            }

            // The check bytes are consumed either way; signalling a mismatch is what makes the CFB quick check
            // the Mister-Zuccherato oracle, so it is done only where useQuickCheck() allows it. For SEIPD v1 the
            // MDC is the integrity check.
            if (!useQuickCheck())
            {
                return encStream;
            }

            boolean repeatCheckPassed = iv[iv.length - 2] == (byte)v1
                && iv[iv.length - 1] == (byte)v2;

            // Note: some versions of PGP appear to produce 0 for the extra
            // bytes rather than repeating the two previous bytes
            boolean zeroesCheckPassed = v1 == 0 && v2 == 0;

            if (!repeatCheckPassed && !zeroesCheckPassed)
            {
                encIn.reset();
                throw new PGPDataValidationException("data check failed.");
            }

            return encStream;
        }
        catch (PGPException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new PGPException("Exception creating cipher", e);
        }
    }

    /**
     * Whether the legacy CFB "quick check" on the two repeated prefix bytes of a SEIPD v1 (or SED)
     * packet is applied when this data is decrypted. Reporting a mismatch is what lets a wrong
     * passphrase be detected - and the stream rewound to try the next SKESK packet - so the
     * password-based path keeps it, while a session key recovered from a public key operation
     * suppresses it: there the report is the Mister-Zuccherato oracle on the CFB prefix and the MDC
     * is the integrity check. Overridden by {@link PGPSessionKeyEncryptedData}, where the caller
     * states which kind of session key it holds.
     *
     * @return true if a quick check mismatch should be reported, false if it should be ignored.
     */
    protected boolean useQuickCheck()
    {
        return true;
    }
}
