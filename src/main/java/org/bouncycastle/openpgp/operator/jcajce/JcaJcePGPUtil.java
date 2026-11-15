package org.bouncycastle.openpgp.operator.jcajce;

import java.io.IOException;
import java.math.BigInteger;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.crypto.asymmetric.ECDomainParameters;
import org.bouncycastle.crypto.asymmetric.ECDomainParametersIndex;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.BigIntegers;

/**
 * Basic utility class
 */
class JcaJcePGPUtil
{
    static final ASN1ObjectIdentifier cryptlib = new ASN1ObjectIdentifier("1.3.6.1.4.1.3029");

    static final ASN1ObjectIdentifier ecc = cryptlib.branch("1").branch("5");

    // GNU
    static final ASN1ObjectIdentifier curvey25519 = ecc.branch("1");

    static final ASN1ObjectIdentifier ellipticCurve = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.15");

    static final ASN1ObjectIdentifier Ed25519 = ellipticCurve.branch("1");

    public static SecretKey makeSymmetricKey(
        int             algorithm,
        byte[]          keyBytes)
        throws PGPException
    {
        String    algName = org.bouncycastle.openpgp.PGPUtil.getSymmetricCipherName(algorithm);

        if (algName == null)
        {
            throw new PGPException("unknown symmetric algorithm: " + algorithm);
        }

        return new SecretKeySpec(keyBytes, algName);
    }

    static ECPoint decodePoint(
        BigInteger encodedPoint,
        ECCurve curve)
        throws IOException
    {
        return curve.decodePoint(BigIntegers.asUnsignedByteArray(encodedPoint));
    }

    static X9ECParameters getX9Parameters(ASN1ObjectIdentifier curveOID)
    {
        ECDomainParameters ecParams = ECDomainParametersIndex.lookupDomainParameters(curveOID);

        if (ecParams == null)
        {
            return ECNamedCurveTable.getByOID(curveOID);
        }

        return new X9ECParameters(ecParams.getCurve(), new X9ECPoint(ecParams.getG()), ecParams.getN(), ecParams.getH(), ecParams.getSeed());
    }
}
