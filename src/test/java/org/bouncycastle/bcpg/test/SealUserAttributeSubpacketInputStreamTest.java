package org.bouncycastle.bcpg.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.bcpg.UserAttributeSubpacket;
import org.bouncycastle.bcpg.UserAttributeSubpacketInputStream;
import org.bouncycastle.bcpg.UserAttributeSubpacketTags;
import org.bouncycastle.bcpg.attr.ImageAttribute;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVectorGenerator;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Parsing of user attribute sub-packets (UserAttributeSubpacketInputStream) for the one-, two- and five-octet
 * length encodings, plus truncated input.
 */
public class SealUserAttributeSubpacketInputStreamTest
{
    private static byte[] image(int length)
    {
        byte[] data = new byte[length];
        for (int i = 0; i != data.length; i++)
        {
            data[i] = (byte)(i * 7 + 3);
        }
        return data;
    }

    private static UserAttributeSubpacket subpacket(int type, byte[] data)
    {
        // the constructor is protected; an anonymous subclass gives a plain sub-packet of the given type
        return new UserAttributeSubpacket(type, data)
        {
        };
    }

    private static byte[] encode(UserAttributeSubpacket[] packets)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        for (int i = 0; i != packets.length; i++)
        {
            packets[i].encode(bOut);
        }
        return bOut.toByteArray();
    }

    private void checkImageRoundTrip(int imageLength)
        throws IOException
    {
        byte[] imageData = image(imageLength);
        PGPUserAttributeSubpacketVectorGenerator gen = new PGPUserAttributeSubpacketVectorGenerator();
        gen.setImageAttribute(ImageAttribute.JPEG, imageData);
        PGPUserAttributeSubpacketVector vector = gen.generate();

        byte[] encoded = encode(new UserAttributeSubpacket[] { vector.getImageAttribute() });

        UserAttributeSubpacketInputStream in = new UserAttributeSubpacketInputStream(new ByteArrayInputStream(encoded));
        UserAttributeSubpacket packet = in.readPacket();
        assertTrue(packet instanceof ImageAttribute);
        assertEquals(UserAttributeSubpacketTags.IMAGE_ATTRIBUTE, packet.getType());

        ImageAttribute attr = (ImageAttribute)packet;
        assertEquals(ImageAttribute.JPEG, attr.getEncoding());
        assertArrayEquals(imageData, attr.getImageData());
        assertEquals(vector.getImageAttribute(), attr);

        assertNull("no further packets expected", in.readPacket());
    }

    @Test
    public void testOneOctetLength()
        throws IOException
    {
        checkImageRoundTrip(20);
    }

    @Test
    public void testTwoOctetLength()
        throws IOException
    {
        checkImageRoundTrip(1000);
    }

    @Test
    public void testFiveOctetLength()
        throws IOException
    {
        checkImageRoundTrip(70000);
    }

    @Test
    public void testExplicitLongLengthEncoding()
        throws IOException
    {
        byte[] body = image(10);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        int len = body.length + 1;
        bOut.write(0xff);
        bOut.write(len >>> 24);
        bOut.write(len >>> 16);
        bOut.write(len >>> 8);
        bOut.write(len);
        bOut.write(100); // private/experimental sub-packet type
        bOut.write(body);

        UserAttributeSubpacketInputStream in = new UserAttributeSubpacketInputStream(
            new ByteArrayInputStream(bOut.toByteArray()));
        UserAttributeSubpacket packet = in.readPacket();
        assertEquals(100, packet.getType());
        assertArrayEquals(body, packet.getData());

        // re-encoding must preserve the long-length form
        ByteArrayOutputStream reOut = new ByteArrayOutputStream();
        packet.encode(reOut);
        assertArrayEquals(bOut.toByteArray(), reOut.toByteArray());
    }

    @Test
    public void testMultiplePackets()
        throws IOException
    {
        UserAttributeSubpacket[] packets = new UserAttributeSubpacket[] {
            subpacket(101, image(5)),
            new ImageAttribute(ImageAttribute.JPEG, image(300)),
            subpacket(102, image(0))
        };
        byte[] encoded = encode(packets);

        UserAttributeSubpacketInputStream in = new UserAttributeSubpacketInputStream(new ByteArrayInputStream(encoded));
        for (int i = 0; i != packets.length; i++)
        {
            UserAttributeSubpacket read = in.readPacket();
            assertEquals(packets[i].getType(), read.getType());
            assertArrayEquals(packets[i].getData(), read.getData());
        }
        assertNull(in.readPacket());
    }

    @Test
    public void testEmptyStream()
        throws IOException
    {
        assertNull(new UserAttributeSubpacketInputStream(new ByteArrayInputStream(new byte[0])).readPacket());
    }

    @Test
    public void testTruncatedBody()
        throws IOException
    {
        byte[] encoded = encode(new UserAttributeSubpacket[] { subpacket(101, image(50)) });
        byte[] truncated = new byte[encoded.length - 10];
        System.arraycopy(encoded, 0, truncated, 0, truncated.length);

        try
        {
            new UserAttributeSubpacketInputStream(new ByteArrayInputStream(truncated)).readPacket();
            fail("truncated sub-packet must not parse");
        }
        catch (EOFException e)
        {
            // expected
        }
    }

    @Test
    public void testMissingTag()
        throws IOException
    {
        try
        {
            new UserAttributeSubpacketInputStream(new ByteArrayInputStream(new byte[] { 5 })).readPacket();
            fail("sub-packet without a type octet must not parse");
        }
        catch (EOFException e)
        {
            // expected
        }
    }

    /**
     * A sub-packet header using the five-octet length form, followed by the type octet only.
     */
    private static byte[] longLengthHeader(int bodyLen, int type)
    {
        return new byte[] {
            (byte)0xff, (byte)(bodyLen >>> 24), (byte)(bodyLen >>> 16), (byte)(bodyLen >>> 8), (byte)bodyLen,
            (byte)type };
    }

    private static void checkRejected(byte[] encoded, String expectedMessage)
    {
        try
        {
            new UserAttributeSubpacketInputStream(new ByteArrayInputStream(encoded)).readPacket();
            fail("sub-packet with out of range length must not parse");
        }
        catch (EOFException e)
        {
            // an EOFException means the body buffer was allocated and the read ran off the end of the data
            fail("length must be rejected before the body is allocated, got: " + e);
        }
        catch (IOException e)
        {
            assertTrue(e.getMessage(), e.getMessage().indexOf(expectedMessage) >= 0);
        }
    }

    @Test
    public void testHugeLengthRejectedBeforeAllocation()
    {
        // CVE-2026-59649: a ~2 GiB declared length with no body must not drive a multi-gigabyte allocation
        checkRejected(longLengthHeader(0x7ffffff0, UserAttributeSubpacketTags.IMAGE_ATTRIBUTE),
            "exceeds max user attribute subpacket length");
        checkRejected(longLengthHeader(Integer.MAX_VALUE, 100), "exceeds max user attribute subpacket length");
    }

    @Test
    public void testLengthJustOverMaxRejected()
    {
        checkRejected(longLengthHeader(UserAttributeSubpacketInputStream.MAX_SUBPACKET_LEN + 1, 100),
            "exceeds max user attribute subpacket length (" + UserAttributeSubpacketInputStream.MAX_SUBPACKET_LEN + ")");
    }

    @Test
    public void testNegativeLengthRejected()
    {
        // a five-octet length with the top bit set decodes negative; bodyLen - 1 must not wrap to a huge array
        checkRejected(longLengthHeader(Integer.MIN_VALUE, 100), "out of range");
        checkRejected(longLengthHeader(-1, 100), "out of range");
        checkRejected(new byte[] { 0, 100 }, "out of range");
    }

    @Test
    public void testMaxLengthAccepted()
        throws IOException
    {
        int bodyLen = UserAttributeSubpacketInputStream.MAX_SUBPACKET_LEN;
        byte[] body = image(bodyLen - 1);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        bOut.write(longLengthHeader(bodyLen, 100));
        bOut.write(body);

        UserAttributeSubpacket packet = new UserAttributeSubpacketInputStream(
            new ByteArrayInputStream(bOut.toByteArray())).readPacket();
        assertEquals(100, packet.getType());
        assertArrayEquals(body, packet.getData());
    }

    @Test
    public void testHugeLengthRejectedInUserAttributePacket()
        throws IOException
    {
        // the same attack through the normal packet parsing path: a small User Attribute packet (tag 17)
        // whose single sub-packet header declares a ~2 GiB body
        byte[] subpacket = longLengthHeader(0x7ffffff0, UserAttributeSubpacketTags.IMAGE_ATTRIBUTE);
        byte[] encoded = new byte[2 + subpacket.length];
        encoded[0] = (byte)(0xc0 | PacketTags.USER_ATTRIBUTE);
        encoded[1] = (byte)subpacket.length;
        System.arraycopy(subpacket, 0, encoded, 2, subpacket.length);

        try
        {
            new BCPGInputStream(new ByteArrayInputStream(encoded)).readPacket();
            fail("user attribute packet with oversized sub-packet must not parse");
        }
        catch (EOFException e)
        {
            fail("length must be rejected before the body is allocated, got: " + e);
        }
        catch (IOException e)
        {
            assertTrue(e.getMessage(), e.getMessage().indexOf("exceeds max user attribute subpacket length") >= 0);
        }
    }
}
