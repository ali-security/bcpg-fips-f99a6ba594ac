package org.bouncycastle.bcpg;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.bcpg.attr.ImageAttribute;

/**
 * reader for user attribute sub-packets
 */
public class UserAttributeSubpacketInputStream
    extends InputStream implements UserAttributeSubpacketTags
{
    /**
     * Hard upper bound on a single user-attribute subpacket body. This is an absolute cap applied
     * before the body buffer is allocated, as the stream used during packet parsing does not
     * otherwise bound the per-packet allocation. Without it a crafted 4-octet length header could
     * force a multi-gigabyte {@code new byte[]} before any body bytes are read. 2 MiB matches the
     * ceiling used upstream for signature subpackets and public-key packets; user-attribute (image)
     * subpackets are not expected to approach it.
     */
    public static final int MAX_SUBPACKET_LEN = 2 * 1024 * 1024;

    InputStream    in;

    public UserAttributeSubpacketInputStream(
        InputStream    in)
    {
        this.in = in;
    }
    
    public int available()
        throws IOException
    {
        return in.available();
    }
    
    public int read()
        throws IOException
    {
        return in.read();
    }
    
    private void readFully(
        byte[]    buf,
        int       off,
        int       len)
        throws IOException
    {
        if (len > 0)
        {
            int    b = this.read();
            
            if (b < 0)
            {
                throw new EOFException();
            }
            
            buf[off] = (byte)b;
            off++;
            len--;
        }
        
        while (len > 0)
        {
            int    l = in.read(buf, off, len);
            
            if (l < 0)
            {
                throw new EOFException();
            }
            
            off += l;
            len -= l;
        }
    }
    
    public UserAttributeSubpacket readPacket()
        throws IOException
    {
        int            l = this.read();
        int            bodyLen = 0;
        boolean        longLength = false;

        if (l < 0)
        {
            return null;
        }

        if (l < 192)
        {
            bodyLen = l;
        }
        else if (l <= 223)
        {
            bodyLen = ((l - 192) << 8) + (in.read()) + 192;
        }
        else if (l == 255)
        {
            bodyLen = (in.read() << 24) | (in.read() << 16) |  (in.read() << 8)  | in.read();
            longLength = true;
        }
        else
        {
            throw new IOException("unrecognised length reading user attribute sub packet");
        }

        // Absolute cap, checked before allocating, so a crafted length cannot drive a huge allocation.
        if (bodyLen > MAX_SUBPACKET_LEN)
        {
            throw new IOException("Body length octet (" + bodyLen + ") exceeds max user attribute subpacket length (" + MAX_SUBPACKET_LEN + ").");
        }
        // The body length covers the type octet, so it must be at least 1; a 5-octet length with the
        // top bit set decodes negative and would otherwise wrap bodyLen - 1 to a huge allocation.
        if (bodyLen < 1)
        {
            throw new IOException("Body length octet (" + bodyLen + ") out of range for user attribute sub packet.");
        }

       int        tag = in.read();

       if (tag < 0)
       {
           throw new EOFException("unexpected EOF reading user attribute sub packet");
       }
       
       byte[]    data = new byte[bodyLen - 1];

       this.readFully(data, 0, data.length);
       
       int       type = tag;

       switch (type)
       {
       case IMAGE_ATTRIBUTE:
           return new ImageAttribute(longLength, data);
       }

       return new UserAttributeSubpacket(type, longLength, data);
    }
}
