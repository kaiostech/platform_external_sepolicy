package com.android.buildbundle;

import android.util.Base64;

import com.google.common.io.Files;

import java.io.File;
import java.io.IOException;

import java.util.HashMap;
import java.util.Map;

/**
 * Abstract class representing the encoding scheme used
 * to create an update bundle for loading.
 */
abstract class Encoding {

    static final int initialCapacity = 2;
    public static final Map<String, Encoding> encodeFunctions =
        new HashMap<String, Encoding>(initialCapacity);

    static {
        encodeFunctions.put("base64", new Base64Encoding());
        encodeFunctions.put("none", new NoEncoding());
    }

    /**
     * Given a File object encode it according to a
     * given bundle scheme capable of being loaded
     * by the ConfigUpdate mechanism.
     *
     * @param path File object of the file to encode.
     *
     * @exception IOException produced by failed or interrupted
     *            I/O operations on the requested path or if
     *            the passed path is null.
     *
     * @return byte array of the encoded file scheme.
     */
    protected abstract byte[] create_encoding(File path) throws IOException;
}

/**
 * Base64 encoding scheme.
 */
class Base64Encoding extends Encoding {

    /**
     * Given a File object encode it as base64 chunked, line
     * wrapped at 76 characters, with each line ending
     * in '\n'. A byte array of the encoded file is returned.
     *
     * @param path File object of the file to encode.
     *
     * @exception IOException produced by failed or interrupted
     *            I/O operations on the requested path or if
     *            the passed path is null.
     *
     * @return byte array of the encoded file scheme.
     */
    @Override
    protected byte[] create_encoding(File path) throws IOException  {
        if (path == null) {
            throw new IOException("Requested path is null.");
        }

        byte[] policy = Files.toByteArray(path);
        return Base64.encode(policy, Base64.DEFAULT);
    }
}

/**
 * No encoding scheme implementation.
 */
class NoEncoding extends Encoding {

    /**
     * Given a File object simply return it as a byte array.
     *
     * @param path File object of the file to encode.
     *
     * @exception IOException produced by failed or interrupted
     *            I/O operations on the requested path or if
     *            the passed path is null.
     *
     * @return byte array of the encoded file scheme.
     */
    @Override
    protected byte[] create_encoding(File path) throws IOException  {
        if (path == null) {
            throw new IOException("Requested path is null.");
        }

        return  Files.toByteArray(path);
    }
}
