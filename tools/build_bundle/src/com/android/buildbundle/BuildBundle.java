package com.android.buildbundle;

import com.android.buildbundle.Encoding.*;

import com.google.common.base.Joiner;
import com.google.common.io.ByteStreams;
import com.google.common.io.Closeables;
import com.google.common.io.Files;

import java.lang.InterruptedException;
import java.lang.Process;
import java.lang.ProcessBuilder;

import java.io.*;

import java.security.*;
import java.security.spec.KeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import java.util.ArrayList;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import android.util.Base64;

/**
 * Command line tool to build OTA config bundles capable of
 * being delivered via the ConfigUpdateInstallReceiver
 * mechanism.
 *
 * <pre>
 * Usage: buildbundle -k &lt;privatekey.pk8&gt; [-v &lt;version&gt;] [-r &lt;required hash&gt;] 
 *                    [-o &lt;output zip file&gt;] [-m &lt;meta&gt;] [-e &lt;encoding&gt;] [-h]
 *                    file [ file [ file ... ] ]
 * Options:
 *    -k pkcs8 DER formatted private key used to sign the bundle.
 *    -v version of the created bundle. Defaults to 1.
 *    -r hash of previous bundle that will be replaced. Defaults to 'NONE'.
 *    -o name of the output zip file. Defaults to update_bundle.zip.
 *    -e type of bundle encoding. Possible values are 'base64' and 'none'.
 *       Defaults to 'base64'.
 *    -m an optional value that will be appended to the metadata file.
 *    -h prints this help screen.
 * Positional Arguments:
 *    file: path to a file to be included in the signed bundle.
 *          The order of the files will be preserved in the bundle.
 * </pre>
 */
public class BuildBundle {

    /**
     * Print a usage statement prepended with a header string
     * and then exit with a value of 1.
     *
     * @param header a string that will be printed before
     *        the usage statement.
     */
    private static void usage(String header) {
        System.err.println("\n" + header + "\n");
        System.err.println("Usage: buildbundle -k <privatekey.pk8> " +
                           "[-v <version>] [-r <required hash>] " +
                           "[-o <output zip file>] [-m <meta>] [-e <encoding>] " +
                           "[-h] file [ file [ file ... ] ] ");
        System.err.println("Options:");
        System.err.println(" -k pkcs8 DER formatted private key used to sign the bundle.");
        System.err.println(" -v version of the created bundle. Defaults to 1.");
        System.err.println(" -r hash of previous bundle that will be replaced. Defaults to 'NONE'.");
        System.err.println(" -o name of the output zip file. Defaults to update_bundle.zip.");
        System.err.println(" -m additional value that will be appended to the metadata file.");
        System.err.println(" -e type of bundle encoding. Possible values are 'base64' and 'none'.");
        System.err.println("    Defaults to 'base64'.");
        System.err.println(" -h prints this help screen.");
        System.err.println("Positional Arguments:");
        System.err.println(" file: path to a file to be included in the signed bundle.");
        System.err.println("       The order of the files will be preserved in the bundle.");
        System.exit(1);
    }

    /**
     * Given an array of paths to files, create a bundle
     * capable of being loaded via the ConfigUpdateInstallReceiver
     * mechanism. The order of the entries in the array will
     * be preserved when building the bundle. The bundle as
     * a byte array is returned and is capable of being directly
     * loaded via the ConfigUpdateInstallReceiver mechanism.
     * The format of the returned bundle depends on the number of
     * passed paths. If more than one file is passed then a
     * header representing file lengths will precede the file
     * contents. If only one file is passed then no byte header
     * is attached. If there are no paths passed then no bundle
     * is created; however, an empty byte array will still be
     * returned. No metadata about the bundle is returned;
     * additional processing must be performed to calculate that
     * data.
     *
     * @param paths ArrayList of strings representing paths
     *              to config files to include in the bundle.
     * @param encodingFunction the scheme used to encode
     *        the bundle.
     *
     * @exception IOException produced by failed or interrupted
     *            I/O operations on any of the requested paths.
     *            Also thrown if the passed paths list is null
     *            or the encoding scheme is null.
     *
     * @return byte array of the created config bundle.
     */
    public static byte[] build_bundle(ArrayList<String> paths, Encoding encodingFunction)
            throws IOException {

        if (paths == null) {
            throw new IOException("Requested paths is null");
        }

        if (encodingFunction == null) {
            throw new IOException("Encoding scheme is null");
        }

        int numOfPaths = paths.size();
        int[] lengths = new int[numOfPaths];
        byte[][] files = new byte[numOfPaths][];

        for (int i = 0; i < numOfPaths; i++) {
            files[i] = encodingFunction.create_encoding(new File(paths.get(i)));
            lengths[i] = files[i].length;
        }

        ByteBuffer b = ByteBuffer.allocate(numOfPaths * 4);
        for (int i = 0; i < numOfPaths; i++) {
            b.putInt(lengths[i]);
        }

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        if (numOfPaths > 1) {
            output.write(b.array());
        }
        for (int i = 0; i < numOfPaths; i++) {
            output.write(files[i]);
        }

        return output.toByteArray();
    }

    /**
     * Prompt the user for a password. The password isn't
     * echoed back to the screen and is returned as a
     * char array. This function assumes there is a console
     * device associated with the current JVM. This might not
     * be the case, for instance if started by a background job
     * scheduler. Thus, this function might have to change
     * in the future.
     *
     * @param keyPath the path to the key as a string.
     *
     * @exception IOException produced by failed or interrupted
     *            I/O operations on the current console.
     *
     * @return a char array of the password needed to decrypt
     *         the key or null if an error occured with the console.
     */
    private static char[] getPassword(String keyPath) throws IOException {

        char[] password = null;
        Console cons = System.console();
        if (cons != null) {
            final String con = "Enter password for " + keyPath;
            password = cons.readPassword("%s> ", con);
        }

        return password;
    }

    /**
     * Based on ghstark's post on Aug 6, 2006 at
     * http://forums.sun.com/thread.jspa?threadID=758133&messageID=4330949
     *
     * Convert a pkcs8 formatted private key into a PrivateKey
     * interface object. The private key can be encrypted or not.
     * If encrypted, the user will be prompted for the password.
     *
     * @param privateKey the private key to decrypt given as byte array.
     * @param keyPath path to the key given as a string.
     *
     * @exception IOException produced by failed or interrupted I/O
     *            operations when retrieving the password for the key.
     * @exception GeneralSecurityException generic security exceptions
     *            that result from signature and key operations.
     *
     * @return a KeySpec object which can be used to derive additional
     *         key material if the passed private key is encrypted. If
     *         the private key isn't encrypted then null is returned.
     */
    private static KeySpec decryptPrivateKey(byte[] privateKey, String keyFile)
            throws IOException, GeneralSecurityException {

        EncryptedPrivateKeyInfo epkInfo;
        try {
            epkInfo = new EncryptedPrivateKeyInfo(privateKey);
        } catch (IOException ex) {
            // Probably not an encrypted key.
            return null;
        }

        char[] password = getPassword(keyFile);

        SecretKeyFactory skFactory = SecretKeyFactory.getInstance(epkInfo.getAlgName());
        Key key = skFactory.generateSecret(new PBEKeySpec(password));

        Cipher cipher = Cipher.getInstance(epkInfo.getAlgName());
        cipher.init(Cipher.DECRYPT_MODE, key, epkInfo.getAlgParameters());

        try {
            return epkInfo.getKeySpec(cipher);
        } catch (InvalidKeySpecException ex) {
            System.err.println("Password for " + keyFile + " may be bad.");
            throw new GeneralSecurityException(ex);
        }
    }

    /**
     * Return a PrivateKey object of the private key after being
     * decrypted with a password if needed. The private key is
     * assumed to be encoded according to the pkcs8 standard.
     *
     * @param privateKey the private key to decrypt given as byte array.
     * @param keyPath path to the key given as a string.
     *
     * @exception IOException produced by failed or interrupted I/O
     *            operations when retrieving the password for the key.
     * @exception GeneralSecurityException generic security exceptions
     *            that result from signature and key operations.
     *
     * @return a PrivateKey interface object to the underlying
     *         key material.
     */
    private static PrivateKey getPrivateKey(byte[] privateKey, String keyPath)
            throws IOException, GeneralSecurityException {

        KeySpec spec = decryptPrivateKey(privateKey, keyPath);
        if (spec == null) {
            spec = new PKCS8EncodedKeySpec(privateKey);
        }

        try {
            return KeyFactory.getInstance("RSA").generatePrivate(spec);
        } catch (InvalidKeySpecException ex) {
            System.err.println(keyPath + " probably not a PKCS#8 DER formatted RSA cert.");
            throw new GeneralSecurityException(ex);
        }
    }

    /**
     * Takes a byte array as well as the version, previous hash and
     * optional meta value and computes the digital signature using
     * RSA and SHA-512. The secured message is then returned as a
     * byte array.
     *
     * @param bundle byte array representing the built config bundle.
     * @param version the version of this config update.
     * @param privKey the path to the pkcs8 DER formatted private key
     *                used to sign the config update.
     * @param requiredHash the hash of the previous config update
     *                     that will be replaced.
     * @param otherMeta a generic string that will be added to the
     *                  signed bundle. If the string is null it
     *                  will not be part of the signed bundle.
     *
     * @exception IOException produced by failed or interrupted
     *            I/O operations when retrieving the key.
     * @exception GeneralSecurityException generic security exceptions
     *            that result from signature and hashing attempts.
     *
     * @return a byte array of the signed message.
     */
    public static byte[] sign_bundle(byte[] bundle, String version, String privKey,
                                     String requiredHash, String otherMeta)
            throws IOException, GeneralSecurityException {

        InputStream is = new FileInputStream(new File (privKey));
        byte[] privateKey = ByteStreams.toByteArray(is);
        is.close();
        PrivateKey pk = getPrivateKey(privateKey, privKey);

        Signature signer = Signature.getInstance("SHA512withRSA");
        signer.initSign(pk);
        signer.update(bundle);
        signer.update(version.getBytes());
        signer.update(requiredHash.getBytes());
        if (otherMeta != null) {
            signer.update(otherMeta.getBytes());
        }

        // The signature should be one large string
        return Base64.encode(signer.sign(), Base64.NO_WRAP);
    }

    /**
     * Runs the command line driver.
     *
     * @param args program arguments.
     */
    public static void main(String[] args) {
        new BuildBundle().run(args);
    }

    /**
     * Main entry point for both command line driver and
     * library hook. Consider the help message invoked with
     * -h for a more complete description of the functionality.
     *
     * @param args program arguments.
     */
    public static void run(String[] args) {

        String privateKey = null;
        String version = "1";
        String requiredHash = "NONE";
        String outputName = "update_bundle.zip";
        String otherMeta = null;
        ArrayList<String> configPaths = new ArrayList<String>();
        Encoding encodingFunction = Encoding.encodeFunctions.get("base64");

        try {
            for (int i = 0; i < args.length; i++) {
                String arg = args[i];

                if (arg.equals("-k")) {
                    privateKey = args[++i];
                } else if (arg.equals("-v")) {
                    version = args[++i];
                } else if (arg.equals("-r")) {
                    requiredHash = args[++i];
                } else if (arg.equals("-o")) {
                    outputName = args[++i];
                } else if (arg.equals("-m")) {
                    otherMeta = args[++i];
                } else if (arg.equals("-e")) {
                    encodingFunction = Encoding.encodeFunctions.get(args[++i]);
                } else if (arg.equals("-h")) {
                    usage("Tool to build OTA config bundles");
                } else {
                    // All positional arguments are files to bundle.
                    configPaths.add(args[i]);
                }
            }
        } catch (ArrayIndexOutOfBoundsException ex) {
            usage("Missing required argument.");
        }

        if (privateKey == null) {
            usage("No private key specified.");
        }

        int numOfFiles = configPaths.size();
        if (numOfFiles == 0) {
            usage("Must specify at least one config file to bundle.");
        }

        try {
            String versionRegex = "\\d+";
            if (!version.matches(versionRegex)) {
                throw new IllegalArgumentException("Illegal version: " + version);
            }

            String hashRegex = "[a-fA-F0-9]{128}";
            if (!"NONE".equals(requiredHash) && !requiredHash.matches(hashRegex)) {
                throw new IllegalArgumentException("Illegal SHA-512 hash: " + requiredHash);
            }

            // Check that the extra meta value is a non-negative integer?
            String metaRegex = "\\d+";
            if (otherMeta != null && !otherMeta.matches(metaRegex)) {
                throw new IllegalArgumentException("Illegal metavalue: " + otherMeta);
            }

            byte[] bundle = build_bundle(configPaths, encodingFunction);
            byte[] signed = sign_bundle(bundle, version, privateKey, requiredHash, otherMeta);

            String joined = Joiner.on(":").join(requiredHash, new String(signed), version);
            if (otherMeta != null) {
                joined += ":" + otherMeta;
            }
            byte[] joined_bytes = joined.getBytes();

            // Build zip file
            final ZipOutputStream out = new ZipOutputStream(new FileOutputStream(outputName));
            ZipEntry e = new ZipEntry("update_bundle");
            out.putNextEntry(e);
            out.write(bundle, 0, bundle.length);
            out.closeEntry();
            e = new ZipEntry("update_bundle_metadata");
            out.putNextEntry(e);
            out.write(joined_bytes, 0, joined_bytes.length);
            out.closeEntry();
            out.close();
        } catch (IOException ioex) {
            System.out.println("IOException error: " + ioex.toString() + ". Exiting.");
        } catch (GeneralSecurityException gex) {
            System.out.println("Security Exception error: " + gex.toString() + ". Exiting.");
        } catch (IllegalArgumentException iax) {
            System.out.println(iax.toString());
        }
    }
}
