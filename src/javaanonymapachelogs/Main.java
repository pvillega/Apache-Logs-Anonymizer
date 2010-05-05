/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package javaanonymapachelogs;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Hashes the IPs on Apache logs to make then anonymous
 * @author pvillega
 */
public class Main {

    /**
     * Given an input and output folder, anonymizes the apache logs in the input
     * folder and copies the result in the output folder.
     *
     * @param args [0]: input folder [1]: output folder.
     */
    public static void main(String[] args) {

        //check input params
        if (args.length < 2) {
            Logger.getLogger(Main.class.getName()).log(Level.INFO, "Please enter the input and output folders for the logs:\n ./run.sh <input> <output>");
            System.exit(0);
        }

        File input = new File(args[0]);
        File output = new File(args[1]);

        if (!input.isDirectory()) {
            Logger.getLogger(Main.class.getName()).log(Level.INFO, "Input has to be a folder which contains the log files");
            System.exit(0);
        }
        if (!output.isDirectory()) {
            Logger.getLogger(Main.class.getName()).log(Level.INFO, "Input has to be a folder to store the anonymized log files");
            System.exit(0);
        }

        File[] logs = input.listFiles();
        for (File f : logs) {
            {
                FileWriter fw = null;
                BufferedReader bin = null;
                try {
                    String s = "";
                    bin = new BufferedReader(new FileReader(f));
                    String fout = output.getPath() + File.separator + "anon_" + f.getName();
                    fw = new FileWriter(fout);

                    //read the file, hash IP's
                    while ((s = bin.readLine()) != null) {

                        MessageDigest digest = java.security.MessageDigest.getInstance("MD5");
                        int space = s.indexOf(' ');
                        digest.update(s.substring(0, space).getBytes());
                        String hash = convertToHex(digest.digest());
                        s = hash + " " + s.substring(space)+"\n";
                        fw.write(s);
                    }

                } catch (NoSuchAlgorithmException ex) {
                    Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
                } catch (IOException ex) {
                    Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
                } finally {
                    try {
                        fw.close();
                        bin.close();
                    } catch (IOException ex) {
                        Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
            }
        }
    }

    /**
     * This code has been obtained from AnyExample.com. It transforms a hash
     * from a byte array to a string.
     *
     * @param data MD5 hash as a byte array
     * @return the HEX representation of the hash
     */
    private static String convertToHex(byte[] data) {
        StringBuffer buffer = new StringBuffer();
        for (int i = 0; i < data.length; i++) {
            int halfbyte = (data[i] >>> 4) & 0x0F;
            int two_halfs = 0;
            do {
                if ((0 <= halfbyte) && (halfbyte <= 9)) {
                    buffer.append((char) ('0' + halfbyte));
                } else {
                    buffer.append((char) ('a' + (halfbyte - 10)));
                }
                halfbyte = data[i] & 0x0F;
            } while (two_halfs++ < 1);
        }
        return buffer.toString();
    }
}
