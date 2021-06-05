package com.company;

import javax.crypto.Cipher;
import java.io.*;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.List;

import static java.nio.charset.StandardCharsets.UTF_8;

public class Decrypt {

    private static final String fileBasePath = "D:\\dev\\java\\sscw2final\\resources";

    public static void main(String[] args)  {

        String keysFilename;
        String sourceFileName;
        String destinationFileName;

        try{

            keysFilename = args[0];
            sourceFileName = args[1];
            destinationFileName = args[2];

            String cipherText = fileRead(sourceFileName);
            KeyPair keyPair = getKeyPairFromKeyStore(keysFilename);
            String decryptedText = decrypt(cipherText, keyPair.getPrivate());
            fileWrite(destinationFileName,decryptedText);

        }catch (ArrayIndexOutOfBoundsException boundsException){
            System.out.println(boundsException.getMessage());
            boundsException.fillInStackTrace();

        } catch (Exception ex) {

            System.out.println(ex.getStackTrace());
        }

    }

    public static KeyPair getKeyPairFromKeyStore(String keyFileName) throws Exception {


        InputStream ins =  new FileInputStream(fileBasePath+"\\"+keyFileName);

        String alias = "buminduskey";
        String keypwd = "bumindu97";


        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(ins, keypwd.toCharArray());
        KeyStore.PasswordProtection keyPassword =
                new KeyStore.PasswordProtection(keypwd.toCharArray());

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, keyPassword);

        java.security.cert.Certificate cert = keyStore.getCertificate(alias);
        PublicKey publicKey = cert.getPublicKey();
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();

        return new KeyPair(publicKey, privateKey);

    }


    public static String decrypt(String cipherText, PrivateKey privateKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText.trim());

        Cipher decriptCipher = Cipher.getInstance("RSA");

        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(decriptCipher.doFinal(bytes), UTF_8);
    }



    public static  void fileWrite(String filename,String decryptedText) throws Exception{

        FileWriter fileWriter = new FileWriter(fileBasePath+"\\"+filename);

        BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);

        bufferedWriter.write(decryptedText);

        bufferedWriter.close();


    }

    public static String fileRead(String filename) throws Exception{

        FileReader fileReader = new FileReader(fileBasePath+"\\"+filename);

        BufferedReader bufferedReader = new BufferedReader(fileReader);

        String text ="";
        String para = "";

        while((text=bufferedReader.readLine())!=null){
            para += text + " ";
        }

        bufferedReader.close();
        return para;
    }

}
