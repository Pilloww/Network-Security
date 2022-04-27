/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package coe817lab3;


import java.io.*;
import java.net.*;
import javax.crypto.*;


public class ClientSide {
    
    public static void main(String[] args)
    {
        byte[]  cipherSent, cipherRecieved = null, 
                decryptedOutput = null;
        String id = "INITIATOR A";
        String host = "localhost";
        String PU_b = "NETWORK SECURITY";
        String K_s = "TRISTANCOLLLINGS";
        String filePath = "C:\\Users\\hihim\\OneDrive\\Desktop\\w2022labs\\coe 817 labs\\COE817-Lab3\\src\\coe817lab3\\client_files"
                + "\\Quiet-NASA-Transpo.jpg";
        int port = 5001;
        SecretKey sessionKey;
        SecretKey PUb;
        String plainText;
        int nonceSent, nonceRecieved, nonceTemp;
        byte[] plainBytes;
        
        try {
             System.out.println("CLIENT");
            // Create key out of the string "NETWORK SECURITY".
            // This uses the DESKeySpec to create a key from text.
            PUb = KeyUtility.getKey(PU_b);
            // Generate Nonce.
            nonceSent = KeyUtility.getNonce();
            // notify client of attempt to connect
            System.out.println("Connecting to " + host
                    + " on port " + port);
            // attempt the connection to socket.
            Socket client = new Socket(host, port);
            //report connection success to client.
            System.out.println("Connected to "
                    + client.getRemoteSocketAddress() +" success!" + "\n" );
            // print ID message sent.
            System.out.println("Sending client ID and nonce encrypted with B's"
                    + " public key PU_b " + "to host: \n"
                    + "Nonce Generated: " + nonceSent + "\n"
                            + "Client Id: " + id + " \n");
            // send ID to host.
            DataOutputStream out =
                    new DataOutputStream(client.getOutputStream());
            plainText = nonceSent + "|" + id;
            cipherSent = KeyUtility.getDESCipher(PUb, 
                    plainText.getBytes());
            // send initial message.
            KeyUtility.printMessageSent(plainText, cipherSent);
            out.writeInt(cipherSent.length);
            out.write(cipherSent);
            
//-------------RECIEVE CIPHER FROM HOST THAT CONTAINS Nonces---------------
            //Recieve cipher from host.
            DataInputStream in =
                        new DataInputStream(client.getInputStream());
            // Read in length of incoming bytes.
            int duration = in.readInt();
            // initialize byte array to contain incoming byte stream.
            if(duration > 0) cipherRecieved = new byte[duration];
            in.read(cipherRecieved, 0, duration);
            
            // print encrypted cipher message to standardout.
            KeyUtility.printRecievedCipher(cipherRecieved);
            // print decrypted message to standardout
            decryptedOutput = KeyUtility.getPlainBytesDES(PUb, cipherRecieved);
            KeyUtility.printRecievedDecryption(decryptedOutput);
            
//-----------Using recieved Nonce to send back for authorization ---------------
            // parse incoming ciphertext for session key using regex.
            plainText = new String(decryptedOutput);
            String[] decryptedArray = plainText.split("\\|");

            // get host's nonce from the decrpyted text.
            nonceRecieved = Integer.parseInt(decryptedArray[1]);
            // get authorization nonce;
            nonceTemp = Integer.parseInt(decryptedArray[0]);
            if(KeyUtility.confirmNonce(nonceSent, nonceTemp)){
                // send to client the length of cipher in bytes, then the cipher
                System.out.println("Send Nonce recieved from host for "
                    + "idenitifaction encrypted using PU_b\n");
                cipherSent = KeyUtility.getDESCipher(PUb, 
                        decryptedArray[1].getBytes());
                KeyUtility.printMessageSent((String)decryptedArray[1], 
                        cipherSent);
                out.writeInt(cipherSent.length);
                out.write(cipherSent);
            }else { return;}     
////-----------------Send the encrypted secret key. ----------------------------
            
            // Create key out of the string recieved session key.
            // This uses the DESKeySpec to create a key from text.
            sessionKey = KeyUtility.getKey((K_s));
            cipherSent = KeyUtility.getDESCipher(PUb, K_s.getBytes());
            // send to client the length of cipher in bytes, then the cipher.
            System.out.println("Send secret session key which is a DES key"
                    + " created from the string TRISTANCOLLINGS\n");
            KeyUtility.printMessageSent(K_s, 
                        cipherSent);
            out.writeInt(cipherSent.length);
            out.write(cipherSent);
//----------------------session chat messages example --------------------------
            String greetingMessage = "Hello how are you?";
            nonceSent = KeyUtility.getNonce();
            greetingMessage = greetingMessage + "|" + nonceSent;
            cipherSent = KeyUtility.getDESCipher(sessionKey, 
                    greetingMessage.getBytes());
            KeyUtility.printMessageSent(greetingMessage, cipherSent);
            out.writeInt(cipherSent.length);
            out.write(cipherSent);
//-------------------- Chat instances example-----------------------------------
            duration = in.readInt();
            // initialize byte array to contain incoming byte stream.
            if(duration > 0) cipherRecieved = new byte[duration];
            in.read(cipherRecieved, 0, duration);
            // print encrypted cipher recieved.
            KeyUtility.printRecievedCipher(cipherRecieved);
            plainBytes = KeyUtility.getPlainBytesDES(sessionKey, 
                    cipherRecieved);
            KeyUtility.printRecievedDecryption(plainBytes);
            
            //parse incoming ciphertext for session key using regex.
            plainText = new String(plainBytes);
            decryptedArray = plainText.split("\\|");
            // Create key out of the string recieved session key.
            // This uses the DESKeySpec to create a key from text.
            System.out.println("Extracted Host Nonce: " + 
                    decryptedArray[1] + "\n" + "Extracted authorization Nonce:"
                            + decryptedArray[2]);
            System.out.println("Extracted Client Message: " + decryptedArray[0] 
                    + "\n");
            nonceRecieved = Integer.parseInt(decryptedArray[1]);
            nonceTemp = Integer.parseInt(decryptedArray[2]);
            String hostMessage = decryptedArray[0];
            KeyUtility.confirmNonce(nonceTemp, nonceSent);
//-------------------------- Send encrypted image ------------------------------
            FileInputStream file = new FileInputStream(filePath);
            byte[] buffer = new byte [1024];
            int i = 0;
             while((duration=file.read(buffer)) != -1) {
                i += 1;
            }
            file.close();
            file = new FileInputStream(filePath);
            System.out.println("The number of packets to be sent are:" + i);
            out.writeInt(i);
            while((duration=file.read(buffer)) != -1) {
                System.out.println("coe817lab3.ClientSide.main()");
                cipherSent = KeyUtility.getDESCipher(sessionKey, 
                    buffer);
                KeyUtility.printMessageSent("Buffer: " + i + "\n", cipherSent);
                out.writeInt(cipherSent.length);
                out.write(cipherSent);
            }
//-------------------------------close all connections--------------------------
            in.close();
            out.close();
            client.close(); 
//-------------------------------close all connections--------------------------

         } catch(IOException ex) {
            System.out.println("Error has during client proccess occured.");
            ex.printStackTrace();
        } 
    }
}
