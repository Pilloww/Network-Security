/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package coe817lab3;

import java.net.*;
import java.io.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.*;

public class ServerSide {
    
    public static void main(String [] args)
    {
        int port = 5001;
        String id = "RESPONDER B";
        String PU_a = "NETWORK SECURITY";
        String ks = "TRISTANCOLLINGS";
        int nonceSent;
        int nonceRecieved;
        ServerSocket serverSocket;
        byte[] cipherSent, cipherRecieved = null, decryptedOutput;
        SecretKey PUa;
        SecretKey sessionKey;
        String plainText;
        byte[] plainBytes;
        FileUtility fu = new FileUtility();
        String clientID;
        String clientMessage;
        try { 
// Setup initial socket connection and recieve requests from clients, 
// recieve ID and nonce.
            System.out.println("SERVER");
            // reserve socket and set timeout to ensure socket is closed.
            serverSocket = new ServerSocket(port);
            serverSocket.setSoTimeout(100000);
            // display waiting message for server side.
            System.out.println("Waiting for client on port " +
            serverSocket.getLocalPort() + "...");

            // Print when client connects to socket.
            Socket server = serverSocket.accept();
            // Print when client connects to socket.
            System.out.println("Connected to "
                    + server.getRemoteSocketAddress()+ "\n");

            // Print recieved input stream from socket.
            DataInputStream in =
                    new DataInputStream(server.getInputStream());
             int duration = in.readInt();
            // initialize byte array to contain incoming byte stream.
            if(duration > 0) cipherRecieved = new byte[duration];
            in.read(cipherRecieved, 0, duration);
            // print encrypted cipher recieved.
            KeyUtility.printRecievedCipher(cipherRecieved);
            PUa = KeyUtility.getKey(PU_a);
            plainBytes = KeyUtility.getPlainBytesDES(PUa, 
                    cipherRecieved);
            KeyUtility.printRecievedDecryption(plainBytes);
            
            //parse incoming ciphertext for session key using regex.
            plainText = new String(plainBytes);
            String[] decryptedArray = plainText.split("\\|");
            // Create key out of the string recieved session key.
            // This uses the DESKeySpec to create a key from text.
            System.out.println("Extracted Nonce: " + decryptedArray[0]);
            System.out.println("Extracted Client ID: " + decryptedArray[1] + 
                    "\n");
            nonceRecieved = Integer.parseInt(decryptedArray[0]);
            clientID = decryptedArray[1];
            
 // Generate Nonce N2, and send to client the encrypted output from step 2.
            nonceSent = KeyUtility.getNonce();
            plainText = nonceRecieved + "|" + nonceSent;
            System.out.println("Sending client's nonce and host's nonce"
                    + " encrypted with public key PU_a " + "to client: \n"
                    + "Nonce Generated: " + nonceSent + "\n");
            plainBytes = plainText.getBytes();
            
            cipherSent = KeyUtility.getDESCipher(PUa, plainBytes);
            KeyUtility.printMessageSent(plainText, cipherSent);
            
             DataOutputStream out =
                new DataOutputStream(server.getOutputStream());
            out.writeInt(cipherSent.length);
            out.write(cipherSent);

// Recieve an authorization nonce from the client which confirms identity-------
            duration = in.readInt();
            // initialize byte array to contain incoming byte stream.
            if(duration > 0) cipherRecieved = new byte[duration];
            in.read(cipherRecieved, 0, duration);
            // print encrypted cipher recieved.
            KeyUtility.printRecievedCipher(cipherRecieved);
            plainBytes = KeyUtility.getPlainBytesDES(PUa, 
                    cipherRecieved);
            KeyUtility.printRecievedDecryption(plainBytes);
            nonceRecieved = Integer.parseInt(new String (plainBytes));
            if(KeyUtility.confirmNonce(nonceSent, nonceRecieved)){
                // send to client the session key.
            }else { return;}
//-----------Using recieved Nonce to send back for authorization ---------------
            duration = in.readInt();
            // initialize byte array to contain incoming byte stream.
            if(duration > 0) cipherRecieved = new byte[duration];
            in.read(cipherRecieved, 0, duration);
            // print encrypted cipher recieved.
            KeyUtility.printRecievedCipher(cipherRecieved);
            plainBytes = KeyUtility.getPlainBytesDES(PUa, 
                    cipherRecieved);
            plainText = new String(plainBytes);
            sessionKey = KeyUtility.getKey(plainText);
            KeyUtility.printRecievedDecryption(plainBytes);
            System.out.println("The secret session key has been created.");
            System.out.println("Ready for communication....\n");
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
            System.out.println("Extracted Nonce: " + decryptedArray[1]);
            System.out.println("Extracted Client Message: " + decryptedArray[0] 
                    + "\n");
            nonceRecieved = Integer.parseInt(decryptedArray[1]);
            clientMessage = decryptedArray[0];
//----------------------session chat response messages example ----------------
            String greetingMessage = "I am fine thank you for asking!";
            nonceSent = KeyUtility.getNonce();
            greetingMessage = greetingMessage + "|" + nonceSent + "|" + 
                    nonceRecieved;
            cipherSent = KeyUtility.getDESCipher(sessionKey, 
                    greetingMessage.getBytes());
            KeyUtility.printMessageSent(greetingMessage, cipherSent);
            out.writeInt(cipherSent.length);
            out.write(cipherSent);
// ---------------------------------------------------------------------------//
            int numberOfPackets = in.readInt();
            System.out.println("The number of incoming packets are " + 
                    numberOfPackets);
            System.out.println(numberOfPackets);
            int i = 0;
            int buffersize = 0;
            while(i <= numberOfPackets){
                buffersize = in.readInt();
                System.out.println(buffersize);
                if(buffersize > 0) cipherRecieved = new byte[buffersize];
                in.read(cipherRecieved, 0, buffersize);
                // print encrypted cipher recieved.
                KeyUtility.printRecievedCipher(cipherRecieved);
                plainBytes = KeyUtility.getPlainBytesDES(sessionKey, 
                    cipherRecieved);
                KeyUtility.printRecievedDecryption(plainBytes);
                i += 1;
            }
           
//------------------------------------------------------------------------------
// Recieve an authorization nonce from the client which confirms identity------
            // Create DES key for encryption using Km = "NETWORK SECURITY".
            // This uses the DESKeySpec to create a key from text.
//            PUa = KeyUtility.getKey(PUa);
//
//            //create plaintext version of message to be encrypted. 
//            plaintext = ks + "|" + clientID + "|" + id;
//            System.out.println("Encrypting and sending the following: " +
//                    plaintext);
//            
//            encryptedOutput = plaintext.getBytes();
//            // get cipher instance.
//            encryptedOutput = KeyUtility.getDESCipher(PUa, encryptedOutput);
//
//            //Display on server side the encrypted Cipher.
//            System.out.println("Sending Encrypted byte code " + 
//                    encryptedOutput.toString());
//            System.out.println("Sending Encrypted string format: " + 
//                    new String(encryptedOutput)+ "\n");
//
//            // send length of ciphertext in bytes, followed by ciphertext.
//            DataOutputStream out =
//                new DataOutputStream(server.getOutputStream());
//            out.writeInt(encryptedOutput.length);
//            out.write(encryptedOutput);
            
 //----------------RECIEVE CLIENT'S CIPHER WHEN SESSION KEY IS USED-------------
//            // recieve the cipher text. 
//            int duration = in.readInt();
//            // initialize byte array to contain incoming byte stream.
//            if(duration > 0) encryptedInput = new byte[duration];
//            in.read(encryptedInput, 0, duration);
//            // print encrypted cipher recieved.
//            KeyUtility.printRecievedCipher(encryptedInput);
//            
//            // use session key RYERSON to unlock client's cipher.
//            PUa = KeyUtility.getKey(ks);
//            
//           System.out.println("Decrypting Recieced Cipher ...");
//            // decrypt the message
//            decryptedOutput = KeyUtility.getPlainBytesDES(PUa, encryptedInput);
//            //print to screen the decrypted message byte code.
//            System.out.println("Decrypted byte code " + 
//                    decryptedOutput.toString());
//            System.out.println("Decrypted string format: " + 
//                    new String(decryptedOutput) + "\n");
            
            in.close();
            out.close();
            server.close();
        }catch(SocketTimeoutException s){
            System.out.println("Socket timed out!");
        }catch (IOException e) {  
           System.out.println("Error related to crypto library! ");
           e.printStackTrace();
        }
    }
}