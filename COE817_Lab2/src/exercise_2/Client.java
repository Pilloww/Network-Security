package exercise_2;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;

public class Client {
	public static void main(String[] args)
    {
        //
        byte[] keyBytes, EOut, DOutput = null,InputMessage = null;
        String ID = "INITIATOR A";
        String km = "NETWORK SECURITY";
        //setting port number to be connected to server
        int portNumber = 15000;
        SecretKey secKey;
        Cipher desCipherObj = null;
        SecretKeyFactory key;
        String plaintext;
        
        try {
             System.out.println("CLIENT SIDE OF THE SYSTEM");
            // Create key out of the string "NETWORK SECURITY".
            // This uses the DESKeySpec to create a key from text.
            keyBytes =  km.getBytes();
            key = SecretKeyFactory.getInstance("DES");
            secKey = key.generateSecret(new DESKeySpec(keyBytes));
            
            // notify client of attempt to connect
            System.out.println("Connecting to Server");
        
            //Creating socket connection to connect to server and display message when connection was established
            Socket client = new Socket("localhost",portNumber);
            System.out.println("Connected to server successfully !" + "\n" );
            // Sending and displaying message 1 
            
            System.out.println("Sending Message 1: " + ID + "\n");
            
           // Creates input an output for sending information
            DataOutputStream out = new DataOutputStream(client.getOutputStream());
            
            //Sending client id (Message1)
            out.writeUTF(ID);
            
            DataInputStream input = new DataInputStream(client.getInputStream());
            
            //Recieve the cipher text message 2 from server
            int duration = input.readInt();
            
            //sets the key generator to DES mode and display the received message 2 in byte mode and string format
            if(duration > 0) InputMessage = new byte[duration];
            input.read(InputMessage, 0, duration);
            System.out.println("Received cipher text from Server (Message 2): \n");
            System.out.println("cipher byte code format of message 2: " + InputMessage.toString()+"\n");
            System.out.println("cipher string format of message 2: " + new String(InputMessage) + "\n");
            
            // Create DES Cipher instance for encryption/decryption. 
            desCipherObj = Cipher.getInstance("DES/ECB/PKCS5Padding");
            
            //Sets the cipher object ot decryption mode
            desCipherObj.init(Cipher.DECRYPT_MODE, secKey);
           
            // decrypt the message
            DOutput = desCipherObj.doFinal(InputMessage);
            
            //print to screen the decrypted message byte code and string format 
            System.out.println("Decrypted byte code message received from Server " + DOutput.toString()+"\n");
            System.out.println("Decrypted string format of message received from Server: " +  new String(DOutput) + "\n");
            
            
            // parse incoming ciphertext for session key using regex. to seperate key IDA and IDB 
            //where first element of the array is Key 2nd is IDA and last one is IDB
            String Text = new String(DOutput);
            String[] MessageArray = Text.split("\\|");
            keyBytes =  (MessageArray[0]+ " ").getBytes();
            
            //Sets the key generator in SecretKeyFactory to DES mode and generated the secret DES key 
            key = SecretKeyFactory.getInstance("DES");
            secKey = key.generateSecret(new DESKeySpec(keyBytes));
           
            // get host's ID from the decrpyted text.
            EOut = MessageArray[2].getBytes();
      
            //Sets the cipher object to encryption mode 
            desCipherObj.init(Cipher.ENCRYPT_MODE, secKey);
            EOut = desCipherObj.doFinal(EOut);
            
            //display message 3 being sent
            System.out.println("Session key is: " + MessageArray[0]);
            System.out.println("host ID is: " + MessageArray[2]);
            System.out.println("Sending Cipher (Message3) ...\n");
            
            //Send the encrypted text to the server
            out.writeInt(EOut.length);
            out.write(EOut);
            
            //close the input and output and socket when program executed successfuly
            input.close();
            out.close();
            client.close();   
         } catch(IOException | InvalidKeyException | NoSuchAlgorithmException |
                InvalidKeySpecException | IllegalBlockSizeException |
               BadPaddingException | NoSuchPaddingException ex) {
            System.out.println("Error has occured.");
            ex.printStackTrace();
        } 
    }
}
