package exercise_2;

import java.net.*;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;

public class Server extends Thread{
	public static void main(String [] args)
    {
        int portNumber = 15000;
        String ID = "RESPONDER B";
        String km = "NETWORK SECURITY";
        String ks = "RYERSON ";
        ServerSocket serverSocket;
        byte[] keyBytes, Output, Input = null, decryptedOutput;
        SecretKey secKey;
        Cipher desCipherObj ;
        SecretKeyFactory key;
        String message2;
       
        try
        { 
            // Creating the server socket with the predefined port
            serverSocket = new ServerSocket(portNumber);
            //Set timeout for the server 
            serverSocket.setSoTimeout(123456);
            System.out.println("SERVER Side of the application");
            // display waiting message for server side.
            System.out.println("Waiting for client To be connected  ...");

            // Listening for clients on the socket and print when client connects to the server
            Socket server = serverSocket.accept();
            System.out.println("Client connected to the server " + "\n");

            // Listen put input from client and print it out
            DataInputStream input = new DataInputStream(server.getInputStream());
            String clientID = input.readUTF();
            System.out.println("ID recieved(Message 1): " + clientID+ "\n");
            
            
            // sets the key generator to DES mode and generated the secret DES key
            key = SecretKeyFactory.getInstance("DES");
            secKey = key.generateSecret(new DESKeySpec(km.getBytes()));

           //Creates message 2 with space to sperate the key, IDA, and IDB and converts the string to bytes
            message2 = ks + "|" + clientID + "|" + ID;
            
            //get byte of message to encrypt the message 2
            Output = message2.getBytes();
            // get cipher instance.
            desCipherObj = Cipher.getInstance("DES/ECB/PKCS5Padding");
            
            // Encrypt message 2 to send to client using the DESkey and DES algorithm
            desCipherObj.init(Cipher.ENCRYPT_MODE, secKey);
            Output = desCipherObj.doFinal(Output);

            //Display the Encypterd Byte cipher and String format of the message 
            System.out.println("Encrypted byte code(Message 2): " + Output.toString());
            System.out.println("Encrypted string format(Message2): " + new String(Output)+ "\n");

            //Sending the encrypted text to the client
            DataOutputStream out = new DataOutputStream(server.getOutputStream());
            out.writeInt(Output.length);
            out.write(Output);
            
            //Recieve the cipher text message 3 from client side and display 
            int duration = input.readInt();
            // set an array to receive the Byte Stream of the message
            if(duration > 0) Input = new byte[duration];
            input.read(Input, 0, duration);
            System.out.println("cipher recieved as (Message 3): ");
            System.out.println("byte code of Message 3: " + Input.toString());
            System.out.println("string format: " + new String(Input) + "\n");
            
            //decode the cipher using the session key and set the algorithm to dECRPT TO DES
            keyBytes = ks.getBytes();
            key = SecretKeyFactory.getInstance("DES");
            secKey = key.generateSecret(new DESKeySpec(keyBytes));
            
            //reinitialize in decrytion mode and decrypting the message received from client
            desCipherObj.init(Cipher.DECRYPT_MODE, secKey);
 
            // decrypt the message and display on screen 
            decryptedOutput = desCipherObj.doFinal(Input);
            System.out.println("byte code Input" + decryptedOutput.toString()+"\n");
            System.out.println("string format Input: " +  new String(decryptedOutput) + "\n");
           
            //close the input and output as well as server socket after completion of the application
            input.close();
            out.close();
            server.close();
        }catch(SocketTimeoutException s){
            System.out.println("Socket timed out Error Try again!");

        }catch (IOException | NoSuchAlgorithmException | 
                NoSuchPaddingException | InvalidKeyException | 
                InvalidKeySpecException | IllegalBlockSizeException 
                | BadPaddingException e) {  
           System.out.println("Error related to crypto library Try Again! ");
           e.printStackTrace();
        }
    }
}
