package exercise_1;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;

public class JEncrypRSA {
	//instance variables to be used and accessed later in the methods
	private static PrivateKey privatekey;
	private static PublicKey publickey;
	private static KeyPairGenerator keyGen;
	private static KeyPair keypair;
	private static Cipher dciph;
	private static Cipher eciph;
	private static byte[] encrypted;
	private static byte[] decrypted;
	public static void Encrypt(String plaintext) {
		try {
			//keygenerator for generating keys, the use keygen to generate a pair of keys: the private and public keys
			keyGen = KeyPairGenerator.getInstance("RSA");
			keypair = keyGen.generateKeyPair();
			privatekey = keypair.getPrivate();
			publickey = keypair.getPublic();
			//cipher object to encrypt the key, get the instance then initialize in encryption mode before encrypting
			eciph = Cipher.getInstance("RSA");
			eciph.init(Cipher.ENCRYPT_MODE, publickey);
			encrypted = eciph.doFinal(plaintext.getBytes());
			//print encrypted text 
			System.out.println("Encoded Text: " + new String(encrypted, StandardCharsets.UTF_8));
			
		}catch(InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException e){
			System.out.println(e.getMessage());
		}
	}
	public static void Decrypt() {
		try{
			//get instance, then initialize cipher in decryption mode before decrypting
			dciph = Cipher.getInstance("RSA");
			dciph.init(Cipher.DECRYPT_MODE, privatekey);
			decrypted = dciph.doFinal(encrypted);
			//print decrypted text
			System.out.println("Decrypted Text: " + new String(decrypted, StandardCharsets.UTF_8));
		}catch(InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException e) {
			System.out.println(e.getMessage());
		}
	}		
	// main method
	public static void main(String[] args) {
		//prompt user to type in "No body can see me" but any input text will work
		System.out.println("Please enter 'No body can see me'");
		//scanner to scan the input text from user and store in a variable
		Scanner sc = new Scanner(System.in);
		String userInput = sc.nextLine();
		//create new object and initialize methods for encryption and decryption using the user input
		JEncrypRSA soup = new JEncrypRSA();
		soup.Encrypt(userInput);
		soup.Decrypt();

	}
}
