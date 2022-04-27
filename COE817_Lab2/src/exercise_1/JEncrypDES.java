package exercise_1;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;

public class JEncrypDES {
	//instance variables to be used and accessed later in methods
	private static SecretKey secKey;
	private static byte[] encrypted;
	private static byte[] decrypted;
	private static Cipher dciph;
	private static Cipher eciph;
	private static KeyGenerator keyGen;
	public static void Encrypt(String plaintext) {
		try {
			//keygenerator for generating keys
			keyGen = KeyGenerator.getInstance("DES");
			secKey = keyGen.generateKey();
			//cipher object to encrypt the key, get instance then initialize in encryption mode then encrypt using doFinal
			eciph = Cipher.getInstance("DES");
			eciph.init(Cipher.ENCRYPT_MODE, secKey);
			encrypted = eciph.doFinal(plaintext.getBytes());
			//print encrypted text
			System.out.println("Encoded Text: " + new String(encrypted, StandardCharsets.UTF_8));
			
		}catch(InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException e){
			System.out.println(e.getMessage());
		}
		
	}
	public static void Decrypt() {
		try{
			//cipher object to decrypt the key, get instance then initialize in decryption mode then decrypt using doFinal
			dciph = Cipher.getInstance("DES");
			dciph.init(Cipher.DECRYPT_MODE, secKey);
			decrypted = dciph.doFinal(encrypted);
			//print output of decryption
			System.out.println("Decrypted Text: " + new String(decrypted, StandardCharsets.UTF_8));
		}catch(InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException e) {
			System.out.println(e.getMessage());
		}
	}
	
	public static void main(String[] args) {
		//prompt user to type in "No body can see me" but any input text will work
		System.out.println("Please enter 'No body can see me'");
		//scanner to scan the input text from user and store in a variable
		Scanner sc = new Scanner(System.in);
		//create new object and initialize methods for encryption and decryption using the user input
		String userInput = sc.nextLine();
		JEncrypDES soup = new JEncrypDES();
		soup.Encrypt(userInput);
		soup.Decrypt();

	}

}
