/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package coe817.lab1;

import java.security.*;
import javax.crypto.*;

public class COE817Lab1 {

    SecretKey key;
    
    public static void main(String[] args) {
            
    }

    public COE817Lab1() {
        this.key = KeyGenerator.getInstance("DES").generateKey();
    }
    
}
