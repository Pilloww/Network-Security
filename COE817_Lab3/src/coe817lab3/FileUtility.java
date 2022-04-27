/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package coe817lab3;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;


public class FileUtility {
   
    public static byte[] getFile(String filepath) {

        File f = new File(filepath).getAbsoluteFile();
        InputStream inputStream = null;
        try {
            inputStream = new FileInputStream(f);
        } catch (FileNotFoundException e2) {
            // TODO Auto-generated catch block
            e2.printStackTrace();
        }
        byte[] imageBytes = null;
        try {
            imageBytes = new byte[inputStream.available()];
        } catch (IOException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }
        try {
            inputStream.read(imageBytes);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return imageBytes;
    }
    
    public static void saveFile(byte[] bytes, String filepath) throws IOException {
        FileOutputStream fileOutput = new FileOutputStream(filepath);
        fileOutput.write(bytes);
        fileOutput.close();
    }
    
}
