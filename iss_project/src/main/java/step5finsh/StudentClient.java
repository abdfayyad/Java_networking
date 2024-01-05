package step5finsh;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Objects;
import java.util.Scanner;

public class StudentClient {
    private static final String SERVER_IP = "127.0.0.1";
    private static int SERVER_PORT = 1234;
    static String nationalNumberSave;
    private static PublicKey serverPublicKey;
    private static SecretKey sessionKey;


    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        try {

            while (true) {
                System.out.print("Enter the port number (1234 to connect): ");
                int port = Integer.parseInt(scanner.nextLine()); // Read input from user
                if (port!=1234){
                    System.out.println("Connection error: Invalid port number. Please enter 1234 to connect.");
                }else {
                    SERVER_PORT=port;
                    break;
                }
            }
            Socket socket = new Socket(SERVER_IP, SERVER_PORT);
            KeyPair clientKeyPair = generateKeyPair();

            // Perform handshake with the server
            performHandshake(socket, clientKeyPair);
            //  Generate session key for this session
            sessionKey = generateSessionKey();
            sendSessionKey(socket);
            //displaySessionKey("tesst_last_v.Client Session Key:", sessionKey);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            // Connect to the server
            System.out.println("Connected to server: " + socket);

            // Read welcome message from server
            String message = in.readLine();
            System.out.println("Server: " + message);

            // Register or login as a student
            boolean loggedIn = false;
            while (!loggedIn) {
                System.out.println("Choose an option:\n1. Register\n2. Login");
                String option = reader.readLine();

                switch (option) {
                    case "1":
                        out.println(option); // Role as student
                        loggedIn = register(reader, in, out);
                        break;
                    case "2":
                        out.println(option); // Role as student
                        loggedIn = login(reader, in, out);
                        break;
                    default:
                        System.out.println("Invalid option. Please try again.");
                        break;
                }
            }


            while (loggedIn) {
                System.out.println("Choose an option:\n1. Add Data\n2. Add Data With Session Key\n3. Display data \n4.exit");
                String choice = reader.readLine();
                out.println(choice);

                switch (choice) {
                    case "1":
                        addData(reader, in, out);
                        break;
                    case "2":
                        addDataWithSessionKey(reader, in, out, socket);
                        break;
                    case "3":
                        displayData(in, out, socket);
                        break;
                    case "4":
                        loggedIn = false; // Exit the loop and close the connection
                        break;
                    default:
                        System.out.println("Invalid option. Please try again .");
                        break;
                }
            }


            in.close();
            out.close();
            socket.close();

        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static boolean register(BufferedReader reader, BufferedReader in, PrintWriter out) throws IOException {
        System.out.println("Enter a username:");
        String username = reader.readLine();
        out.println(username);

        System.out.println("Enter a password:");
        String password = reader.readLine();
        out.println(password);

        System.out.println("Enter your national number:"); // Prompt for national number
        String nationalNumber = reader.readLine();
        out.println(nationalNumber);
        // Send the role "student" to the server
        out.println("student");

        // Read response from server
        String message = in.readLine();
        System.out.println("Server: " + message);
        String nationalNumberSave = in.readLine();
        StudentClient.nationalNumberSave = nationalNumberSave;
        System.out.println("Server say the naaa: " + nationalNumberSave);
        return message.contains("Registration successful.");
    }

    private static boolean login(BufferedReader reader, BufferedReader in, PrintWriter out) throws IOException {
        System.out.println("Enter your username:");
        String username = reader.readLine();
        out.println(username);

        System.out.println("Enter your password:");
        String password = reader.readLine();
        out.println(password);
        out.println("student");
        // Read response from server
        String message = in.readLine();
        System.out.println("Server: " + message);
        if (message.equals("you can not login in this account because you are not a teacher") || message.equals("Invalid username or password."))
            return false;
        String nationalNumberSave = in.readLine();
        StudentClient.nationalNumberSave = nationalNumberSave;
        System.out.println("Server say the naaaaa: " + nationalNumberSave);
        return message.contains("Login successful as student.");
    }

    private static void addData(BufferedReader reader, BufferedReader in, PrintWriter out) throws IOException {
        SecretKey secretKey;  // assuming this.name contains the national number
        try {
            secretKey = EncryptionUtils.generateSecretKey(StudentClient.nationalNumberSave);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        System.out.println("Enter the name of whatever you want to store :");
        String key = reader.readLine();
        String encryptedKey;
        try {
            encryptedKey = EncryptionUtils.encrypt(secretKey, key);
            // System.out.println(encryptedKey);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        out.println(encryptedKey);
        System.out.println("Enter value of the  " + key + " you entered in the text field above :");
        String value = reader.readLine();
        String encryptedValue;
        try {
            encryptedValue = EncryptionUtils.encrypt(secretKey, value);
            // System.out.println(encryptedValue);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        out.println(encryptedValue);
        // Read response from the server
        String message = in.readLine();
        System.out.println("Server: " + message);
    }

    private static void addDataWithSessionKey(BufferedReader reader, BufferedReader in, PrintWriter out, Socket socket) throws IOException {

        System.out.println("Enter the name of whatever you want to store :");
        String key = reader.readLine();
        byte[] encryptedRequest = new byte[0];
        try {
            encryptedRequest = encryptWithSessionKey(key, sessionKey);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        ObjectOutputStream outt = new ObjectOutputStream(socket.getOutputStream());
        outt.writeObject(encryptedRequest);
        System.out.println("Enter value of the  " + key + " you entered in the text field above :");
        String value = reader.readLine();
        byte[] encryptedRequest2 = new byte[0];
        try {
            encryptedRequest2 = encryptWithSessionKey(value, sessionKey);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        ObjectOutputStream outtt = new ObjectOutputStream(socket.getOutputStream());
        outtt.writeObject(encryptedRequest2);

        ObjectInputStream inn = new ObjectInputStream(socket.getInputStream());

        // Read response from the server
        byte[] encryptedResponse3 = new byte[0];
        try {
            encryptedResponse3 = (byte[]) inn.readObject();
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
        String message;
        try {
            message = decryptWithSessionKey(encryptedResponse3, sessionKey);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        System.out.println("Server: " + message);
    }

    private static void displayData(BufferedReader in, PrintWriter out, Socket socket) throws IOException, ClassNotFoundException {
        String decryptedData = in.readLine();

        // System.out.println(decryptedData);
        // System.out.println(response);
        SecretKey secretKey;  // assuming this.name contains the national number
        try {
            secretKey = EncryptionUtils.generateSecretKey(StudentClient.nationalNumberSave);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        String response = "";
        try {
            response = EncryptionUtils.decrypt(secretKey, decryptedData);
//            System.out.println(response);
        } catch (BadPaddingException e) {
            System.err.println("BadPaddingException: Incorrect padding. Ensure correct decryption key and padding scheme.");
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("Error occurred during decryption.");
            e.printStackTrace();
        }
        // Check if the response indicates an error or contains data
        if (Objects.equals(response, "")) {
            System.out.println("No data available.");
        } else {
            // Display the data received from the server
            System.out.println("Decrypted server response with national number:\n" + response);

        }
        ObjectInputStream inn = new ObjectInputStream(socket.getInputStream());

        byte[] encryptedResponse = (byte[]) inn.readObject();
        String decryptedResponse;
        try {
            decryptedResponse = decryptWithSessionKey(encryptedResponse, sessionKey);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        //  System.out.println(decryptedResponse);
        System.out.println("Decrypted server response wish session key: \n" + decryptedResponse);
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private static void performHandshake(Socket socket, KeyPair serverKeyPair) throws Exception {

        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

        // Receive server public key
        serverPublicKey = (PublicKey) in.readObject();

        // Send client public key to the server
        out.writeObject(serverKeyPair.getPublic());

    }

    private static SecretKey generateSessionKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    private static void displaySessionKey(String label, SecretKey sessionKey) {
        System.out.println(label + " " + sessionKey);
    }

    private static void sendSessionKey(Socket socket) throws Exception {
        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        // Encrypt the session key using the server's public key
        byte[] encryptedSessionKey = encryptWithPublicKey(sessionKey.getEncoded(), serverPublicKey);
        out.writeObject(encryptedSessionKey);
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        String message = in.readObject().toString();
        System.out.println("server say:" + message);
    }

    // Implement RSA encryption with the server's public key
    private static byte[] encryptWithPublicKey(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    private static byte[] encryptWithSessionKey(String data, SecretKey sessionKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey);
        return cipher.doFinal(data.getBytes());
    }

    // Assuming you have a method to decrypt data using AES
    private static String decryptWithSessionKey(byte[] encryptedData, SecretKey sessionKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, sessionKey);
        byte[] decryptedData = cipher.doFinal(encryptedData);
        return new String(decryptedData);
    }
}
