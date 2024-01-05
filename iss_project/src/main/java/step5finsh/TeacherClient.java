package step5finsh;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Scanner;


public class TeacherClient {
    private static X509Certificate certificate;
    private static int SERVER_PORT = 1234;
    private static PublicKey certificateAuthorityPublicKey;
    static String nationalNumberSave;
    private static PublicKey serverPublicKey;
    private static SecretKey sessionKey;
    private static PrivateKey privateKey;

    public static void main(String[] args) {
        try {
            KeyPair clientKeyPair = generateKeyPair();
            privateKey = clientKeyPair.getPrivate();
            Socket socketCertificate = new Socket("localhost", 8080);

            HandshakeWithCertificate(socketCertificate, clientKeyPair);
            receiveCertificate(socketCertificate, clientKeyPair);
            boolean isVerified = verifySignatureForCertificate(certificate);
            System.out.println(isVerified ? "You are a doctor." : "You are not a doctor.");
            //////
            Scanner scanner=new Scanner(System.in);
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
            Socket socket = new Socket("127.0.0.1", SERVER_PORT);

            // Perform handshake with the server
            performHandshake(socket, clientKeyPair);
            //  Generate session key for this session
            sessionKey = generateSessionKey();
          //  displaySessionKey("Client Session Key:", sessionKey);
            sendSessionKey(socket);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

            // Connect to the server
            System.out.println("Connected to server: " + socket);

            // Read welcome message from server
            String message = in.readLine();
            System.out.println("Server: " + message);

            // Register or login as a teacher
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
                System.out.println("Choose an option:\n1. Add Data\n2. Add Data with session key\n3. Display Data\n4. send file with digital signature \n5. show my files\n6. exit");
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
                        sendFileWithDigitalSignature(socket); // Exit the loop and close the connection
                        break;
                    case "5":
                        sendFileToTeacher(socket);  // Exit the loop and close the connection
                        break;
                    case "6":
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

    private static void sendFileToTeacher(Socket socket) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
        ObjectOutputStream outputStream = new ObjectOutputStream(socket.getOutputStream());

        outputStream.writeObject(certificate);
        outputStream.writeObject(certificateAuthorityPublicKey);

        Object responseFromServer = ois.readObject();

        if ("try again".equals(responseFromServer)) {
            System.out.println("Signature verification failed on the server side. Retrying...");
            // You can implement retry logic here if needed.
        } else {
            List<String> receivedList = (List<String>) responseFromServer;
            openMyFile(receivedList);
            System.out.println("Received list: " + receivedList);
        }
    }



    private static void openMyFile(List<String> list) {
        // Print the list of requests
        for (String request : list) {
            System.out.println(request);

            File file = new File(request);

            // Check if the file exists and can be opened
            if (file.exists()) {
                try {
                    Desktop.getDesktop().open(file);  // Open the file
                    System.out.println("File opened successfully!");
                } catch (IOException e) {
                    System.out.println("Failed to open the file.");
                    e.printStackTrace();
                }
            } else {
                System.out.println("File does not exist on the desktop.");
            }
        }
    }

    private static void receiveCertificate(Socket socket, KeyPair keyPair) throws Exception {
        try (PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

            boolean isCertificateReceived = false;

            while (!isCertificateReceived) {
                // Send CSR to CA
                String csr = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
                out.println(csr);

                // Receive challenge from CA
                String challenge = in.readLine();
                System.out.println("Received challenge from CA: " + challenge);

                // Solve the math challenge
                int answer = solveMathChallenge();
                out.println(answer);

                // Receive response from CA
                String response = in.readLine();

                if ("Verification failed. Please try again.".equals(response)) {
                    System.out.println(response);
                    continue; // Retry the process
                }

                // Receive and save the digital certificate from CA
                String encodedCertificate = response; // Assuming the CA sends the certificate as a response
                System.out.println("Received encoded certificate from CA: " + encodedCertificate);

                // Decode the Base64 encoded certificate and save it
                byte[] decodedCertificateBytes = Base64.getDecoder().decode(encodedCertificate);
                certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                        .generateCertificate(new ByteArrayInputStream(decodedCertificateBytes));
                saveCertificate(certificate);
                System.out.println("Saved certificate: " + certificate);

                isCertificateReceived = true; // Set flag to true to exit the loop
            }
        }
    }


    private static int solveMathChallenge() {
        Scanner scanner = new Scanner(System.in);
        System.out.print("enter your result:");
        return scanner.nextInt();
    }

    private static void saveCertificate(X509Certificate certificate) throws IOException {
        try (FileOutputStream fos = new FileOutputStream("certificate.txt")) {
            fos.write(certificate.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        }
        System.out.println("Certificate saved to: certificate");
    }

    public static boolean verifySignatureForCertificate(X509Certificate certificate) throws Exception {
        // Extract the signature from the certificate
        byte[] signature = certificate.getSignature();

        // Create a signature verifier instance
        Signature verifier = Signature.getInstance("SHA256WithRSA");
        verifier.initVerify(certificateAuthorityPublicKey);
        verifier.update(certificate.getTBSCertificate()); // Using the TBSCertificate content for verification

        // Verify the signature
        return verifier.verify(signature);
    }

    private static void HandshakeWithCertificate(Socket socket, KeyPair serverKeyPair) throws Exception {
        System.out.println("call performHandshake");

        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());


        // Receive server public key
        certificateAuthorityPublicKey = (PublicKey) in.readObject();

        // Send client public key to the server
        out.writeObject(serverKeyPair.getPublic());


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
        // Send the role "teacher" to the server
        out.println("teacher");

        // Read response from server
        String message = in.readLine();
        System.out.println("Server: " + message);
        String nationalNumberSave = in.readLine();
        TeacherClient.nationalNumberSave = nationalNumberSave;
        System.out.println("Server say the : " + nationalNumberSave);
        return message.contains("Registration successful.");
    }

    private static boolean login(BufferedReader reader, BufferedReader in, PrintWriter out) throws IOException {
        System.out.println("Enter your username:");
        String username = reader.readLine();
        out.println(username);

        System.out.println("Enter your password:");
        String password = reader.readLine();
        out.println(password);
        out.println("teacher");
        // Read response from server
        String message = in.readLine();
        System.out.println("Server: " + message);
        if (message.equals("you can not login in this account because you are not a student") || message.equals("Invalid username or password."))
            return false;
        String nationalNumberSave = in.readLine();
        TeacherClient.nationalNumberSave = nationalNumberSave;
       // System.out.println("Server say the naaaaa: " + nationalNumberSave);
        return message.contains("Login successful as teacher.");
    }

    private static void sendFileWithDigitalSignature(Socket socket) throws Exception {

        File selectedFile = chooseFile();
        byte[] encryptedFileContent = encryptWithSessionKey(String.valueOf(selectedFile), sessionKey);
        byte[] signature = generateSignature(encryptedFileContent, privateKey);

        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());

        // Send encrypted file content and its signature to server
        out.writeObject(encryptedFileContent);
        out.writeObject(signature);

        ObjectInputStream confirmationIn = new ObjectInputStream(socket.getInputStream());
        String confirmationMessage = (String) confirmationIn.readObject();
        System.out.println("Server confirmation: " + confirmationMessage);
    }

    private static File chooseFile() {
        JFileChooser fileChooser = new JFileChooser();
        int returnValue = fileChooser.showOpenDialog(null);

        if (returnValue == JFileChooser.APPROVE_OPTION) {
            return fileChooser.getSelectedFile();
        }

        return null;  // Return null if no file was selected
    }

    private static byte[] generateSignature(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    private static void addData(BufferedReader reader, BufferedReader in, PrintWriter out) throws IOException {
        SecretKey secretKey;  // assuming this.name contains the national number
        try {
            secretKey = EncryptionUtils.generateSecretKey(TeacherClient.nationalNumberSave);
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

        System.out.println(decryptedData);
        // System.out.println(response);
        SecretKey secretKey;  // assuming this.name contains the national number
        try {
            secretKey = EncryptionUtils.generateSecretKey(TeacherClient.nationalNumberSave);
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
            System.out.println("with national number:\n" + response);

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

    private static void performHandshake(Socket socket, KeyPair serverKeyPair) throws Exception {

        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        // Receive server public key
        serverPublicKey = (PublicKey) in.readObject();
        // Send client public key to the server
        out.writeObject(serverKeyPair.getPublic());



    }

    private static KeyPair generateKeyPair() throws Exception {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
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
