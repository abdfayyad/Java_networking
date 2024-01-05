package step5finsh;


import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.*;

public class Server {
    private static final int PORT = 1234;
    private static final String ACCOUNTS_FILE = "accounts.txt";
    // private static HashMap<String, String> accounts = new HashMap<>();
    private static List<User> accounts = new ArrayList<>();
    private static PublicKey clientPublicKey;
    private static SecretKey sessionKey;
    private static KeyPair serverKeyPair;
    private static X509Certificate certificate;
    private  static  PublicKey certificateAuthorityPublicKey;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) {
        loadAccounts();

        try {


            ServerSocket serverSocket = new ServerSocket(PORT);
            System.out.println("tesst_last_v.Server started on port " + PORT);

            while (true) {
                Socket clientSocket = serverSocket.accept();
                //performHandshake(clientSocket, clientKeyPair);

                System.out.println("New client connected: " + clientSocket);
                // Generate key pair for the server
                serverKeyPair = generateKeyPair();

                // Perform handshake with the client
                performHandshake(clientSocket, serverKeyPair);

                receiveSessionKey(clientSocket);

//
                ClientHandler clientHandler = new ClientHandler(clientSocket);
                clientHandler.start();


            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static class ClientHandler extends Thread {
        private Socket clientSocket;
        private BufferedReader in;
        private PrintWriter out;
        private String name; // To store the name of the logged-in or registered user
        String rolee;
        String nationalNumber;

        public ClientHandler(Socket socket) {
            this.clientSocket = socket;
        }

        public void run() {
            try {
                in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                out = new PrintWriter(clientSocket.getOutputStream(), true);


                out.println("Welcome to the server!");

                // Register or login
                boolean loggedIn = false;
                while (!loggedIn) {
                    //out.println("Choose an option:\n1. Register\n2. Login\n3. Exit");
                    String option = in.readLine();
                    switch (option) {
                        case "1":
                            loggedIn = register();
                            break;
                        case "2":
                            loggedIn = login();
                            break;
                        default:
                            out.println("Invalid option. Please try again.");
                            break;
                    }
                }

                while (loggedIn) {

                    String choice = in.readLine();

                    switch (choice) {
                        case "1":
                            addData();
                            break;
                        case "2":
                            addDataWithSessionKey();
                            break;
                        case "3":
                            displayData();
                            break;
                        case "4":
                            if (Objects.equals(this.rolee, "teacher")) {
                                receivedFileWithDigitalSignature(clientSocket);
                                //sendFileToTeacher(clientSocket);
                                break;
                            } else {
                                loggedIn = false;  // Exit the loop and close the connection
                                break;
                            }
                        case "5":
                            if (Objects.equals(this.rolee, "teacher")) {
                                sendFileToTeacher(clientSocket);
                                break;
                            } else {
                                System.out.println("Invalid option. Please try again .");
                                break;
                            }
                        case "6":
                            if (Objects.equals(this.rolee, "teacher")) {
                                loggedIn = false;
                                break;
                            } else {
                                System.out.println("Invalid option. Please try again .");
                                break;
                            }
                        default:
                            System.out.println("Invalid option. Please try again .");
                            break;
                    }
                }


                in.close();
                out.close();
                clientSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        private boolean register() throws IOException {
            String name = in.readLine();
            String password = in.readLine();
            String nationalNumber = in.readLine(); // Read national number
            String role = in.readLine();

            for (User user : accounts) {
                if (user.name.equals(name)) {
                    out.println("Username already exists. Please choose a different username.");
                    return false;
                }
            }

            User newUser = new User(name, password, nationalNumber, role);
            accounts.add(newUser);

            try (FileWriter writer = new FileWriter(ACCOUNTS_FILE, true);
                 BufferedWriter bw = new BufferedWriter(writer);
                 PrintWriter out = new PrintWriter(bw)) {
                out.println(name + "," + password + "," + nationalNumber + "," + role);
            } catch (IOException e) {
                e.printStackTrace();
                out.println("Error occurred while registering. Please try again.");
            }
            try (FileWriter writer = new FileWriter("publicClient.txt", true);
                 BufferedWriter bw = new BufferedWriter(writer);
                 PrintWriter out = new PrintWriter(bw)) {
                out.println(name + "," + clientPublicKey);
            } catch (IOException e) {
                e.printStackTrace();
                out.println("Error occurred while registering. Please try again.");
            }
            out.println("Registration successful.");
            this.name = name;
            this.nationalNumber = nationalNumber + "0000000000";
            this.rolee = role;
            out.println(nationalNumber);
          //  System.out.println(nationalNumber);
            return true;
        }


        private boolean login() throws IOException {
            String name = in.readLine();
            String password = in.readLine();
            String role = in.readLine();
            for (User user : accounts) {
                if (user.name.equals(name) && user.password.equals(password) && !user.role.equals(role)) {
                    out.println("you can not login in this account because you are not a " + user.role);
                    return false;
                }

            }
            for (User user : accounts) {
                if (user.name.equals(name) && user.password.equals(password) && user.role.equals(role)) {
                    out.println("Login successful as " + user.role + ".");
                    try (FileWriter writer = new FileWriter("publicClient.txt", true);
                         BufferedWriter bw = new BufferedWriter(writer);
                         PrintWriter out = new PrintWriter(bw)) {
                        out.println(name + "," + clientPublicKey);
                    } catch (IOException e) {
                        e.printStackTrace();
                        out.println("Error occurred while registering. Please try again.");
                    }
                    this.name = name;
                    nationalNumber = user.nationalNumber + "0000000000";
                    rolee = user.role;
                    out.println(nationalNumber);
                    System.out.println(nationalNumber);
                    return true;
                }
            }
            System.out.println(nationalNumber);
            out.println("Invalid username or password.");
            return false;
        }

        private void addData() throws IOException {
            SecretKey secretKey;  // assuming this.name contains the national number
            try {
                secretKey = EncryptionUtils.generateSecretKey(this.nationalNumber);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
//            out.println("Enter the key:");
            String key = in.readLine();
            String responseKey = "";
            try {
                responseKey = EncryptionUtils.decrypt(secretKey, key);
//            System.out.println(response);
            } catch (BadPaddingException e) {
                System.err.println("BadPaddingException: Incorrect padding. Ensure correct decryption key and padding scheme.");
                e.printStackTrace();
            } catch (Exception e) {
                System.err.println("Error occurred during decryption.");
                e.printStackTrace();
            }
//            out.println("Enter the value:");
            String value = in.readLine();
            String responseValue = "";
            try {
                responseValue = EncryptionUtils.decrypt(secretKey, value);
//            System.out.println(response);
            } catch (BadPaddingException e) {
                System.err.println("BadPaddingException: Incorrect padding. Ensure correct decryption key and padding scheme.");
                e.printStackTrace();
            } catch (Exception e) {
                System.err.println("Error occurred during decryption.");
                e.printStackTrace();
            }
            try (FileWriter writer = new FileWriter("data.txt", true);
                 BufferedWriter bw = new BufferedWriter(writer);
                 PrintWriter fileOut = new PrintWriter(bw)) {
                fileOut.println(this.name + "," + responseKey + "," + responseValue);  // Storing user's name, key, and value
            } catch (IOException e) {
                e.printStackTrace();
                out.println("Error occurred while storing data. Please try again.");
            }
            //rewriteFile();
            out.println("Data stored successfully for " + this.name);
        }

        private void addDataWithSessionKey() throws IOException {


            ObjectInputStream inn = new ObjectInputStream(clientSocket.getInputStream());

            byte[] encryptedResponse = new byte[0];
            try {
                encryptedResponse = (byte[]) inn.readObject();
            } catch (ClassNotFoundException e) {
                throw new RuntimeException(e);
            }
            String decryptedResponseKey;
            try {
                decryptedResponseKey = decryptWithSessionKey(encryptedResponse, sessionKey);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            ObjectInputStream inn2 = new ObjectInputStream(clientSocket.getInputStream());
            byte[] encryptedResponse2 = new byte[0];
            try {
                encryptedResponse2 = (byte[]) inn2.readObject();
            } catch (ClassNotFoundException e) {
                throw new RuntimeException(e);
            }
            String decryptedResponseValue;
            try {
                decryptedResponseValue = decryptWithSessionKey(encryptedResponse2, sessionKey);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            try (FileWriter writer = new FileWriter("data.txt", true);
                 BufferedWriter bw = new BufferedWriter(writer);
                 PrintWriter fileOut = new PrintWriter(bw)) {
                fileOut.println(this.name + "," + decryptedResponseKey + "," + decryptedResponseValue);  // Storing user's name, key, and value
            } catch (IOException e) {
                e.printStackTrace();
                byte[] encryptedRequest4 = new byte[0];
                try {
                    encryptedRequest4 = encryptWithSessionKey("Error occurred while storing data. Please try again.", sessionKey);
                } catch (Exception ee) {
                    throw new RuntimeException(ee);
                }
                ObjectOutputStream outt = new ObjectOutputStream(clientSocket.getOutputStream());
                outt.writeObject(encryptedRequest4);
                out.println();
            }
            //rewriteFile();
            byte[] encryptedRequest3 = new byte[0];
            try {
                encryptedRequest3 = encryptWithSessionKey("Data stored successfully for " + this.name + " using session key ", sessionKey);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            ObjectOutputStream outt = new ObjectOutputStream(clientSocket.getOutputStream());
            outt.writeObject(encryptedRequest3);
        }


        private void displayData() throws IOException {
            StringBuilder dataToSend = new StringBuilder();  // StringBuilder to concatenate lines

            try (BufferedReader reader = new BufferedReader(new FileReader("data.txt"))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.split(",");
                    if (parts.length >= 1 && parts[0].equals(this.name)) {
                        dataToSend.append("").append(parts[1]).append(": ").append(parts[2]).append("\n");
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
                out.println("Error occurred while displaying data. Please try again.");
                return;  // Exit method if there's an error
            }
            String dataToSend2 = String.valueOf(dataToSend);
            //out.println(dataToSend2);
            SecretKey secretKey;  // assuming this.name contains the national number
            try {
                secretKey = EncryptionUtils.generateSecretKey(this.nationalNumber);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            String encryptedData;
            try {
                encryptedData = EncryptionUtils.encrypt(secretKey, dataToSend2);
                //System.out.println(encryptedData);

            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            out.println(encryptedData);
            System.out.println(encryptedData);
//////////////////////////////////////////////////////////////////////////////////////////

            byte[] encryptedRequest = new byte[0];
            try {
                encryptedRequest = encryptWithSessionKey(dataToSend2, sessionKey);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
            out.writeObject(encryptedRequest);
            System.out.println(encryptedRequest.toString());
            // byte[] encryptedResponse = (byte[]) inn.readObject();
            String decryptedResponse;
            try {
                decryptedResponse = decryptWithSessionKey(encryptedRequest, sessionKey);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

        }

    }

    private static void receivedFileWithDigitalSignature(Socket socket) throws Exception {
        System.out.println("Server is ready to receive a file.");

        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        byte[] encryptedFileContent = (byte[]) in.readObject();
        byte[] receivedSignature = (byte[]) in.readObject();

        if (verifySignature(encryptedFileContent, receivedSignature, clientPublicKey)) {
            String decryptedFileContent = decryptWithSessionKey(encryptedFileContent, sessionKey);
            System.out.println(decryptedFileContent);
            // Save the received file content to a file
            //saveFile(decryptedFileContent);
            storeMessageInFile(decryptedFileContent);
            ObjectOutputStream confirmationOut = new ObjectOutputStream(socket.getOutputStream());
            confirmationOut.writeObject("File received and saved successfully.");
        } else {
            System.out.println("Signature verification failed!");
        }
    }

    private static void storeMessageInFile(String request) {
        String id = generateUniqueID();
        Instant timestamp = Instant.now();
        String fileName = "stored_requests.txt";

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(fileName, true))) {
            writer.write("ID: " + id + "\n");
            writer.write("Timestamp: " + timestamp.toString() + "\n");
            writer.write("Request: ");
            writer.write(request + "\n");
            writer.write("\n");  // Add a separator between entries

            System.out.println("Request stored in file with ID: " + id);
        } catch (IOException e) {
            System.err.println("Error writing to file: " + e.getMessage());
        }
    }

    private static boolean verifySignature(byte[] data, byte[] signatureToVerify, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureToVerify);
    }


    private static String generateUniqueID() {
        return UUID.randomUUID().toString();  // Generate a unique ID
    }

    private static KeyPair generateKeyPair() throws Exception {
        //System.out.println("call generateKeyPair");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private static void performHandshake(Socket socket, KeyPair clientKeyPair) throws Exception {
        // System.out.println("call performHandshake");

        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());


        // Send client public key to the server
        out.writeObject(clientKeyPair.getPublic());

        // Receive server public key
        clientPublicKey = (PublicKey) in.readObject();
        // System.out.println(clientPublicKey);


    }

    private static List<String> readLinesFromFile(String filePath) {
        List<String> lines = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                lines.add(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return lines;
    }

    private static List<ExtractRequests.RequestObject> parseLines(List<String> lines) {
        List<ExtractRequests.RequestObject> requestObjects = new ArrayList<>();
        for (String line : lines) {
            String[] parts = line.split(": ");

            if (parts.length == 2 && parts[0].length() == 7) {
                String id = parts[0];//.split(",")[0];
                String request = parts[1];
                requestObjects.add(new ExtractRequests.RequestObject(id, request));
            }
        }
        return requestObjects;
    }

    private static List<String> extractRequests(List<ExtractRequests.RequestObject> requestObjects) {
        List<String> requests = new ArrayList<>();
        for (ExtractRequests.RequestObject obj : requestObjects) {
            requests.add(obj.getRequest());
        }
        return requests;
    }

    private static void sendFileToTeacher(Socket socket) throws Exception {
        List<String> lines = readLinesFromFile("stored_requests.txt");
        List<ExtractRequests.RequestObject> requestObjects = parseLines(lines);
        List<String> requests = extractRequests(requestObjects);

        ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream inputStream = new ObjectInputStream(socket.getInputStream());

        certificate = (X509Certificate) inputStream.readObject();
        certificateAuthorityPublicKey = (PublicKey) inputStream.readObject();

        boolean isSignatureValid = verifySignature(certificate, certificateAuthorityPublicKey);
        if (!isSignatureValid) {
            System.out.println("Signature verification failed. Sending 'try again' to client.");
            oos.writeObject("try again");
            return; // Exit the method if signature verification fails.
        }

        System.out.println("Signature verification successful. Sending requests to client.");
        oos.writeObject(requests);
    }

    public static boolean verifySignature(X509Certificate certificate, PublicKey publicKey) throws Exception {
        // Extract the signature from the certificate
        byte[] signature = certificate.getSignature();

        // Create a signature verifier instance
        Signature verifier = Signature.getInstance("SHA256WithRSA");
        verifier.initVerify(publicKey);
        verifier.update(certificate.getTBSCertificate()); // Using the TBSCertificate content for verification

        // Verify the signature
        return verifier.verify(signature);
    }
    private static void receiveSessionKey(Socket clientSocket) throws Exception {
        ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());
        byte[] encryptedSessionKey = (byte[]) in.readObject();
        // Decrypt the session key using the server's private key
        byte[] decryptedSessionKey = decryptWithPrivateKey(encryptedSessionKey);
        sessionKey = new SecretKeySpec(decryptedSessionKey, 0, decryptedSessionKey.length, "AES");
        //System.out.println(sessionKey);
        //System.out.println("tesst_last_v.Server received and decrypted session key.");
        ObjectOutputStream confirmationOut = new ObjectOutputStream(clientSocket.getOutputStream());
        confirmationOut.writeObject("Session key received and agreed upon by the server.");
    }

    // Implement RSA decryption with the server's private key
    private static byte[] decryptWithPrivateKey(byte[] encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, serverKeyPair.getPrivate());
        return cipher.doFinal(encryptedData);
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

    private static void loadAccounts() {
        try (BufferedReader reader = new BufferedReader(new FileReader(ACCOUNTS_FILE))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts.length == 4) {
                    accounts.add(new User(parts[0], parts[1], parts[2], parts[3]));
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
