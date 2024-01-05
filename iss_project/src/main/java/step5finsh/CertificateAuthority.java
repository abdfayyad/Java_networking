package step5finsh;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.Random;

public class CertificateAuthority {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
private  static  PublicKey clientPublicKey;

    public   static  PublicKey publicKey;

    private  static PrivateKey privateKey;
    public static void main(String[] args) throws Exception {
        try (ServerSocket serverSocket = new ServerSocket(8080)) {
            System.out.println("CA is running and waiting for clients...");
            KeyPair keyPair=generateKeyPair();
            publicKey=keyPair.getPublic();

          //  System.out.println(publicKey);
            privateKey=keyPair.getPrivate();

            while (true) {
                try (Socket clientSocket = serverSocket.accept();
                     PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
                     BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()))) {

                     performHandshake(clientSocket,keyPair);
                    handleClientConnection(out, in);

                }
            }
        }
    }





    private static void handleClientConnection(PrintWriter out, BufferedReader in) throws Exception {
        boolean isVerified = false;

        while (!isVerified) {
            // Receive CSR from client
            String csr = in.readLine();
            System.out.println("Received CSR from client: " + csr);

            // Challenge the client
            String challenge = generateMathChallenge();
            out.println(challenge);

            // Receive answer from client
            int answer;
            try {
                answer = Integer.parseInt(in.readLine());
            } catch (NumberFormatException e) {
                out.println("Invalid answer format. Please try again.");
                continue; // Restart the loop
            }

            int expectedAnswer = solveMathChallenge(challenge);

            if (answer == expectedAnswer) {
                issueCertificate(out);
                isVerified = true; // Set flag to true to exit the loop
            } else {
                out.println("Verification failed. Please try again."); // Inform the client that the verification failed
            }
        }
    }


    private static void issueCertificate(PrintWriter out) throws Exception {
        X509Certificate certificate = createCertificate(); // Generate the certificate

        // Convert certificate to a string (e.g., Base64) for sending
        String encodedCertificate = Base64.getEncoder().encodeToString(certificate.getEncoded());
        out.println(encodedCertificate); // Send the certificate to the client
    }
    // Method to generate a public-private key pair
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // You can adjust the key size as needed
        return keyPairGenerator.generateKeyPair();
    }

    // Method to create a certificate signing request (CSR)
    public static X509Certificate createCertificate() throws Exception {
        // Prepare the information for the certificate
        X500Principal subjectName = new X500Principal("CN=MyTestCertificate");
        Date startDate = new Date();
        Date expiryDate = new Date(startDate.getTime() + 365 * 24 * 60 * 60 * 1000); // Valid for 1 year
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());

        // Create a certificate signing request (CSR)
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        certGen.setSerialNumber(serialNumber);
        certGen.setSubjectDN(subjectName);
        certGen.setIssuerDN(subjectName); // Self-signed
        certGen.setNotBefore(startDate);
        certGen.setNotAfter(expiryDate);
        certGen.setPublicKey(clientPublicKey);
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");


        X509Certificate certificate = certGen.generate(privateKey);

        // You can save the certificate to a file or use it as needed
        return certificate;
    }
    private static void performHandshake(Socket socket, KeyPair clientKeyPair) throws Exception {
        // System.out.println("call performHandshake");

        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());



        out.writeObject(clientKeyPair.getPublic());

        // Receive server public key
        clientPublicKey = (PublicKey) in.readObject();
       // System.out.println(clientKeyPair.getPublic());

    }


    private static String generateMathChallenge() {
        Random random = new Random();
        int num1 = random.nextInt(10);
        int num2 = random.nextInt(10);
        return num1 + " + " + num2;
    }

    private static int solveMathChallenge(String challenge) {
        String[] parts = challenge.split("\\+");
        return Integer.parseInt(parts[0].trim()) + Integer.parseInt(parts[1].trim());
    }
}
