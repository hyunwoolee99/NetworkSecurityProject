package TermProject;

import java.io.*; // java.io ���� ��� ���̺귯�� �ڵ� ȣ��
import java.net.*; // java.net ���� ��� ���̺귯�� �ڵ� ȣ��

import java.util.Base64;
import java.util.Date;
import java.text.SimpleDateFormat;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.PublicKey;
import java.security.PrivateKey;


public class Server {
	
	public static KeyPair RSAkeyPair;			//RSA Keypair
	public static PublicKey RSApublicKey;		//RSA public key
	public static PrivateKey RSAprivateKey;		//RSA private key
	public static SecretKey key;				//AES symmetric key
	public static IvParameterSpec IV;			//AES initial vector
	
	/*
	 * RSA keypair generator
	 */
	public static void RSAKeyPairGenerator() throws NoSuchAlgorithmException {

        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator gen;
        gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048, secureRandom);
        RSAkeyPair = gen.generateKeyPair();
        RSApublicKey = RSAkeyPair.getPublic();
        RSAprivateKey = RSAkeyPair.getPrivate();
    }
	
	/*
	 * message encrypt by AES
	 */
	public static String AES_Encrypt(String data) throws Exception {
		if (data == null || data.length() == 0)
			return "";
		
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key, IV);
		
		byte[] plainToByte = data.getBytes();
		byte[] encryptedByte = cipher.doFinal(plainToByte);
		
		byte[] encryptedBase64 = java.util.Base64.getEncoder().encode(encryptedByte);
		
		return new String(encryptedBase64);
	}
	
	/*
	 * message decrypt by AES
	 */
	public static String AES_Decrypt(String data) throws Exception {
		if (data == null || data.length() == 0)
			return "";
		javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key, IV);
		
		byte[] decodeBase64 = java.util.Base64.getDecoder().decode(data);
		byte[] decryptedByte = cipher.doFinal(decodeBase64);
		String byteToPlain = new String(decryptedByte);
		
		return byteToPlain;
	}

	/*
	 * ��ȣȭ�� AES key�� RSA decrypt
	 */
	public static void RSA_decrypt(String encryptedKey) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		byte[] decodedKey = Base64.getDecoder().decode(encryptedKey);
		cipher.init(Cipher.DECRYPT_MODE, RSAprivateKey);
		byte[] bytePlain = cipher.doFinal(decodedKey);
		key = new SecretKeySpec(bytePlain, 0, bytePlain.length, "AES");
	}
	
	/*
	 * ��ȣȭ�� AES IV�� RSA decrypt
	 */
	public static void RSA_decryptiv(String encryptedIV) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		byte[] decodedKey = Base64.getDecoder().decode(encryptedIV);
		cipher.init(Cipher.DECRYPT_MODE, RSAprivateKey);
		byte[] bytePlain = cipher.doFinal(decodedKey);
		IV = new IvParameterSpec(bytePlain);
	}
	
	public static void main(String[] args) throws Exception {
		Socket socket = null;
		ServerSocket server_socket = null; // Client�� ����ϱ� ���� Server Socket
		BufferedReader in = null; // Client�κ��� �����͸� �޴� �Է½�Ʈ��
		BufferedReader in2 = null; // Ű���� �Է��� �д� �Է½�Ʈ��
		PrintWriter out = null; // Client�� �����ϴ� ��½�Ʈ��
		
		/*
		 * socket open
		 */
		try {
			server_socket = new ServerSocket(3535); //������ Port no.
		}catch(IOException e) {
			System.out.println("Port already opened");
		}
		
		/*
		 * socket ����, I/O stream ����
		 */
		try {
			System.out.println("Server opened");
			socket = server_socket.accept(); //Client�� ����
			
			in = new BufferedReader(new InputStreamReader(socket.getInputStream())); // �Է½�Ʈ�� ����
			in2 = new BufferedReader(new InputStreamReader(System.in)); // Ű���� �Է½�Ʈ��
			out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()))); // ��½�Ʈ�� ����
			
		}catch(IOException e) {
			
		}
		
		/*
		 * Key Exchange
		 */
		try {
			RSAKeyPairGenerator();
			System.out.println("> Creating RSA Key Pair...");
			System.out.println("Private Key : " + Base64.getEncoder().encodeToString(RSAprivateKey.getEncoded()));
			System.out.println("Public Key : " + Base64.getEncoder().encodeToString(RSApublicKey.getEncoded()));
			System.out.println();
			
			OutputStream os = socket.getOutputStream();
			ObjectOutputStream outO = new ObjectOutputStream(os); //public Key ������ ���� ��½�Ʈ��
			
			outO.writeObject(RSApublicKey); //public key ����
			outO.flush();
			
			String encryptedKey = null;
			encryptedKey = in.readLine(); //Receive AES key
			System.out.println("> Received AES Key : " + encryptedKey);
			RSA_decrypt(encryptedKey);
			System.out.println("Decrypted AES Key : " + Base64.getEncoder().encodeToString(key.getEncoded()));
			String encryptedIV = in.readLine(); //Receive AES IV
			RSA_decryptiv(encryptedIV);
			System.out.println();
		}catch(Exception e) {
			
		}
		
		try {
			while(true) {
				Long timeStamp = System.currentTimeMillis();
				SimpleDateFormat sdf=new SimpleDateFormat("[yyyy/MM/dd HH:mm:ss]");
				String sd = sdf.format(new Date(Long.parseLong(String.valueOf(timeStamp)))); //timestamp ����
				
				String str = null;
				str = in.readLine(); // Client�κ��� ������ �о��
				String decryptedText = AES_Decrypt(str);
				System.out.println("> Received : \"" + decryptedText + "\" " + sd);
				System.out.println("Encrypted Message : \"" + str + "\"");
				
				if(decryptedText.equals("exit")) {			//���� ��ɾ�
					System.out.println("Connection closed");
					String exit = AES_Encrypt("exit");
					out.println(exit);
					out.flush();
					break;
				}
				System.out.println();
				System.out.print("> ");
				String data = in2.readLine(); // Ű����κ��� �Է�
				String encryptedText = AES_Encrypt(data);
				out.println(encryptedText);
				out.flush();
				System.out.println();
			}
			socket.close(); 
		}catch(Exception e) {
			
		}
	}
}