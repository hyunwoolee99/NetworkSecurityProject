package TermProject;

import java.io.*; // java.io 하위 모든 라이브러리 자동 호출
import java.net.*; // java.net 하위 모든 라이브러리 자동 호출

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
	 * 암호화된 AES key를 RSA decrypt
	 */
	public static void RSA_decrypt(String encryptedKey) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		byte[] decodedKey = Base64.getDecoder().decode(encryptedKey);
		cipher.init(Cipher.DECRYPT_MODE, RSAprivateKey);
		byte[] bytePlain = cipher.doFinal(decodedKey);
		key = new SecretKeySpec(bytePlain, 0, bytePlain.length, "AES");
	}
	
	/*
	 * 암호화된 AES IV를 RSA decrypt
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
		ServerSocket server_socket = null; // Client와 통신하기 위한 Server Socket
		BufferedReader in = null; // Client로부터 데이터를 받는 입력스트림
		BufferedReader in2 = null; // 키보드 입력을 읽는 입력스트림
		PrintWriter out = null; // Client로 전송하는 출력스트림
		
		/*
		 * socket open
		 */
		try {
			server_socket = new ServerSocket(3535); //임의의 Port no.
		}catch(IOException e) {
			System.out.println("Port already opened");
		}
		
		/*
		 * socket 생성, I/O stream 생성
		 */
		try {
			System.out.println("Server opened");
			socket = server_socket.accept(); //Client와 연결
			
			in = new BufferedReader(new InputStreamReader(socket.getInputStream())); // 입력스트림 생성
			in2 = new BufferedReader(new InputStreamReader(System.in)); // 키보드 입력스트림
			out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()))); // 출력스트림 생성
			
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
			ObjectOutputStream outO = new ObjectOutputStream(os); //public Key 전송을 위한 출력스트림
			
			outO.writeObject(RSApublicKey); //public key 전송
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
				String sd = sdf.format(new Date(Long.parseLong(String.valueOf(timeStamp)))); //timestamp 생성
				
				String str = null;
				str = in.readLine(); // Client로부터 데이터 읽어옴
				String decryptedText = AES_Decrypt(str);
				System.out.println("> Received : \"" + decryptedText + "\" " + sd);
				System.out.println("Encrypted Message : \"" + str + "\"");
				
				if(decryptedText.equals("exit")) {			//종료 명령어
					System.out.println("Connection closed");
					String exit = AES_Encrypt("exit");
					out.println(exit);
					out.flush();
					break;
				}
				System.out.println();
				System.out.print("> ");
				String data = in2.readLine(); // 키보드로부터 입력
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