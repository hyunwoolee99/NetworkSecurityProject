package TermProject;

import java.io.*; // java.io ���� ��� ���̺귯�� �ڵ� ȣ��
import java.net.*;// java.net ���� ��� ���̺귯�� �ڵ� ȣ��

import java.util.Base64;
import java.util.Date;
import java.text.SimpleDateFormat;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.PublicKey;

public class Client {
	
	public static PublicKey RSApublicKey;	//RSA public key
	public static SecretKey key;			//AES symmetric key
	public static IvParameterSpec IV;		//AES Initial Vector
	
	/*
	 * AES key, IV generator
	 */
	public static void AES_KeyGenerator() throws Exception {
		String k = "12345678901234567890123456789012"; //32Bytes
		key=new SecretKeySpec(k.getBytes(), 0, k.length(), "AES");
		IV=new IvParameterSpec(k.substring(0,16).getBytes()); //16Bytes
	}
	
	/*
	 * AES Encrypt method
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
	 * AES Decrypt method
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
	 * encrypt AES symmetric key by RSA
	 */
	public static String RSA_encrypt(PublicKey publicKey) throws Exception {
        Cipher cipher=Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(key.getEncoded());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
	
	/*
	 * encrypt AES Initial Vector by AES
	 */
	public static String RSA_encryptiv(PublicKey publicKey) throws Exception {
        Cipher cipher=Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(IV.getIV());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
	
	public static void main(String[] args) throws Exception {
		Socket socket = null; // Server�� ����ϱ� ���� Client�� Socket
		BufferedReader in = null; // Server�κ��� �����͸� �޴� �Է½�Ʈ��
		BufferedReader in2 = null; // Ű���� �Է��� �д� �Է½�Ʈ��
		PrintWriter out = null; // ������ �����ϴ� ��½�Ʈ��
		InetAddress ia = null;  // ip address
		
		try {
			ia = InetAddress.getLocalHost(); // ������ �����ϱ� ���� ���� �ּ� �Է�
			
			socket = new Socket(ia, 3535);
			in = new BufferedReader(new InputStreamReader(socket.getInputStream())); // server���� �����͸� �޴� �Է½�Ʈ��
			in2 = new BufferedReader(new InputStreamReader(System.in)); // Ű���� �Է½�Ʈ��
			out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()))); // server�� ������ ��½�Ʈ��
			
			System.out.println(socket.toString());
		}catch(IOException e) {
			
		}
		
		/*
		 * Key exchange
		 */
		try {
			InputStream is = socket.getInputStream();
			ObjectInputStream inO = new ObjectInputStream(is); //publicKey�� �޴� �Է½�Ʈ��
			
			RSApublicKey = (PublicKey) inO.readObject();  //publicKey �޾ƿ���
			System.out.print("> Received Public Key : " + Base64.getEncoder().encodeToString(RSApublicKey.getEncoded()));
			System.out.println();
			AES_KeyGenerator();	//AES key, IV ����
			System.out.println("Creating AES 256 Key..");
			System.out.print("AES 256 Key : " + Base64.getEncoder().encodeToString(key.getEncoded()));
			System.out.println();
			out.flush();
			String encryptedKey = null;
			encryptedKey = RSA_encrypt(RSApublicKey);
			out.println(encryptedKey); // send encrypted AES Key
			out.flush();
			String encryptedIV = RSA_encryptiv(RSApublicKey);
			out.println(encryptedIV); //send encrypted IV
			out.flush();
			System.out.print("Encrypted AES Key : " + encryptedKey);
			System.out.println();
			System.out.println();
			
		} catch(Exception e) {
			
		}
		
		try {
			while(true) {
				Long timeStamp = System.currentTimeMillis();
				SimpleDateFormat sdf=new SimpleDateFormat("[yyyy/MM/dd HH:mm:ss]");
				String sd = sdf.format(new Date(Long.parseLong(String.valueOf(timeStamp)))); //timestamp ����
				
				System.out.print("> ");
				String data = in2.readLine(); // Ű����κ��� �Է�
				String encryptedText = AES_Encrypt(data);
				out.println(encryptedText); // ������ ������ ����
				out.flush();
				System.out.println();

				String str2 = in.readLine(); // �����κ��� ������ �о��
				String decryptedText = AES_Decrypt(str2);
				System.out.println("> Received : \"" + decryptedText +"\" " + sd);
				System.out.println("Encrypted Message : \"" + str2 + "\"");
				if(decryptedText.equals("exit")) { //���� ��ɾ�
					System.out.println("Connection closed");
					String exit = AES_Encrypt("exit");
					out.println(exit);
					out.flush();
					break;
				}
				System.out.println();
			}
			socket.close();
		}catch(Exception e) {
			
		}
	}
}