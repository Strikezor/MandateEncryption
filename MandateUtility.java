package com.tcs.sbi.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.cert.Certificate;

import org.apache.commons.io.FilenameUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.tcs.sbi.launcher.MandateLauncher;

public class MandateUtility {
	
	private static final Logger log = LogManager.getLogger(MandateLauncher.class);

	public static PrivateKey getCertKeys(String cerFileStream, String password) throws Exception {

		KeyStore keyStore = KeyStore.getInstance("PKCS12"); // , "BC");
		try (FileInputStream fis = new FileInputStream(cerFileStream)) {
			keyStore.load(fis, password.toCharArray());
		}
		String aliase = keyStore.aliases().nextElement();
		java.security.Key key = keyStore.getKey(aliase, password.toCharArray());

		return (PrivateKey) key;
	}
	
	public static String aesDecrypt(String key, String initVector, String encrypted)
			throws UnsupportedEncodingException {
		byte[] keyb = keyToB(key);
		byte[] ivb = keyToB(initVector);
		String dec = decrypt1(keyb, ivb, encrypted);
		return dec;
	}
	public static String decrypt1(byte[] key, byte[] initVector, String encrypted) {
		try {
			IvParameterSpec iv = new IvParameterSpec(initVector);
			SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
			byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));
	        return new String(original, "UTF-8");
		} catch (NoSuchAlgorithmException e) {
		    log.error("Algorithm not found: {}", e);
		} catch (NoSuchPaddingException e) {
		    log.error("Padding not found: {}",  e);
		} catch (InvalidKeyException e) {
		    log.error("Invalid key: {}", e);
		} catch (InvalidAlgorithmParameterException e) {
		    log.error("Invalid algorithm parameter: {}",  e);
		} catch (IllegalBlockSizeException e) {
		    log.error("Illegal block size: {}", e);
		} catch (BadPaddingException e) {
		    log.error("Bad padding: {}", e);
		} catch (UnsupportedEncodingException e) {
		    log.error("Unsupported encoding: {}", e);
		} catch (Exception e) {
		    log.error("An unexpected error occurred: {}", e);
		}

		return null;
	}
	public static byte[] keyToB(String key) throws UnsupportedEncodingException {

		byte[] keybyte = Base64.getDecoder().decode(key.getBytes("UTF-8"));

		return keybyte;
	}

	public static PublicKey getPubkeyfrompath(String pubkeypath) {
		PublicKey pubkey;
		try {
			CertificateFactory certfactory = CertificateFactory.getInstance("X.509");
			FileInputStream fis = new FileInputStream(pubkeypath);
			java.security.cert.Certificate certificate = certfactory.generateCertificate(fis);

			pubkey = certificate.getPublicKey();
			fis.close();
			return pubkey;
		} catch (Exception e) {

			return null;
		}
	}

	public static String generateReferenceNumber() {
		String generateUUIDNo = String.format("%010d",
				new BigInteger(UUID.randomUUID().toString().replace("-", ""), 16));
		String unique_no = "SBIN" + generateUUIDNo.substring(generateUUIDNo.length() - 10);

		return unique_no;
	}

	public static int returnMaxDays(int calMonth) {

		int maxDays = 0;

		if (calMonth == 1) {
			maxDays = 31;
		} else if (calMonth == 2) {
			maxDays = 28;
		} else if (calMonth == 3) {
			maxDays = 31;
		} else if (calMonth == 4) {
			maxDays = 30;
		} else if (calMonth == 5) {
			maxDays = 31;
		} else if (calMonth == 6) {
			maxDays = 30;
		} else if (calMonth == 7) {
			maxDays = 31;
		} else if (calMonth == 8) {
			maxDays = 31;
		} else if (calMonth == 9) {
			maxDays = 30;
		} else if (calMonth == 10) {
			maxDays = 31;
		} else if (calMonth == 11) {
			maxDays = 30;
		} else {
			maxDays = 31;
		}
		return maxDays;
	}

	public static String generateRefrenceNumber() {

		String generateUUIDNo = String.format("%010d",
				new BigInteger(UUID.randomUUID().toString().replace("-", ""), 16));
		String unique_no = "SBIN" + generateUUIDNo.substring(generateUUIDNo.length() - 10);

		return unique_no;

	}

	public static Timestamp getTimestamp() {
		Timestamp timestamp = null;
		try {
			SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SS");
			String strTime = sdf.format(new Date());
			timestamp = Timestamp.valueOf(strTime);
		} catch (Exception e) {
			e.getMessage();
		}
		return timestamp;
	}

	public static String readorgcontentfromfile(String path, HashMap<String, Object> encdmap) throws IOException {

		String orgcontent = null;
		StringBuilder str = new StringBuilder();
		BufferedReader br = new BufferedReader(new FileReader(path));
		int lineCount = 0;
		try {

			while ((orgcontent = br.readLine()) != null) {

				str.append(orgcontent);
				str.append("\r\n");
				lineCount++;
			}

			if (lineCount > 0) {
				lineCount = lineCount - 1;
			}
			encdmap.put("totalnoofRecords", lineCount);

		} catch (IOException e) {
			log.info("IO Exception occured : " + e.getMessage());
		} catch (Exception e) {
			log.error("Error occur while updating the table : " + e);
		} finally {
			br.close();

		}

		return str.toString();
	}

	public static void createToProcessFolder(String folderName, String type) {
		try {
			Path basePath = Paths.get(MandateLauncher.getToProcessPath());
			Path toProcessPath = basePath.resolve(type).resolve(folderName).toAbsolutePath();

			Files.createDirectories(toProcessPath);
		} catch (IOException e) {
			log.error("Error while creating the toProcessPath : " + e.getMessage());
		}
	}

	public static void deleteDirectory(Path dir) throws IOException{
		if(!Files.exists(dir)){
			log.info("File does not exists");
		}
		else {
		Files.walk(dir).sorted(Comparator.reverseOrder()).forEach(path->{
				try {
					Files.delete(path);
				} catch (IOException e) {
					e.printStackTrace();
				} catch (Exception e) {
					log.info("Error while deleting directory + " + e);
				}
			});
		}
	}

	public static void zipFolder(Path sourceFolderPath, Path zippedPath) throws IOException {
		try (ZipOutputStream zs = new ZipOutputStream(Files.newOutputStream(zippedPath))) {
			Files.walk(sourceFolderPath).filter(path -> !Files.isDirectory(path)).forEach(path -> {
				ZipEntry zipEntry = new ZipEntry(sourceFolderPath.relativize(path).toString());
				try {
					zs.putNextEntry(zipEntry);
					Files.copy(path, zs);
					zs.closeEntry();
				} catch (IOException e) {
					log.error(e);
				} catch (Exception e) {
					log.error("Error while zipping hte folder " + e);
				}
			});
		}
	}

	public static void createBackUp(String source, String backup) {
		try {
			Files.copy(Paths.get(source), Paths.get(backup), StandardCopyOption.REPLACE_EXISTING);
		} catch (Exception e) {
			log.info("Error while creating backup : " + e);
		}
	}
}
