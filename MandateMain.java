package com.tcs.sbi.main;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Calendar;
import java.util.Currency;
import java.util.Date;
import java.util.HashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.apache.commons.logging.LogSource;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import com.tcs.sbi.constants.ErrorConstants;
import com.tcs.sbi.dbConnection.Manager;
import com.tcs.sbi.launcher.MandateLauncher;
import com.tcs.sbi.util.MandateUtility;

public class MandateMain implements Runnable {

	int testCounter = 0; 
	File zipName;
	String type;
	Integer totalnoofRecords;
	String Zone;

	public MandateMain(File folderName, String type, Integer totalnoofRecords, String Zone) {
		super();

		this.zipName = folderName;
		this.type = type;
		this.totalnoofRecords = totalnoofRecords;
		this.Zone = Zone;
	}

	private static final Logger log = LogManager.getLogger(MandateLauncher.class);

	public void run() {
		String srcPath = MandateLauncher.getToProcessPath() + File.separator + type;
		String zippedPath = MandateLauncher.getZippedPath();
		String signedPath = MandateLauncher.getSignedPath();
		String signedFilePath = "";
		String finalXmlPath = "";
		String destPath = MandateLauncher.getDestPath();
		String backUpPath = MandateLauncher.getBackUpPath();
		PrivateKey privateKey = MandateLauncher.getPrivateKey();
		PublicKey publicKey = MandateLauncher.getPublicKey();
		PGPPublicKey pgpPublicKey = MandateLauncher.getPgpPublicKey();
		HashMap<String, Object> encdmap = new HashMap<String, Object>();
		String referenceNumber = null;
		
		try {
			referenceNumber = MandateUtility.generateReferenceNumber();
			boolean success = false;
			boolean dbupdate = false;
			File sourceFolder = new File(srcPath);
			File[] listOfFolders = sourceFolder.listFiles(File::isDirectory);

			log.info("Total number of folders found in source folder for ACH-Mandate to be processed is : "
					+ (listOfFolders != null ? listOfFolders.length : 0));
			boolean isZipped = false;
			boolean isSigned = false;
			boolean isEncrypted = false;
			
			encdmap.put("ReferenceNumber", referenceNumber);
			encdmap.put("FileName",zipName.getName());
			encdmap.put("fileCopiedTime",MandateUtility.getTimestamp());
			encdmap.put("FileReadingTime", MandateUtility.getTimestamp()); 
			encdmap.put("FileType", type);
			encdmap.put("totalnoofRecords", totalnoofRecords);
			encdmap.put("Zone", Zone);
			
//			Zipping the folder contents
			if (!isZipped) {
				String newSrcPath = zipName.getAbsolutePath();
				String zipFilePath = zippedPath + File.separator + zipName.getName() + ".zip";
				MandateUtility.zipFolder(Paths.get(newSrcPath), Paths.get(zipFilePath));
				String currDate = new java.text.SimpleDateFormat("ddMMyyyy").format(new java.util.Date());
				
				isZipped = true;
//			Signing the zipped file start
				encdmap.put("Status", ErrorConstants.ZIP_SUCCESS.toString());
				encdmap.put("statusENC", ErrorConstants.ZIP_SUCCESS.name().toString());
				encdmap.put("lastUpdatedtime", MandateUtility.getTimestamp());
				encdmap.put("EncryptionType", ErrorConstants.ZIPPED_FILE.toString());
				if (isZipped) {
					try {
						signedFilePath = signedPath + File.separator + zipName.getName() + ".zip";
						byte[] zipFileBytes = Files.readAllBytes(Paths.get(zipFilePath));
						Signature signature = Signature.getInstance("SHA256withRSA");
						signature.initSign(privateKey);
						signature.update(zipFileBytes);
						byte[] digitalSignature = signature.sign();
						String base64ZipContent = Base64.getEncoder().encodeToString(zipFileBytes);
						String base64Signature = Base64.getEncoder().encodeToString(digitalSignature); 
						String base64Certificate = Base64.getEncoder().encodeToString(publicKey.getEncoded());
						String xmlContent = String.format(
								"<Envelope> \n" +
							    "  <OrgContent>%s</OrgContent>\n" +
								"  <Signature>%s</Signature>\n"	 +
							    "  <Certificate>%s</Certificate>\n" +
								"</Envelope>",
								base64ZipContent,
								base64Signature,
								base64Certificate
								);
						finalXmlPath = signedFilePath.replaceAll("(?i)\\.zip$", ".xml");
						Files.write(Paths.get(finalXmlPath),xmlContent.getBytes(StandardCharsets.UTF_8));
						isSigned = true;
						encdmap.put("Status", ErrorConstants.SIGN_SUCCESS.toString());
						encdmap.put("statusENC", ErrorConstants.SIGN_SUCCESS.name().toString());
						encdmap.put("lastUpdatedtime", MandateUtility.getTimestamp());
						encdmap.put("EncryptionType", ErrorConstants.SIGNED_FILE.toString());
//			Encrypting the zipped file
					if (isSigned) {
						try {
							Files.createDirectories(Paths.get(destPath + File.separator + currDate));
							String encryptedFilePath = destPath + File.separator + currDate + File.separator
									+ zipName.getName() + ".zip";
							
							PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
									new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
											.setWithIntegrityPacket(true).setSecureRandom(new SecureRandom())
											.setProvider("BC"));

							encGen.addMethod(
									new JcePublicKeyKeyEncryptionMethodGenerator(pgpPublicKey).setProvider("BC"));

							try (OutputStream out = new BufferedOutputStream(new FileOutputStream(encryptedFilePath));
									ArmoredOutputStream armoredOut = new ArmoredOutputStream(out)){
									OutputStream encOut = encGen.open(armoredOut, new byte[4096]); 
								Files.copy(Paths.get(finalXmlPath), encOut);
								encGen.close();
							} catch (Exception e) {
								log.info(e.getMessage());
							}
							encdmap.put("Status", ErrorConstants.ENCRYPTION_SUCCESS.toString());
							encdmap.put("statusENC", ErrorConstants.ENCRYPTION_SUCCESS.name().toString());
							encdmap.put("lastUpdatedtime", MandateUtility.getTimestamp());
							encdmap.put("EncryptionType", ErrorConstants.ENCRYPTED_FILE.toString());
							log.info("Successfully encrypted file: " + zipName.getName());
							success = true;

//						source backup
							String backUpString = backUpPath + File.separator + File.separator + "SourceFilesBackUp"
									+ File.separator + currDate + File.separator + type + File.separator
									+ zipName.getName() + ".zip";
							Files.createDirectories(Paths.get(backUpPath + File.separator + File.separator
									+ "SourceFilesBackUp" + File.separator + currDate + File.separator + type));
							MandateUtility.createBackUp(zipFilePath, backUpString);

//						output backup
							backUpString = backUpPath + File.separator + File.separator + "EncryptedFilesBackUp"
									+ File.separator + currDate + File.separator + zipName.getName() + ".zip";
							Files.createDirectories(Paths.get(backUpPath + File.separator + File.separator
									+ "EncryptedFilesBackUp" + File.separator + currDate + File.separator + type));
							MandateUtility.createBackUp(encryptedFilePath, backUpString);
							isEncrypted = true;
						} catch (IOException ex) {
							log.error("IO Exception occured " + ex);
						} catch (Exception e) {
							log.info("Error encrypting the files : " + e.getMessage());
						}
					} else {
						encdmap.put("Status", ErrorConstants.ENCRYPTION_FAILURE.toString());
						encdmap.put("statusENC", ErrorConstants.ENCRYPTION_FAILURE.name().toString());
						encdmap.put("lastUpdatedtime", MandateUtility.getTimestamp());
						encdmap.put("EncryptionType", ErrorConstants.SIGNED_FILE.toString());
//						encryption failed
						log.info("Failed to encrypt the files");
					}
				} catch (IOException ex) {
					log.error("IO Exception occured " + ex);
				} catch(Exception e) {
					log.info("Failed to sign the files");
				}
				} else {
					encdmap.put("Status", ErrorConstants.SIGN_FAILURE.toString());
					encdmap.put("statusENC", ErrorConstants.SIGN_FAILURE.name().toString());
					encdmap.put("lastUpdatedtime", MandateUtility.getTimestamp());
					encdmap.put("EncryptionType", ErrorConstants.ZIPPED_FILE.toString());
//					signing failed
					log.info("Failed to sign the files");
				}
				
//				deleting files after processing/
				try {
					if(success) {
						MandateUtility.deleteDirectory(Paths.get(newSrcPath));
						Files.delete(Paths.get(zipFilePath));
						Files.delete(Paths.get(finalXmlPath));
					}
				} catch (IOException ex) {
					log.error("IO Exception occured " + ex);
				} catch (Exception e) {
					log.info("Error while deleting files from process Folders " + e.getMessage());
				}
			} else {
				encdmap.put("Status", ErrorConstants.ZIP_FAILURE.toString());
				encdmap.put("statusENC", ErrorConstants.ZIP_FAILURE.name().toString());
				encdmap.put("lastUpdatedtime", MandateUtility.getTimestamp());
//				zipping failed
				log.info("Failed to zip the files");
			}
			
			dbupdate = Manager.insertintoMandate_logs(encdmap, new Date());
			if (dbupdate == true) {
				log.info("Status updated in DB for File and the Reference Number is : "
						+ referenceNumber);
			} else {
				log.info("Unable to updated in DB for File and the Reference Number is : "
						+ referenceNumber);
			}
			
		} catch (IOException ex) {
			log.error("IO Exception occured " + ex);
		} catch (Exception e) {
			e.getMessage();
		}

	}
}
