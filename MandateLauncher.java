package com.tcs.sbi.launcher;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.Configurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPAlgorithmParameters;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;

import com.tcs.sbi.constants.ErrorConstants;
import com.tcs.sbi.constants.MandateConstants;
import com.tcs.sbi.dbConnection.Manager;
import com.tcs.sbi.main.MandateMain;
import com.tcs.sbi.util.MandateEncProperties;
import com.tcs.sbi.util.MandateUtility;

public class MandateLauncher {
	private static final Logger log = LogManager.getLogger(MandateLauncher.class);
	private static String loggerPath;
	private static String srcPath;
	private static String destPath;
	private static String zippedPath;
	private static String signedPath;
	private static String encryptedPath;
	private static String failedFilesPath;
	private static String backUpPath;
	public static String password;
	public static PrivateKey privateKey;
	public static PublicKey publicKey;
	public static PGPPublicKey pgpPublicKey;
	private static String threadSleepTimeString;
	private static int threadSleepTime;
	private static String publicKeyPath;
	private static String privateKeyPath;
	private static String tailName;
	private static String zippingFailedPath;
	private static String signingFailedPath;
	private static String encryptingFailedPath;
	private static String fileProcessLimitString;
	private static int fileProcessLimit;
	private static String toProcessPath;
	private static String nameStart;
	private static String nameEnd;
	private static String minFileNameLengthString;
	private static String maxFileNameLengthString;
	private static int minFileNameLength;
	private static int maxFileNameLength;
	private static String noOfDays;
	private static String sbiSrNo;
	private static String Key, IV;
	private static String dbUser, dbPwd, dbUrl;
	private static String pubKey;
	private static X509Certificate privCert;
	private static X509Certificate pubCert;
	private static String Encodedpubcert;
	
	private static String sftpHost;
	private static String sftpUsername;
	private static String sftpPwd;
	private static String sftpPort;
	private static String remoteDir;
	private static String archiveDir;
	private static String localDir;
	private static String serverPrivateKeypath;

	
	public static X509Certificate getPrivCert() {
		return privCert;
	}

	public static void setPrivCert(X509Certificate privCert) {
		MandateLauncher.privCert = privCert;
	}

	public static X509Certificate getPubCert() {
		return pubCert;
	}

	public static void setPubCert(X509Certificate pubCert) {
		MandateLauncher.pubCert = pubCert;
	}

	public static String getEncodedpubcert() {
		return Encodedpubcert;
	}

	public static void setEncodedpubcert(String encodedpubcert) {
		Encodedpubcert = encodedpubcert;
	}

	public static String getServerPrivateKeypath() {
		return serverPrivateKeypath;
	}

	public static void setServerPrivateKeypath(String serverPrivateKeypath) {
		MandateLauncher.serverPrivateKeypath = serverPrivateKeypath;
	}

	public static String getSftpHost() {
		return sftpHost;
	}

	public static void setSftpHost(String sftpHost) {
		MandateLauncher.sftpHost = sftpHost;
	}

	public static String getSftpUsername() {
		return sftpUsername;
	}

	public static void setSftpUsername(String sftpUsername) {
		MandateLauncher.sftpUsername = sftpUsername;
	}

	public static String getSftpPwd() {
		return sftpPwd;
	}

	public static void setSftpPwd(String sftpPwd) {
		MandateLauncher.sftpPwd = sftpPwd;
	}

	public static String getSftpPort() {
		return sftpPort;
	}

	public static void setSftpPort(String sftpPort) {
		MandateLauncher.sftpPort = sftpPort;
	}

	public static String getRemoteDir() {
		return remoteDir;
	}

	public static void setRemoteDir(String remoteDir) {
		MandateLauncher.remoteDir = remoteDir;
	}

	public static String getArchiveDir() {
		return archiveDir;
	}

	public static void setArchiveDir(String archiveDir) {
		MandateLauncher.archiveDir = archiveDir;
	}

	public static String getLocalDir() {
		return localDir;
	}

	public static void setLocalDir(String localDir) {
		MandateLauncher.localDir = localDir;
	}

	public static String getPassword() {
		return password;
	}

	public static void setPassword(String password) {
		MandateLauncher.password = password;
	}

	public static String getSbiSrNo() {
		return sbiSrNo;
	}

	public static void setSbiSrNo(String sbiSrNo) {
		MandateLauncher.sbiSrNo = sbiSrNo;
	}

	public static String getNoOfDays() {
		return noOfDays;
	}

	public static void setNoOfDays(String noOfDays) {
		MandateLauncher.noOfDays = noOfDays;
	}

	public static String getNameStart() {
		return nameStart;
	}

	public static void setNameStart(String nameStart) {
		MandateLauncher.nameStart = nameStart;
	}

	public static String getNameEnd() {
		return nameEnd;
	}

	public static void setNameEnd(String nameEnd) {
		MandateLauncher.nameEnd = nameEnd;
	}

	public static String getToProcessPath() {
		return toProcessPath;
	}

	public static void setToProcessPath(String toProcessPath) {
		MandateLauncher.toProcessPath = toProcessPath;
	}

	public static int getFileProcesslimit() {
		return fileProcessLimit;
	}

	public static void setFileProcesslimit(int fileProcessLimit) {
		MandateLauncher.fileProcessLimit = fileProcessLimit;
	}

	public static String getEncryptingFailedPath() {
		return encryptingFailedPath;
	}

	public static void setEncryptingFailedPath(String encryptingFailedPath) {
		MandateLauncher.encryptingFailedPath = encryptingFailedPath;
	}

	public static String getSigningFailedPath() {
		return signingFailedPath;
	}

	public static void setSigningFailedPath(String signingFailedPath) {
		MandateLauncher.signingFailedPath = signingFailedPath;
	}

	public static String getZippingFailedPath() {
		return zippingFailedPath;
	}

	public static void setZippingFailedPath(String zippingFailedPath) {
		MandateLauncher.zippingFailedPath = zippingFailedPath;
	}

	public static String getTailName() {
		return tailName;
	}

	public static void setTailName(String tailName) {
		MandateLauncher.tailName = tailName;
	}

	public static String getPublicKeyPath() {
		return publicKeyPath;
	}

	public static void setPublicKeyPath(String publicKeyPath) {
		MandateLauncher.publicKeyPath = publicKeyPath;
	}

	public static String getPrivateKeyPath() {
		return privateKeyPath;
	}

	public static void setPrivateKeyPath(String privateKeyPath) {
		MandateLauncher.privateKeyPath = privateKeyPath;
	}

	public static String getLoggerPath() {
		return loggerPath;
	}

	public static String getBackUpPath() {
		return backUpPath;
	}

	public static void setBackUpPath(String backUpPath) {
		MandateLauncher.backUpPath = backUpPath;
	}

	public static void setLoggerPath(String loggerPath) {
		MandateLauncher.loggerPath = loggerPath;
	}

	public static String getSrcPath() {
		return srcPath;
	}

	public static void setSrcPath(String srcPath) {
		MandateLauncher.srcPath = srcPath;
	}

	public static String getDestPath() {
		return destPath;
	}

	public static void setDestPath(String destPath) {
		MandateLauncher.destPath = destPath;
	}

	public static String getZippedPath() {
		return zippedPath;
	}

	public static void setZippedPath(String zippedPath) {
		MandateLauncher.zippedPath = zippedPath;
	}

	public static String getSignedPath() {
		return signedPath;
	}

	public static void setSignedPath(String signedPath) {
		MandateLauncher.signedPath = signedPath;
	}

	public static PrivateKey getPrivateKey() {
		return privateKey;
	}

	public static void setPrivateKey(PrivateKey privateKey) {
		MandateLauncher.privateKey = privateKey;
	}

	public static PublicKey getPublicKey() {
		return publicKey;
	}

	public static void setPublicKey(PublicKey publicKey) {
		MandateLauncher.publicKey = publicKey;
	}

	public static PGPPublicKey getPgpPublicKey() {
		return pgpPublicKey;
	}

	public static void setPgpPublicKey(PGPPublicKey pgpPublicKey) {
		MandateLauncher.pgpPublicKey = pgpPublicKey;
	}

	public static String getFailedFilesPath() {
		return failedFilesPath;
	}

	public static void setFailedFilesPath(String failedFilesPath) {
		MandateLauncher.failedFilesPath = failedFilesPath;
	}
	
	public static String getEncryptedPath() {
		return encryptedPath;
	}

	public static void setEncryptedPath(String encryptedPath) {
		MandateLauncher.encryptedPath = encryptedPath;
	}

	public static String getThreadSleepTimeString() {
		return threadSleepTimeString;
	}

	public static void setThreadSleepTimeString(String threadSleepTimeString) {
		MandateLauncher.threadSleepTimeString = threadSleepTimeString;
	}

	public static int getThreadSleepTime() {
		return threadSleepTime;
	}

	public static void setThreadSleepTime(int threadSleepTime) {
		MandateLauncher.threadSleepTime = threadSleepTime;
	}

	public static String getFileProcessLimitString() {
		return fileProcessLimitString;
	}

	public static void setFileProcessLimitString(String fileProcessLimitString) {
		MandateLauncher.fileProcessLimitString = fileProcessLimitString;
	}

	public static int getFileProcessLimit() {
		return fileProcessLimit;
	}

	public static void setFileProcessLimit(int fileProcessLimit) {
		MandateLauncher.fileProcessLimit = fileProcessLimit;
	}

	public static String getMinFileNameLengthString() {
		return minFileNameLengthString;
	}

	public static void setMinFileNameLengthString(String minFileNameLengthString) {
		MandateLauncher.minFileNameLengthString = minFileNameLengthString;
	}

	public static String getMaxFileNameLengthString() {
		return maxFileNameLengthString;
	}

	public static void setMaxFileNameLengthString(String maxFileNameLengthString) {
		MandateLauncher.maxFileNameLengthString = maxFileNameLengthString;
	}

	public static int getMinFileNameLength() {
		return minFileNameLength;
	}

	public static void setMinFileNameLength(int minFileNameLength) {
		MandateLauncher.minFileNameLength = minFileNameLength;
	}

	public static int getMaxFileNameLength() {
		return maxFileNameLength;
	}

	public static void setMaxFileNameLength(int maxFileNameLength) {
		MandateLauncher.maxFileNameLength = maxFileNameLength;
	}

	public static String getKey() {
		return Key;
	}

	public static void setKey(String key) {
		Key = key;
	}

	public static String getIV() {
		return IV;
	}

	public static void setIV(String iV) {
		IV = iV;
	}

	public static String getDbUser() {
		return dbUser;
	}

	public static void setDbUser(String dbUser) {
		MandateLauncher.dbUser = dbUser;
	}

	public static String getDbPwd() {
		return dbPwd;
	}

	public static void setDbPwd(String dbPwd) {
		MandateLauncher.dbPwd = dbPwd;
	}

	public static String getDbUrl() {
		return dbUrl;
	}

	public static void setDbUrl(String dbUrl) {
		MandateLauncher.dbUrl = dbUrl;
	}

	public static Logger getLog() {
		return log;
	}

	static {
		try {
			loggerPath = MandateEncProperties.getInstance().getProperty(MandateConstants.LOGGER_FILEPATH.toString());
			Configurator.initialize(null, loggerPath + MandateConstants.LOGGER_FILENAME.toString() + ".properties");
			srcPath = MandateEncProperties.getInstance().getProperty("SOURCE_PATH");
			destPath = MandateEncProperties.getInstance().getProperty("DESTINATION_PATH");
			zippedPath = MandateEncProperties.getInstance().getProperty("ZIPPED_PATH");
			signedPath = MandateEncProperties.getInstance().getProperty("SIGNED_PATH");
			failedFilesPath = MandateEncProperties.getInstance().getProperty("FAILED_FILES_PATH");
			backUpPath = MandateEncProperties.getInstance().getProperty("BACKUP_PATH");
			zippingFailedPath = MandateEncProperties.getInstance().getProperty("ZIPPING_FAILED_PATH");
			signingFailedPath = MandateEncProperties.getInstance().getProperty("SIGNING_FAILED_PATH");
			encryptingFailedPath = MandateEncProperties.getInstance().getProperty("ENCRYPTING_FAILED_PATH");
			threadSleepTimeString = MandateEncProperties.getInstance().getProperty("THREAD_SLEEP_TIME");
			fileProcessLimitString = MandateEncProperties.getInstance().getProperty("FILE_PROCESS_LIMIT");
			fileProcessLimit = Integer.parseInt(fileProcessLimitString);
			publicKeyPath = MandateEncProperties.getInstance().getProperty("PUBLIC_KEY_PATH");
			privateKeyPath = MandateEncProperties.getInstance().getProperty("PRIVATE_KEY_PATH");
			toProcessPath = MandateEncProperties.getInstance().getProperty("TO_PROCESS_PATH");
			nameStart = MandateEncProperties.getInstance().getProperty("NAME_STARTS_WITH");
			nameEnd = MandateEncProperties.getInstance().getProperty("NAME_ENDS_WITH");
			minFileNameLengthString = MandateEncProperties.getInstance().getProperty("MIN_FILE_NAME_LENGTH");
			minFileNameLength = Integer.parseInt(minFileNameLengthString);
			maxFileNameLengthString = MandateEncProperties.getInstance().getProperty("MAX_FILE_NAME_LENGTH");
			maxFileNameLength = Integer.parseInt(maxFileNameLengthString);
			noOfDays = MandateEncProperties.getInstance().getProperty("NO_OF_DAYS");
			sbiSrNo = MandateEncProperties.getInstance().getProperty("USER_ID");
			password = MandateEncProperties.getInstance().getProperty("PASSWORD");
			dbPwd = MandateEncProperties.getInstance().getProperty("dbpwd");
			dbUrl = MandateEncProperties.getInstance().getProperty("dburl");
			dbUser = MandateEncProperties.getInstance().getProperty("dbuser");
			Key = MandateEncProperties.getInstance().getProperty("Key");
			IV = MandateEncProperties.getInstance().getProperty("IV");
			
			sftpHost = MandateEncProperties.getInstance().getProperty("SFTP_HOST");
			sftpUsername = MandateEncProperties.getInstance().getProperty("SFTP_USERNAME");
			sftpPort = MandateEncProperties.getInstance().getProperty("SFTP_PORT");
			sftpPwd = MandateEncProperties.getInstance().getProperty("SFTP_PASSWORD");
			remoteDir = MandateEncProperties.getInstance().getProperty("REMOTE_DIR");
			localDir = MandateEncProperties.getInstance().getProperty("LOCAL_DIR");
			archiveDir = MandateEncProperties.getInstance().getProperty("ARCHIVE_DIR");
//			serverPrivateKeypath = MandateEncProperties.getInstance().getProperty("SERVER_PRIVATE_KEY_PATH");

			threadSleepTime = Integer.parseInt(threadSleepTimeString);
			tailName = MandateEncProperties.getInstance().getProperty("TAIL_NAME");
			Security.addProvider(new BouncyCastleProvider());
			privateKey = MandateUtility.getCertKeys(privateKeyPath, password);
			pubKey = MandateEncProperties.getInstance().getProperty("PUBLIC_CERT_PATH");
			pubCert = MandateUtility.loadX509Certificate(pubKey);
			privCert = MandateUtility.x509certget(privateKeyPath,password);
			Encodedpubcert = MandateUtility.base64Certificate(MandateLauncher.getPubCert());
			publicKey = MandateUtility.getPubkeyfrompath(publicKeyPath);
			pgpPublicKey = (new JcaPGPKeyConverter().getPGPPublicKey(PGPPublicKey.RSA_GENERAL, publicKey,new java.util.Date()));
		} catch (IOException ex) {
			log.error("Error while accessing properties file " + ex);
		} catch (Exception e) {
			log.error("Error while fetching data for variables " + e.getMessage());
		}
	}

	

	public static void main(String[] args) {

		while (true) {
			HashMap<String, Object> encdmap = new HashMap<String, Object>();
			log.info(
					"********************************  || AADESH_MANDATE_ENC UTILITY STARTED ||  ***********************************\n");

			try {
				boolean EODReached = false;
				boolean dbupdate = false;
				String Zone = "";
				Calendar cal = Calendar.getInstance();
				int dTm = Integer.parseInt(MandateLauncher.getNoOfDays());
				cal.add(Calendar.DATE, -dTm);

				int prevCalMonth = cal.get(Calendar.MONTH) + 1;
				int prevCalYear = cal.get(Calendar.YEAR);
				int prevCalDate = cal.get(Calendar.DATE);

				cal.add(Calendar.DATE, dTm);
				int currCalMonth = cal.get(Calendar.MONTH) + 1;
				int currCalYear = cal.get(Calendar.YEAR);
				int currCalDate = cal.get(Calendar.DATE);

				LocalDate startDate = LocalDate.of(prevCalYear, prevCalMonth, prevCalDate);
				LocalDate endDate = LocalDate.of(currCalYear, currCalMonth, currCalDate);

				File sourceFolder = new File(srcPath);
				File[] listOfFolders = sourceFolder.listFiles(File::isDirectory); //create,cancel,amend
				Integer totalnoofRecords;

				for (File folder : listOfFolders) {
					String folderName = folder.getName();
					File[] files = folder.listFiles();

					if (files != null && files.length > 0) {
						log.info("Number of files found in " + folder.getName() + " is : " + files.length
								+ ", now starting the processing.");
						totalnoofRecords = files.length;
						try {
							int cnt = 1;
							List<Path> batchFiles = new ArrayList<>();
							String toProcessFolderName = null;
							String currDate = new java.text.SimpleDateFormat("ddMMyyyy").format(new java.util.Date());
							boolean isPreviouslyProcessed = false;
							for (File file : files) {
								String[] parts = file.getName().split("-");
								String dateStr = parts[5];
								String finalName = "";
								if (parts.length == 8) { //OTH removed and added SBISrNo after sbin
									finalName = parts[0] + "-" + parts[1] + "-" + parts[2] + "-"
											+ parts[4].substring(0, 4) + MandateLauncher.getSbiSrNo() + "-" + currDate
											+ "-" + parts[6] + "-" + parts[7];
								}
								encdmap.put("FileName", file.getName());
								if (file.getName().contains("OTH")) {
									Zone = "OTH";
									encdmap.put("Zone", "OTH");
								} else if (file.getName().contains("SOU")) {
									encdmap.put("Zone", "SOU");
									Zone = "SOU";
								} else if (file.getName().contains("NOR")) {
									encdmap.put("Zone", "NOR");
									Zone = "NOR";
								}
								DateTimeFormatter formatter = DateTimeFormatter.ofPattern("ddMMyyyy");
								boolean flag = false;
								try {
									isPreviouslyProcessed = Manager.isFilepreviouslyProcessed(file.getName(),
											new Date());
									if (!isPreviouslyProcessed) {
										if (file.getName().length() > minFileNameLength
												&& file.getName().length() < maxFileNameLength) {
											LocalDate fileDate = LocalDate.parse(dateStr, formatter);
											if ((fileDate.isEqual(startDate) || fileDate.isAfter(startDate))
													&& (fileDate.isEqual(endDate) || fileDate.isBefore(endDate))) {
												if (file.getName().contains(nameStart)
														&& file.getName().contains(nameEnd)) {
													flag = true;
												} else {
													encdmap.put("ERROR_CODE", ErrorConstants.ERR01.name());
													encdmap.put("lastUpdatedtime", MandateUtility.getTimestamp());
													log.info(
															"FileName validation failed, Moving to Name validation failed path");
													Files.move(file.toPath(),
															Paths.get(failedFilesPath + File.separator
																	+ "NameValidationFailed" + File.separator
																	+ folderName + File.separator + file.getName()),
															StandardCopyOption.REPLACE_EXISTING);
													dbupdate = Manager.insertintoMandate_file_logs(encdmap, new Date());
													if (dbupdate == true) {
														log.info("Status updated in DB for File : " + file.getName());
													} else {
														log.info(
																"Unable to updated in DB for File : " + file.getName());
													}
												}
											} else {
												encdmap.put("ERROR_CODE", ErrorConstants.ERR03.name());
												encdmap.put("lastUpdatedtime", MandateUtility.getTimestamp());
												log.info(
														"Date validation failed, Moving to date validation failed path ");
												Files.move(file.toPath(),
														Paths.get(failedFilesPath + File.separator
																+ "DateValidationFailed" + File.separator + folderName
																+ File.separator + file.getName()),
														StandardCopyOption.REPLACE_EXISTING);
												dbupdate = Manager.insertintoMandate_file_logs(encdmap, new Date());
												if (dbupdate == true) {
													log.info("Status updated in DB for File : " + file.getName());
												} else {
													log.info("Unable to updated in DB for File : " + file.getName());
												}
											}
										} else {
											encdmap.put("ERROR_CODE", ErrorConstants.ERR01.name());
											encdmap.put("lastUpdatedtime", MandateUtility.getTimestamp());

//											log.infoln("File Name length validation failed");
											log.info(
													"File name length validation failed, Moving to name length validation failed path");
											Files.move(file.toPath(),
													Paths.get(failedFilesPath + File.separator
															+ "NameLengthValidationFailed" + File.separator + folderName
															+ File.separator + file.getName()),
													StandardCopyOption.REPLACE_EXISTING);
											dbupdate = Manager.insertintoMandate_file_logs(encdmap, new Date());
											if (dbupdate == true) {
												log.info("Status updated in DB for File : " + file.getName());
											} else {
												log.info("Unable to updated in DB for File : " + file.getName());
											}
										}
									} else {
										encdmap.put("ERROR_CODE", ErrorConstants.ERR04.name());
										encdmap.put("lastUpdatedtime", MandateUtility.getTimestamp());
										log.info("File is already processed , Moving to name validation failed path");
										Files.move(file.toPath(),
												Paths.get(failedFilesPath + File.separator + "NameValidationFailed"
														+ File.separator + folderName + File.separator
														+ file.getName()),
												StandardCopyOption.REPLACE_EXISTING);
										dbupdate = Manager.insertintoMandate_file_logs(encdmap, new Date());
										if (dbupdate == true) {
											log.info("Status updated in DB for File : " + file.getName());
										} else {
											log.info("Unable to updated in DB for File : " + file.getName());
										}
									}
								} catch (DateTimeParseException dtpe) {
									log.error("Date parsing failed, moving to date validation failed path "
											+ dtpe.getMessage());
								} catch (IOException ex) {
									log.error("IO Exception occured " + ex);
								} catch (Exception e) {
									log.info("Failed to validate the filename, Moving to name validation failed path");
									Files.move(file.toPath(),
											Paths.get(failedFilesPath + File.separator + "NameLengthValidationFailed"
													+ File.separator + folderName + File.separator + file.getName()),
											StandardCopyOption.REPLACE_EXISTING);
								}

								if (flag) {
									File toProcessFolderPath = new File(MandateLauncher.getToProcessPath());
									
//									if (batchFiles.isEmpty() && toProcessFolderPath.listFiles().length != 0) {
//										String tailName = getTailName();
//										String srNo = String.format("%06d", cnt);
//										toProcessFolderName = "MMS-" + folder.getName() + "-SBIN-SBIN" + tailName + "-"
//												+ currDate + "-" + srNo + "-ACCEPT";
//										MandateUtility.createToProcessFolder(toProcessFolderName, folder.getName());
//										cnt++;
//									} else {
//										toProcessFolderName = toProcessFolderPath.listFiles()[0].toString(); 
//									}
									if (batchFiles.isEmpty()) {
										String tailName = getTailName();
										String srNo = String.format("%06d", cnt);
										toProcessFolderName = "MMS-" + folder.getName() + "-SBIN-SBIN" + tailName + "-"
												+ currDate + "-" + srNo + "-ACCEPT";
										MandateUtility.createToProcessFolder(toProcessFolderName, folder.getName());
										cnt++;
									} 
									Path source = Paths.get(getSrcPath(), folder.getName(), file.getName());
									Path destDir = Paths.get(getToProcessPath(), folder.getName(), toProcessFolderName);
									Path dest = destDir.resolve(finalName);
									encdmap.put("FolderName", toProcessFolderName);
									encdmap.put("lastUpdatedtime", MandateUtility.getTimestamp());
									Files.createDirectories(destDir);
									if (Files.exists(source)) {
										Files.move(source, dest, StandardCopyOption.REPLACE_EXISTING);
										batchFiles.add(dest);
									} else {
										log.error("Source not found , skipping : " + source.toAbsolutePath());
									}
									dbupdate = Manager.insertintoMandate_file_logs(encdmap, new Date());
									if (dbupdate == true) {
										log.info("Status updated in DB for File : " + file.getName());
									} else {
										log.info("Unable to updated in DB for File : " + file.getName());
									}

									if (batchFiles.size() == fileProcessLimit) {
										log.info("Batch ready (" + batchFiles.size()
												+ " files). Launching mandateMain for : " + toProcessFolderName);
										ExecutorService service = Executors.newSingleThreadExecutor();
										Runnable aadeshMain = new MandateMain(destDir.toFile(), folder.getName(),
												totalnoofRecords, Zone);
										service.execute(aadeshMain);
										service.shutdown();

										batchFiles.clear();
										toProcessFolderName = null;
									}
								} else {
									log.info("Failed to validate the filename, hence unable to add to batch");
								}
							}

							if (!batchFiles.isEmpty() && EODReached) {
								Path finalDir = batchFiles.get(0).getParent();
								log.info("Final batch (" + batchFiles.size()
										+ " files). Launching MandateMain for final batch");

								ExecutorService service = Executors.newSingleThreadExecutor();
								Runnable aadeshMain = new MandateMain(finalDir.toFile(), folder.getName(),
										totalnoofRecords, Zone);
								service.execute(aadeshMain);
								service.shutdown();
								batchFiles.clear();
							}
						} catch (SecurityException se) {
							log.error("Security exception during file batch processing " + se.getMessage());
						} catch (IOException ex) {
							log.error("Unable to access files : " + ex.getMessage());
						} catch (Exception e) {
							log.info("Error executing the encryption task : " + e.getMessage());
						}
					} else {
						files = folder.listFiles();
					}
				}
				log.info("There are no files available to process, hence thread is going to sleep for "
						+ threadSleepTime);
				Thread.sleep(threadSleepTime);

			} catch (Exception e) {
				log.info("Error occured during validation :" + e);
			} finally {
				log.info(
						"********************************  || MANDATE_ENC UTILITY ENDED ||  ***********************************\n");
			}
		}
	}
}
