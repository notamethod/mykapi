package org.dpr.mykeys.app.keystore;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.apache.commons.lang.StringUtils;

import org.dpr.mykeys.app.KeyTools;
import org.dpr.mykeys.app.KeyToolsException;
import org.dpr.mykeys.app.certificate.CertificateValue;

public class KeystoreBuilder extends KeyTools {

	KeyStore keystore;

	/**
	 * Create a keystore of type 'ksType' with filename 'name'
	 * 
	 * @param format
	 *            .toString()
	 * @param name
	 * @param password
	 * @throws Exception
	 */
	public KeystoreBuilder create(StoreFormat format, String name, char[] password) throws Exception {
		KeyStore ks = null;
		try {
			ks = KeyStore.getInstance(format.toString());

			ks.load(null, password);
			OutputStream fos = new FileOutputStream(new File(name));
			ks.store(fos, password);
			fos.close();
		} catch (Exception e) {
			throw new Exception(e);
		}
		keystore = ks;
		return this;

	}

	public KeyStore get() {
		return keystore;
	}

	public void addCertToKeyStoreNew(X509Certificate cert, KeyStoreInfo ksInfo, CertificateValue certInfo)
			throws KeyToolsException {
		KeyStore kstore = loadKeyStore(ksInfo.getPath(), ksInfo.getStoreFormat(), ksInfo.getPassword()).get();
		saveCertChain(kstore, cert, certInfo);
		saveKeyStore(kstore, ksInfo);
	}

	public void addCert(X509Certificate cert, KeyStoreInfo ksInfo, CertificateValue certInfo) throws KeyToolsException {
		saveCertChain(keystore, cert, certInfo);
		saveKeyStore(keystore, ksInfo);
	}

	@Deprecated
	public KeystoreBuilder addCert(X509Certificate[] xCerts, KeyStoreInfo ksInfo, CertificateValue certInfo, char[] password)
			throws KeyToolsException {
		// FIXME
		if (ksInfo.getStoreType().equals(StoreLocationType.INTERNAL)) {
			certInfo.setPassword(password);
		}

		saveCertChain(keystore, xCerts[0], certInfo);
		saveKeyStore(keystore, ksInfo);
		return this;
	}

	public KeystoreBuilder addCert(KeyStoreInfo ksInfo, CertificateValue certInfo, char[] password) throws KeyToolsException {

		// FIXME
		if (ksInfo.getStoreType().equals(StoreLocationType.INTERNAL)) {
			certInfo.setPassword(password);
		}

		saveCertChain(keystore, certInfo);
		saveKeyStore(keystore, ksInfo);
		return this;
	}

	private String saveCertChain(KeyStore keystore, CertificateValue certInfo) throws KeyToolsException {

		if (StringUtils.isBlank(certInfo.getAlias())) {
			BigInteger bi = KeyTools.RandomBI(30);
			certInfo.setAlias(bi.toString(16));
		}
		try {
			// pas bonne chaine
			// X509Certificate x509Cert = (X509Certificate) cert;

			if (certInfo.getPrivateKey() == null) {
				keystore.setCertificateEntry(certInfo.getAlias(), certInfo.getCertificate());
			} else {
				Certificate[] chaine = certInfo.getCertificateChain();

				keystore.setKeyEntry(certInfo.getAlias(), certInfo.getPrivateKey(), certInfo.getPassword(), chaine);
			}

		} catch (KeyStoreException e) {
			throw new KeyToolsException("Sauvegarde du certificat impossible:" + certInfo.getAlias(), e);
		}
		return certInfo.getAlias();

	}

	public KeystoreBuilder removeCert(CertificateValue certificateInfo) throws KeyToolsException, KeyStoreException {

		keystore.deleteEntry(certificateInfo.getAlias());

		return this;
	}

	public KeystoreBuilder load(KeyStoreInfo ksin) throws KeyToolsException {
		loadKeyStore(ksin.getPath(), ksin.getStoreFormat(), ksin.getPassword());
		return this;
	}

	public void save(KeyStoreInfo ksInfo) throws KeyToolsException {

		try {
			OutputStream fos = new FileOutputStream(new File(ksInfo.getPath()));
			keystore.store(fos, ksInfo.getPassword());
			fos.close();
		} catch (FileNotFoundException e) {
			throw new KeyToolsException("Echec de sauvegarde du magasin impossible:" + ksInfo.getPath(), e);
		} catch (KeyStoreException e) {
			throw new KeyToolsException("Echec de sauvegarde du magasin impossible:" + ksInfo.getPath(), e);
		} catch (NoSuchAlgorithmException e) {
			throw new KeyToolsException("Echec de sauvegarde du magasin impossible:" + ksInfo.getPath(), e);
		} catch (CertificateException e) {
			throw new KeyToolsException("Echec de sauvegarde du magasin impossible:" + ksInfo.getPath(), e);
		} catch (IOException e) {
			throw new KeyToolsException("Echec de sauvegarde du magasin impossible:" + ksInfo.getPath(), e);
		}
	}

	/**
	 * 
	 * @param ksName
	 * @param format
	 * @param pwd
	 * @return
	 * @throws KeyToolsException
	 */
	public KeystoreBuilder loadKeyStore(String ksName, StoreFormat format, char[] pwd) throws KeyToolsException {
		// KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		String type = StoreFormat.getValue(format);
		KeyStore ks = null;
		try {
			try {
				ks = KeyStore.getInstance(type, "BC");
			} catch (Exception e) {
				ks = KeyStore.getInstance("JKS");
			}

			// get user password and file input stream

			java.io.FileInputStream fis = new java.io.FileInputStream(ksName);
			ks.load(fis, pwd);
			fis.close();
		} catch (KeyStoreException e) {
			throw new KeyToolsException("Echec du chargement de:" + ksName, e);

		} catch (FileNotFoundException e) {
			throw new KeyToolsException("Fichier non trouvé:" + ksName + ", " + e.getCause(), e);
		} catch (NoSuchAlgorithmException e) {
			throw new KeyToolsException("Format inconnu:" + ksName + ", " + e.getCause(), e);
		} catch (CertificateException e) {
			throw new KeyToolsException("Echec du chargement de:" + ksName + ", " + e.getCause(), e);
		} catch (IOException e) {
			throw new KeyToolsException("Echec du chargement de:" + ksName + ", " + e.getCause(), e);
		}
		keystore = ks;
		return this;

	}

	public KeyStore loadKeyStore2(String ksName, String type, char[] pwd) throws KeyToolsException {
		// KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());

		KeyStore ks = null;
		try {
			try {
				ks = KeyStore.getInstance(type, "BC");
			} catch (Exception e) {
				ks = KeyStore.getInstance("JKS");
			}

			// get user password and file input stream

			java.io.FileInputStream fis = new java.io.FileInputStream(ksName);
			ks.load(fis, pwd);
			fis.close();
		} catch (KeyStoreException e) {
			throw new KeyToolsException("Echec du chargement de:" + ksName, e);

		} catch (FileNotFoundException e) {
			throw new KeyToolsException("Fichier non trouvé:" + ksName, e);
		} catch (NoSuchAlgorithmException e) {
			throw new KeyToolsException("Format inconnu:" + ksName, e);
		} catch (CertificateException e) {
			throw new KeyToolsException("Echec du chargement de:" + ksName, e);
		} catch (IOException e) {
			throw new KeyToolsException("Echec du chargement de:" + ksName, e);
		}
		return ks;
	}

	public void saveCertChain(KeyStore kstore, X509Certificate cert, CertificateValue certInfo)
			throws KeyToolsException {
		try {
			// pas bonne chaine
			// X509Certificate x509Cert = (X509Certificate) cert;

			if (certInfo.getPrivateKey() == null) {
				kstore.setCertificateEntry(certInfo.getAlias(), cert);
			} else {
				Certificate[] chaine = null;
				if (certInfo.getCertificateChain() != null) {
					chaine = certInfo.getCertificateChain();
				} else {
					chaine = new Certificate[] { cert };
				}
				kstore.setKeyEntry(certInfo.getAlias(), certInfo.getPrivateKey(), certInfo.getPassword(), chaine);
			}

		} catch (KeyStoreException e) {
			throw new KeyToolsException("Sauvegarde du certificat impossible:" + certInfo.getAlias(), e);
		}
	}
}
