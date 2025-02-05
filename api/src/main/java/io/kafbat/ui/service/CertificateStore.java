package io.kafbat.ui.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.kafbat.ui.model.CertificateCreationDTO;
import io.kafbat.ui.model.CertificateDTO;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class CertificateStore {

  private static final String caKeyPassword = "password";
  private static final String caCertFilePath = "/etc/kafkaui/secrets/ca-cert";
  private static final String caKeyFilePath = "/etc/kafkaui/secrets/ca-key";

  public static final String certStorePath = "/etc/kafkaui/certStore/";
  private static final String metadataFile = "/etc/kafkaui/certStore/certificates.json";

  private synchronized void appendCertificateMetadata(CertificateDTO certificate) throws Exception {
    Path metadataFilePath = Paths.get(metadataFile);
    ObjectMapper mapper = new ObjectMapper();

    // Read existing metadata if the file exists, else start with an empty list
    List<CertificateDTO> metadataList = new ArrayList<>();
    if (Files.exists(metadataFilePath)) {
      metadataList = new ArrayList<>(Arrays.asList(
          mapper.readValue(metadataFilePath.toFile(), CertificateDTO[].class)
      ));
    }

    // Find existing certificate by certUserName
    Optional<CertificateDTO> existingCert = metadataList.stream()
        .filter(cert -> cert.getCertificateUserName().equals(certificate.getCertificateUserName()))
        .findFirst();

    if (existingCert.isPresent()) {
      // Update existing certificate
      existingCert.get().setPassword(certificate.getPassword());  // Update required fields
      existingCert.get().setCreation(certificate.getCreation());
      existingCert.get().setExpiration(certificate.getExpiration());
      existingCert.get().setFileName(certificate.getFileName());
      existingCert.get().setAdminLdapGroup(certificate.getAdminLdapGroup());
      log.info("Updated existing certificate for {}", certificate.getCertificateUserName());
    } else {
      // Add new certificate
      metadataList.add(certificate);
      log.info("Added new certificate for {}", certificate.getCertificateUserName());
    }

    // Write back the updated metadata list to the file
    mapper.writerWithDefaultPrettyPrinter().writeValue(metadataFilePath.toFile(), metadataList);

    log.info("Updated certificate metadata stored in {}", metadataFilePath);
  }

  @SneakyThrows
  public List<CertificateDTO> getAllCertificateMetadata() {
    Path metadataFilePath = Paths.get(metadataFile);

    if (!Files.exists(metadataFilePath)) {
      log.warn("No metadata file found at {}, returning an empty list", metadataFilePath);
      return Collections.emptyList();
    }

    ObjectMapper mapper = new ObjectMapper();

    // Read and return the metadata list
    return Arrays.asList(
        mapper.readValue(metadataFilePath.toFile(), CertificateDTO[].class)
    );
  }

  public CertificateDTO storeCertificate(CertificateCreationDTO certificateCreationDto) throws Exception {
    // Add BouncyCastle provider
    Security.addProvider(new BouncyCastleProvider());

    // Set variables
    var clientSystem = certificateCreationDto.getCertificateUserName();
    String keystoreFilePath = certStorePath + clientSystem + "-keystore.p12";
    String keystorePassword = certificateCreationDto.getPassword();

    Date notAfter = new Date(System.currentTimeMillis()
        + certificateCreationDto.getExpirationInDays().longValue() * 24 * 60 * 60 * 1000); // 2 years validity

    // Step 1: Create client key/cert and keystore
    KeyPair clientKeyPair = generateKeyPair();

    // Step 2: Create a keystore and store the client key and certificate
    KeyStore keyStore = KeyStore.getInstance("PKCS12");
    keyStore.load(null, keystorePassword.toCharArray());

    // Step 3: Generate a certificate request (CSR)
    byte[] csr = generateCertificateRequest(clientKeyPair, clientSystem);

    // Step 4: Sign the CSR with the CA private key
    X509Certificate caCert = loadCertificate();
    PrivateKey caPrivateKey = loadPrivateKey();
    X509Certificate signedCert = signCertificateRequest(csr, clientSystem, caCert, caPrivateKey, notAfter);

    // Step 5: Import the CA cert and signed client cert into the keystore
    keyStore.setCertificateEntry("CARoot", caCert);

    // First, remove the original self-signed certificate, if any
    if (keyStore.containsAlias(clientSystem)) {
      keyStore.deleteEntry(clientSystem);
    }

    // Then, insert the signed certificate and private key under the same alias
    Certificate[] chain = new Certificate[] { signedCert, caCert };  // Signed cert followed by CA cert in the chain
    keyStore.setKeyEntry(clientSystem, clientKeyPair.getPrivate(), keystorePassword.toCharArray(), chain);

    // Step 6: Save the keystore to a file
    try (FileOutputStream fos = new FileOutputStream(keystoreFilePath)) {
      keyStore.store(fos, keystorePassword.toCharArray());
    }

    log.info("Keystore created successfully with signed certificate and CA certificate.");

    var cert = new CertificateDTO(
        clientSystem,
        certificateCreationDto.getPassword(),
        new Date(System.currentTimeMillis()).toString(),
        notAfter.toString(),
        keystoreFilePath,
        certificateCreationDto.getAdminLdapGroup());

    appendCertificateMetadata(cert);

    return cert;
  }

  // Method to generate a keypair (RSA)
  private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048);  // 2048 bit RSA key pair
    return keyPairGenerator.generateKeyPair();
  }

  // Method to generate a certificate request (CSR)
  private byte[] generateCertificateRequest(KeyPair keyPair, String clientSystem) throws Exception {
    JcaPKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
        new X500Name("CN=" + clientSystem), keyPair.getPublic());
    JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withRSA");
    signerBuilder.setProvider("BC");
    ContentSigner signer = signerBuilder.build(keyPair.getPrivate());

    PKCS10CertificationRequest csr = p10Builder.build(signer);
    return csr.getEncoded();
  }

  // Method to sign a CSR using the CA private key
  private X509Certificate signCertificateRequest(byte[] csr,
                                                       String clientSystem,
                                                       X509Certificate caCert,
                                                       PrivateKey caPrivateKey,
                                                       Date notAfter) throws Exception {
    // Parse the CSR (Certificate Signing Request)
    PKCS10CertificationRequest p10Request = new PKCS10CertificationRequest(csr);

    // Extract the issuer from the CA certificate as X500Name
    X500Name issuer = X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded());

    // Extract the SubjectPublicKeyInfo from the CSR
    SubjectPublicKeyInfo subjectPublicKeyInfo = p10Request.getSubjectPublicKeyInfo();

    // Convert the SubjectPublicKeyInfo into an AsymmetricKeyParameter
    AsymmetricKeyParameter asymmetricKeyParam = PublicKeyFactory.createKey(subjectPublicKeyInfo);

    // Convert the AsymmetricKeyParameter into a Java PublicKey
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    RSAPublicKey rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(
        new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded()));

    // Create a serial number and validity period
    BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
    Date notBefore = new Date(System.currentTimeMillis());
    //Date notAfter = new Date(System.currentTimeMillis() + 730L * 24 * 60 * 60 * 1000); // 2 years validity

    // Build the certificate using the CA's certificate and private key
    JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
        issuer, serial, notBefore, notAfter, p10Request.getSubject(), rsaPublicKey
    );

    // Use the CA's private key to sign the certificate
    JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256withRSA");
    contentSignerBuilder.setProvider("BC");
    ContentSigner contentSigner = contentSignerBuilder.build(caPrivateKey);

    // Convert the builder to a certificate and return
    X509Certificate signedCert = new JcaX509CertificateConverter().setProvider("BC")
        .getCertificate(certBuilder.build(contentSigner));

    // Verify the signed certificate using the CA's public key
    signedCert.verify(caCert.getPublicKey());
    return signedCert;
  }


  // Method to load a certificate from a file (PEM)
  private X509Certificate loadCertificate() throws Exception {
    try (FileReader certReader = new FileReader(caCertFilePath);
         PEMParser pemParser = new PEMParser(certReader)) {
      Object parsedObject = pemParser.readObject();

      // Convert the parsed certificate (X509CertificateHolder) into a Java X509Certificate
      if (parsedObject instanceof X509CertificateHolder) {
        X509CertificateHolder certHolder = (X509CertificateHolder) parsedObject;
        return new JcaX509CertificateConverter().getCertificate(certHolder);
      } else {
        throw new IllegalArgumentException("The file does not contain a valid X509 certificate.");
      }
    }
  }

  // Method to load a private key from a PEM file
  private PrivateKey loadPrivateKey() throws Exception {
    try (PemReader pemReader = new PemReader(new FileReader(caKeyFilePath))) {
      byte[] encoded = pemReader.readPemObject().getContent();
      PKCS8EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = new PKCS8EncryptedPrivateKeyInfo(encoded);
      InputDecryptorProvider decryptorProvider = new JceOpenSSLPKCS8DecryptorProviderBuilder()
          .build(caKeyPassword.toCharArray());
      PrivateKeyInfo privateKeyInfo = encryptedPrivateKeyInfo.decryptPrivateKeyInfo(decryptorProvider);
      return new JcaPEMKeyConverter().getPrivateKey(privateKeyInfo);
    }
  }

}
