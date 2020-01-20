package com.neobank.kms.kmsdb.Service;

import com.neobank.kms.kmsdb.Model.User;
import com.neobank.kms.kmsdb.Repository.UserRepository;
import org.springframework.data.util.Pair;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptResponse;

import java.util.Base64;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;

@Service
public class KmsService {

    private final static String cmkArn = "arn:aws:kms:eu-west-1:730880032795:key/95ae5ce4-862f-49eb-b103-05d06cd0b426";
    private final static String cmkAlias = "tw_poc_cmk";
    private final static Region region = Region.EU_WEST_1;
    private final static String profileName = "personal";
    private KmsClient kmsClient;
    @Autowired
    private UserRepository users;

    public KmsService() {
        ProfileCredentialsProvider credentialsProvider = ProfileCredentialsProvider
                .builder()
                .profileName(profileName)
                .build();

        kmsClient = KmsClient.builder()
                .credentialsProvider(credentialsProvider)
                .region(region)
                .build();
    }

    /**
     * Takes a customerId and registrationCode and creates a new record in the database.
     * The registrationCode will go through the entire encryption mechanism
     *
     * @param customerId
     * @param registrationCode
     * @return User
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     */
    public User createUser(String customerId, String registrationCode) throws IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        Pair<String, String> keyRegistrationCodePair = encryptRegistrationCode(registrationCode);
        User createdUser = users.saveAndFlush(new User(customerId,
                                keyRegistrationCodePair.getSecond(),
                                cmkAlias,
                                cmkArn,
                                keyRegistrationCodePair.getFirst()));
        return createdUser;
    }

    /**
     * Fetch a record from the DB with a customerId and decrypt the registration code
     *
     * @param customerId
     * @return User
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidAlgorithmParameterException
     */
    public User getUser(String customerId) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        User fetchedUser = users.findByCustomerId(customerId).get(0);
        return new User(fetchedUser.getCustomerId(),
                decryptRegistrationCode(fetchedUser.getEncryptionKey(),
                        fetchedUser.getEncryptedRegistrationCode()),
                fetchedUser.getCmkAlias(),
                fetchedUser.getCmkId(),
                fetchedUser.getEncryptionKey());
    }

    /**
     * Takes a Secret Key that was used in the first encryption step and
     * encrypts that key using the CMK stored in KMS
     *
     * This key will be sent to KMS. The CMK never leaves the HSM.
     *
     * @param key
     * @return Base64 encoded SecretKey
     */
    private String encryptAESKey(SecretKey key) {
        SdkBytes keyBytesArray = SdkBytes.fromByteArray(key.getEncoded());
        EncryptRequest request = EncryptRequest.builder()
                .keyId(cmkArn)
                .plaintext(keyBytesArray)
                .encryptionAlgorithm("RSAES_OAEP_SHA_256")
                .build();
        EncryptResponse response = kmsClient.encrypt(request);
        return Base64.getEncoder().encodeToString(response.ciphertextBlob().asByteArray());
    }

    /**
     * Takes a Base64 encoded encrypted key and attemps to decrypt it using the CMK
     * stored in KMS.
     *
     * @param key
     * @return Byte array of the decrypted Secret Key
     */
    private byte[] decryptAESKey(String key) {
        SdkBytes encryptedKey = SdkBytes.fromByteArray(Base64.getDecoder().decode(key));
        DecryptRequest request = DecryptRequest.builder()
                .keyId(cmkArn)
                .encryptionAlgorithm("RSAES_OAEP_SHA_256")
                .ciphertextBlob(encryptedKey).build();
        DecryptResponse response = kmsClient.decrypt(request);
        return response.plaintext().asByteArray();
    }

    /**
     * Uses a randomized IV (acts like a salt) and a randomized Secret Key to encrypt
     * the registrationCode with AES-GCM.
     *
     * It will combine the IV and encrypted registrationCode into a byte array and then
     * encode that byte array to Base64 for storage in the database.
     *
     * This method will also encrypt the Secret Key used in encrypting the registrationCode
     * with the CMK (Customer Master Key) stored in KMS.
     *
     * It will return a tuple of the encrypted secret key and encrypted registrationCode.
     *
     * @param registrationCode
     * @return Pair of encrypted secret key and encrypted registrationCode
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     */
    private Pair<String, String> encryptRegistrationCode(String registrationCode) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException {
        byte[] IV = getNextIv();
        SecretKey secretKey = getNextKey();
        byte[] registrationCodeArray = registrationCode.getBytes();

        // Initialize the cipher and encrypt the registrationCode
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, IV);
        cipher.init(Cipher.ENCRYPT_MODE,
                secretKey,
                parameterSpec);
        byte[] encryptedRegistrationCode = cipher.doFinal(registrationCodeArray);

        // Combine the encryptedRegistrationCode with the IV so that they're both
        // stored in the database
        ByteBuffer byteBuffer = ByteBuffer.allocate(4 + IV.length + encryptedRegistrationCode.length);
        byteBuffer.putInt(IV.length);
        byteBuffer.put(IV);
        byteBuffer.put(encryptedRegistrationCode);
        byte[] encryptedPayload = byteBuffer.array();

        // Encrypt the secret key with the CMK stored in KMS and return the result
        // in a tuple along with the encryptedRegistrationCode and IV
        return Pair.of(encryptAESKey(secretKey),
                Base64.getEncoder().encodeToString(encryptedPayload));
    }

    /**
     * This method takes a Secret Key (key) stored in the database along with an
     * encryptedRegistrationCode, it will use the CMK (Customer Master Key) stored in KMS
     * to first decrypt the secret key.
     *
     * The decrypted secret key will be used to decrypt the encryptedRegistrationCode.
     *
     * Once that is achieve this method will return the decrypted registrationCode as a
     * String.
     *
     * @param key
     * @param encryptedRegistrationCode
     * @return Decrypted registrationCode in plaintext
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    private String decryptRegistrationCode(String key, String encryptedRegistrationCode) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException {
        byte[] decryptedSecretKey = decryptAESKey(key);
        // Extract the IV and encryptedRegistrationCode from the combined payload that was stored
        // in the DB
        ByteBuffer byteBuffer = ByteBuffer.wrap(Base64.getDecoder().decode(encryptedRegistrationCode));

        // First 4 bytes are the IV length value
        int ivLength = byteBuffer.getInt();

        if (ivLength < 12 || ivLength >= 16) { // check input parameter
            throw new IllegalArgumentException("invalid iv length");
        }
        // The IV is extracted based on the length value that was extracted previously
        byte[] IV = new byte[ivLength];
        byteBuffer.get(IV);
        // The encrypted registration code is what remains
        byte[] cipherText = new byte[byteBuffer.remaining()];
        byteBuffer.get(cipherText);

        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE,
                new SecretKeySpec(decryptedSecretKey, "AES"),
                new GCMParameterSpec(128, IV));
        byte[] registrationCode = cipher.doFinal(cipherText);

        return new String(registrationCode);
    }

    /**
     * Generates a random (16 bytes) 128 bit key
     *
     * @return a 128 bit key
     */
    private static SecretKey getNextKey() {
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        return secretKey;
    }

    /**
     * Generates a 12 bytes random IV to be used for the AES 256 encryption
     *
     * The basic idea of an IV is to prepend a bit of random content to each message,
     * in a principled way. How this works precisely depends on the mode.
     * (The core AES operation only works on 16-byte blocks. A mode is a way to extend this
     * to longer messages.) For example, with CBC, the encryption of each block is computed
     * from the key, the plaintext block and the ciphertext of the previous block; for the very
     * first block, the IV is used instead of the ciphertext of the non-existent previous block.
     * The IV is normally sent in cleartext alongside the ciphertext, usually it is sent a the first
     * 16 bytes of the encrypted message.
     *
     * CTR mode technically uses a counter and not an IV, but operationally they work very
     * similarly: a 16-byte random value is generated at random by the sender and sent at the
     * beginning of the encrypted message. With CTR mode, reusing that value for another
     * message is catastrophic, because CTR works by XORing the plaintext with a pseudorandom
     * stream deduced from the key and counter. If you have two encrypted messages that use the
     * same counter value, their XOR is the XOR of the two plaintexts.
     *
     * GCM is basically CTR mode which also calculates an authentication tag sequentially during
     * encryption. This authentication tag is then usually appended to the cipher text. Its size
     * is an important security property, so it should be at least 128 bit long.
     *
     * @return a 12 bytes random IV
     */
    private static byte[] getNextIv() {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        return iv;
    }
}
