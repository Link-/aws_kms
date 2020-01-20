### Installation

#### Pre-Requisites:
1. Make sure your `~/.aws/credentials` is populated with your account's access key and secrets. This POC will attempt 
to read the keys NOT in the default profile but a profile named `personal`
2. Create a new CMK in KMS using the following configuration:
    ```
    Key Type: Asymmetric
    Origin: AWS_KMS
    Key Spec: RSA_4096
    Key Usage: Encrypt and decrypt
    Encryption algorithms: 
    RSAES_OAEP_SHA_1
    RSAES_OAEP_SHA_256
    ```
3. 


#### References
1. http://jamesabrannan.com/2019/06/14/aws-key-management-system-kms-to-encrypt-and-decrypt-using-the-asw-java-2-sdk/
2. https://proandroiddev.com/security-best-practices-symmetric-encryption-with-aes-in-java-7616beaaade9