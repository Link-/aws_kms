#### ⚠️ This is a work in progress, this is not production ready.

### Installation

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
3. Open the `KmsService.java` file and update the member variables to match your configuration
    ```
    private final static String cmkArn = "arn:aws:kms:eu-west-1:XXX:key/XXX";
    private final static String cmkAlias = "KEY_ALIAS";
    private final static Region region = Region.EU_WEST_1;
    private final static String profileName = "personal";
    ```
4. Build: `mvn clean install`
5. Run: `mvn spring-boot:run`

### Usage

##### Create a User:
*Request:*
```
curl --location --request POST 'localhost:8080/customer' \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --form 'customerId=1111111' \
    --form 'registrationCode=e54c7f888147b5596e721019bc023eb073e108a01b4d3589ce94c92282b0c17a'
```

*Example Response:*
```
{
    "id": 1,
    "customerId": "1111111",
    "encryptedRegistrationCode": "AAAADA5rOCQ3i0zw7t9/RiUUxmOOem3l/Lzpze8n9xZg2Y/aVMN43h05fJQSlSl7R0jIc5YBsltgsOaglVUFzMBaaNLmX94zOeNhUi5X+ol95hpV/yFcncGt3/G7fMCm",
    "cmkAlias": "tw_poc_cmk",
    "cmkId": "arn:aws:kms:eu-west-1:730880032795:key/95ae5ce4-862f-49eb-b103-05d06cd0b426",
    "encryptionKey": "TKEsGWuv2Q3zb/NnlIlJq3NavKjpYQ09MHj7nny/Xvk+wovHXwOFaKBOQ0Ctkog8/ENVmF3CmzqRmMeiMqwGV5zGID58kn61nPtzeU4nc27XTj+mUxTq9VOCBZ4M+Op+BNUUOOmFa8sNhIk4z/QFFk+7aiU/PGZKcku3o9PrwDTHR9MMerujaBlhKury0rI0daan5wPQmUZw8cd8DoDMGYsdEa4D3raK8nPsadOiJbIEvNvhQGBuWaDCEcCwmR4u7cwVd+EgElRlquRvwP+HF4WLyXdtuNzVVfbWOZQorajoKPL63xv+HILiKkcHD2bo5hrZIpDHVnkfP9sWtrPH9SiB8710XWQJMg7FIGVgHe9M/1Fa+LyNTxzR6EJsWa+Z+vnY7JKsmRynRDup4liSX7OLRYinWOvgFppPxceNuR6DfxOl062FYgksIfbRbCnhAZuZ/EyxAmLx6XdQXIPhjm0dcwrvodPPO/XB95slRmEzzsi0WeNqqFnKvtt91vn6FnDLU4BV143EWKcXysdy0fFdWMbXxXNztUGIt4sMTEd0Xr88FNFY4ZpkjtCcPb1ZJi0+su4CzXSSaDg3Rw4G46oEtqHNzLn0EG2a00A2vrsM0sT5J1M8MkefsoX1qGPsy99RV4JiWMu8zh6FfNiVd97gxehqWATZi1P0qm4EeXw="
}
```

##### Get a User:


*Request:*
```
curl --location --request GET 'localhost:8080/customer' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--form 'customerId=1111111'
```

*Example Response:* 
```
{
    "id": null,
    "customerId": "1111111",
    "encryptedRegistrationCode": "e54c7f888147b5596e721019bc023eb073e108a01b4d3589ce94c92282b0c17a",
    "cmkAlias": "tw_poc_cmk",
    "cmkId": "arn:aws:kms:eu-west-1:730880032795:key/95ae5ce4-862f-49eb-b103-05d06cd0b426",
    "encryptionKey": "TKEsGWuv2Q3zb/NnlIlJq3NavKjpYQ09MHj7nny/Xvk+wovHXwOFaKBOQ0Ctkog8/ENVmF3CmzqRmMeiMqwGV5zGID58kn61nPtzeU4nc27XTj+mUxTq9VOCBZ4M+Op+BNUUOOmFa8sNhIk4z/QFFk+7aiU/PGZKcku3o9PrwDTHR9MMerujaBlhKury0rI0daan5wPQmUZw8cd8DoDMGYsdEa4D3raK8nPsadOiJbIEvNvhQGBuWaDCEcCwmR4u7cwVd+EgElRlquRvwP+HF4WLyXdtuNzVVfbWOZQorajoKPL63xv+HILiKkcHD2bo5hrZIpDHVnkfP9sWtrPH9SiB8710XWQJMg7FIGVgHe9M/1Fa+LyNTxzR6EJsWa+Z+vnY7JKsmRynRDup4liSX7OLRYinWOvgFppPxceNuR6DfxOl062FYgksIfbRbCnhAZuZ/EyxAmLx6XdQXIPhjm0dcwrvodPPO/XB95slRmEzzsi0WeNqqFnKvtt91vn6FnDLU4BV143EWKcXysdy0fFdWMbXxXNztUGIt4sMTEd0Xr88FNFY4ZpkjtCcPb1ZJi0+su4CzXSSaDg3Rw4G46oEtqHNzLn0EG2a00A2vrsM0sT5J1M8MkefsoX1qGPsy99RV4JiWMu8zh6FfNiVd97gxehqWATZi1P0qm4EeXw="
}
```

#### References
1. https://aws.amazon.com/kms/faqs/
2. http://jamesabrannan.com/2019/06/14/aws-key-management-system-kms-to-encrypt-and-decrypt-using-the-asw-java-2-sdk/
3. https://proandroiddev.com/security-best-practices-symmetric-encryption-with-aes-in-java-7616beaaade9
4. http://www.crypto-it.net/eng/theory/modes-of-block-ciphers.html
