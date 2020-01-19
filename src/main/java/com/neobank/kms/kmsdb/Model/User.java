package com.neobank.kms.kmsdb.Model;

import javax.persistence.*;

@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy= GenerationType.AUTO)
    private Long id;
    @Column(unique = true)
    private String customerId;
    private String encryptedRegistrationCode;
    private String cmkAlias;
    private String cmkId;
    private String encryptionKey;

    protected User() {}

    public User(String customerId,
                String encryptedRegistrationCode,
                String cmkAlias,
                String cmkId,
                String encryptionKey) {
        this.customerId = customerId;
        this.encryptedRegistrationCode = encryptedRegistrationCode;
        this.cmkAlias = cmkAlias;
        this.cmkId = cmkId;
        this.encryptionKey = encryptionKey;
    }

    public Long getId() {
        return id;
    }

    public String getCustomerId() {
        return customerId;
    }

    public String getEncryptedRegistrationCode() {
        return encryptedRegistrationCode;
    }

    public String getCmkAlias() {
        return cmkAlias;
    }

    public String getCmkId() {
        return cmkId;
    }

    public String getEncryptionKey() {
        return encryptionKey;
    }
}
