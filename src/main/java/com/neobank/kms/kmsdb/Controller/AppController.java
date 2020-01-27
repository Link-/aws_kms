package com.neobank.kms.kmsdb.Controller;

import com.neobank.kms.kmsdb.Service.KmsService;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.common.security.SecurityUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.atomic.AtomicLong;

@RestController
public class AppController {

    private final AtomicLong counter = new AtomicLong();
    @Autowired
    private KmsService kmsService;

    @PostMapping("/customer")
    public ResponseEntity<Object> addUser(
            @RequestParam(name="customerId") String customerId,
            @RequestParam(name="registrationCode") String registrationCode) throws BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        char[] registrationCodeArray = registrationCode.toCharArray();

        // The implementation of GuardedString here is almost useless because the registrationCode already hit the
        // Heap in plaintext. However, this code is a POC to demonstration a safe encryption implementation.
        // In the actual implementation the registrationCode will come as a response to an HTTP request and will be
        // handled directly and cleared from memory as soon as possible.
        GuardedString guardedRegistrationCode = new GuardedString(registrationCodeArray);

        // Cleanup
        SecurityUtil.clear(registrationCodeArray);

        return ResponseEntity.ok().body(kmsService.createUser(customerId, guardedRegistrationCode));
    }

    @GetMapping("/customer")
    public ResponseEntity<Object> getUser(@RequestParam(name="customerId") String customerId) throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        return ResponseEntity.ok().body(kmsService.getUser(customerId));
    }
}
