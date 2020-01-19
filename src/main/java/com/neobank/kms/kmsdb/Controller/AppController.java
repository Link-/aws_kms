package com.neobank.kms.kmsdb.Controller;

import com.neobank.kms.kmsdb.Model.User;
import com.neobank.kms.kmsdb.Repository.UserRepository;
import com.neobank.kms.kmsdb.Service.KmsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.ws.Response;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

@RestController
public class AppController {

    private final AtomicLong counter = new AtomicLong();
    @Autowired
    private KmsService kmsService;

    @GetMapping("/index")
    public ResponseEntity<Object> index() {
        return ResponseEntity.ok().body(kmsService.testServiceCall());
    }

    @PostMapping("/customer")
    public ResponseEntity<Object> addUser(
            @RequestParam(name="customerId") String customerId,
            @RequestParam(name="registrationCode") String registrationCode
    ) throws BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        return ResponseEntity.ok().body(kmsService.createUser(customerId, registrationCode));
    }

    @GetMapping("/customer")
    public ResponseEntity<Object> getUser(@RequestParam(name="customerId") String customerId) throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        return ResponseEntity.ok().body(kmsService.getUser(customerId));
    }
}
