package com.neobank.kms.kmsdb.Repository;

import com.neobank.kms.kmsdb.Model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface UserRepository extends JpaRepository<User, Long> {
    List<User> findByCustomerId(String customerId);
}
