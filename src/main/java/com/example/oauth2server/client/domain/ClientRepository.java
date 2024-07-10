package com.example.oauth2server.client.domain;

import org.springframework.data.jpa.repository.JpaRepository;

public interface ClientRepository extends JpaRepository<Client, String> {

    Client findByClientEmail(String clientEmail);

}
