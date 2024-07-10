package com.example.oauth2server.client.controller;

import com.example.oauth2server.client.service.ClientService;
import com.example.oauth2server.dto.ClientSaveRequestDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequiredArgsConstructor
@Slf4j
@RequestMapping(value = "/api/v1/client")
public class ClientController {

    private final ClientService clientService;

    @PostMapping
    public void registerClient(@RequestBody ClientSaveRequestDto clientSaveRequestDto){
        clientService.registerClient(clientSaveRequestDto);
    }

}
