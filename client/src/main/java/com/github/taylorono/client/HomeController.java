package com.github.taylorono.client;

import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;

@Controller
public class HomeController {
    private static final String baseUrl = "http://localhost:9000";
    private String clientId = "client";

    @GetMapping("/")
    public String home() {
        return "redirect:http://localhost:8888/index";
    }

    @GetMapping("/index")
    public String index() {
        return "index";
    }

    @PostMapping("/authorized/{clientId}")
    public String getToken(Model model, @RequestParam String code, @PathVariable String clientId) {
        if (!this.clientId.equals(clientId)) {
            model.addAttribute("clientId", this.clientId);
            return "authorized";
        }

        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add("grant_type", "authorization_code");
        parameters.add("code", code);
        parameters.add("redirect_uri", "http://localhost:8888/authorized/" + clientId);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
		headers.setBasicAuth("honest-client", "secret");

        RequestEntity<MultiValueMap<String, String>> requestEntity = new RequestEntity<>(parameters, headers, HttpMethod.POST, URI.create(baseUrl + "/oauth2/token"));

        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<Map<String, String>> responseEntity = restTemplate.exchange(requestEntity, new ParameterizedTypeReference<>() {});
        model.addAttribute("accessToken", responseEntity.getBody().get("access_token"));

        return "authorized";
    }
}
