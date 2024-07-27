package com.example.demo.controllers;

import com.example.demo.JwtService;
import com.example.demo.Test;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;

@RestController
public class HelloWork {


    @Autowired
    Test test;
    @Autowired
    private JwtService jwtService;

    @GetMapping
    public String Helloworld(){
        return "Hello world";
    }

@GetMapping("/protected")
public String Protected(){
return  "Protected Data only admin can see";
}
    @GetMapping("/token")
    public String Token(HttpServletResponse res){
     String token =  jwtService.generateToken("test",List.of("admin"));
        Cookie cookie = new Cookie("BearerToken", token);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(1800000);


//                cookie.setSecure(true);

        // Make sure the cookie is only sent over HTTPS connections
        res.addCookie(cookie);
        return token;
    }
}
