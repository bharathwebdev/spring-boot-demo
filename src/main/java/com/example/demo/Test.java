package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;


@Component
public class Test {
    @Autowired
    AuthenticationManager authenticationManager;
    public Authentication AuthenticateUser(){
        Authentication authentication  =  authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        "test",
                        "test"
                )
        );

        return authentication;
    }
}
