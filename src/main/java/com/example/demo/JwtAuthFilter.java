package com.example.demo;


import io.jsonwebtoken.ExpiredJwtException;
import io.micrometer.common.lang.NonNull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collection;



@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    @Autowired
    private JwtService jwtService;
//    @Autowired
//    private UserDetailsService userDetailsService;


    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull  FilterChain filterChain) throws ServletException, IOException
    {
        String authHeader = request.getHeader("Authorization");
        String token = new String();
//        System.out.println(request.getCookies());
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("BearerToken")) {
                    token = cookie.getValue();
                    break;
                }
            }
        }


//        System.out.println("this is token :  " + token);
//
//        System.out.println("this is cookies : "+ request.getCookies());


        String username = null;
//        if(authHeader!=null && authHeader.startsWith("Bearer ")) {
//            token = authHeader.substring(7);
//            username = jwtService.extractUsername(token);
//        }
        try{
            if(!token.isEmpty()){
                username = jwtService.extractUsername(token);
            }
        }catch (ExpiredJwtException e){
            Cookie cookie = new Cookie("BearerToken",null);
            cookie.setHttpOnly(true);
            cookie.setMaxAge(0);
            cookie.setPath("/");
            response.addCookie(cookie);
//    e.printStackTrace();
        }




        if(username!=null && SecurityContextHolder.getContext().getAuthentication()==null){
            Collection<? extends GrantedAuthority> authorities = jwtService.getRole(token);

//         authorities.stream().forEach(e-> System.out.println(e));

                UsernamePasswordAuthenticationToken authToken = new
                        UsernamePasswordAuthenticationToken (
                        username,
                        null,
                        authorities
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource()
                                .buildDetails(request)
                );
                SecurityContextHolder
                        .getContext()
                        .setAuthentication(authToken);
            }
        filterChain.doFilter(request,response);
    }
}
