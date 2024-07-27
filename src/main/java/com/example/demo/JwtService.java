package com.example.demo;





import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.security.Key;
import java.util.*;
import java.util.function.Function;

@Component
public class JwtService {



    private String SECRET_KEY = "6161d296ef83c97ce8bf20657b80e944ce46470cdb7b2a70251ff402ffdc17e4";




    public  String extractUsername(String token){
        return extractClaim(token, Claims::getSubject);
    }
    public Date extractExpiration(String token){
        return  extractClaim(token,Claims::getExpiration);
    }

    private <T> T extractClaim(String token, Function<Claims,T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public  Boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }

    public  Boolean  validateToken(String token){
        return (!isTokenExpired(token));
    }

    public  String generateToken(String username,List<String> authorities){
        Map<String,Object> claims = new HashMap<>();
        claims.put("firstname","test");
        claims.put("lastname","test");
        return createToken(claims,username,authorities);
    }

    private String createToken(Map<String, Object> claims, String username, List<String> roles) {
        List<String> role = new ArrayList<>();

        role.add("admin");

        Map<String,Object> Claims = new LinkedHashMap<>();
        List<String> audience = new ArrayList<>();
        Claims.put("role",role);
        claims.putAll(Claims);
        String id= UUID.randomUUID().toString();
        String baseUrl = getServerNameAndPort();

        if(role.get(0).equalsIgnoreCase("USER")){
            audience.add(baseUrl + "/user");
        }else if(role.get(0).equalsIgnoreCase("ADMIN")){
            audience.add(baseUrl + "/user");
            audience.add(baseUrl + "/admin");
        }

        return Jwts.builder()
                .setIssuer(baseUrl)
                .setHeaderParam("typ", "JWT")
                .setSubject(username)
//                .setAudience(audience)
                .claim("aud",audience)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 30 ))     // Expiration Time (1 hour from now)
                .setId(id)
                .addClaims(claims)
                .signWith(SignatureAlgorithm.HS256, getSignKey())
                .compact();

    }

    public Claims getClaims(String jwtToken){
        return    Jwts.parser()
                .setSigningKey(SECRET_KEY)
                .parseClaimsJws(jwtToken)
                .getBody();
    }

    private String getServerNameAndPort() {
        ServletRequestAttributes requestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (requestAttributes != null) {
            HttpServletRequest request = requestAttributes.getRequest();
            if (request != null) {
                String serverName = request.getServerName();
                int port = request.getServerPort();
                return "http://" + serverName + ":" + port;
            }
        }
        return null;
    }

    public Collection<? extends GrantedAuthority> getRole(String token)  {
        Claims claims = extractAllClaims(token);
        Collection<CustomAuthority> authorities = new ArrayList<>();
        List<String> roles = claims.get("role", List.class);
        roles.forEach(e-> authorities.add(new CustomAuthority(e)));
        return authorities;
    }



    private Key getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}
