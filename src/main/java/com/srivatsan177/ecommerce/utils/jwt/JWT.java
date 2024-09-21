package com.srivatsan177.ecommerce.utils.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.SignatureException;
import org.apache.coyote.BadRequestException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

@Service
public class JWT {
    @Value("${custom.app.jwt_secret}")
    private String jwtSecret;

    private Key getKey() {
        byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        return new SecretKeySpec(keyBytes, SignatureAlgorithm.HS256.getJcaName());
    }

    public String getJWT(String email) {
        return Jwts.builder()
                .setSubject(email)
                .setIssuer("user-service")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 28800000)) // 8 hour expiration
                .signWith(this.getKey())
                .compact();
    }

    public String getEmail(String jws) throws BadRequestException {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(this.getKey())
                    .build()
                    .parseClaimsJws(jws)
                    .getBody();
            return claims.getSubject();
        } catch (ExpiredJwtException e) {
            throw new BadRequestException("JWT token expired login again");
        } catch (SignatureException e) {
            throw new BadRequestException(String.format("Invalid signation: %s", e.getMessage()));
        } catch (Exception ex) {
            throw new BadRequestException("Unknown error when parsing jwt token");
        }
    }
}
