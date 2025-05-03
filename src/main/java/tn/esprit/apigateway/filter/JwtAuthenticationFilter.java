package tn.esprit.apigateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import jakarta.annotation.PostConstruct;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

@Component
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    @Value("${jwt.secret}")
    private String secretKeyBase64;

    private javax.crypto.SecretKey secretKey;

    public JwtAuthenticationFilter() {
        super(Config.class);
    }

    @PostConstruct
    public void init() {
        if (secretKeyBase64 == null) {
            logger.error("JWT secret key is not configured.");
            throw new IllegalStateException("JWT secret key is not configured.");
        }
        try {
            byte[] keyBytes = Base64.getDecoder().decode(secretKeyBase64);
            this.secretKey = new SecretKeySpec(keyBytes, "HmacSHA512");
            logger.info("Initialized JWT filter with secret key");
        } catch (IllegalArgumentException e) {
            logger.error("Failed to decode JWT secret key: {}", e.getMessage());
            throw new IllegalStateException("Invalid JWT secret key", e);
        }
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String path = request.getURI().getPath();
            String method = request.getMethod().toString();
            logger.debug("Processing request - Method: {}, Path: {}", method, path);

            if ("OPTIONS".equals(method)) {
                ServerHttpResponse response = exchange.getResponse();
                response.setStatusCode(HttpStatus.OK);
                return response.setComplete();
            }

            if (path.contains("/api/auth/login") || path.contains("/api/auth/register")) {
                logger.debug("Bypassing JWT check for: {}", path);
                return chain.filter(exchange);
            }

            String authHeader = request.getHeaders().getFirst("Authorization");
            logger.debug("Authorization Header: {}", authHeader);

            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);
                try {
                    Claims claims = Jwts.parserBuilder()
                            .setSigningKey(secretKey)
                            .build()
                            .parseClaimsJws(token)
                            .getBody();
                    logger.debug("Token validated, user: {}", claims.getSubject());
                    ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                            .header("X-Authenticated-User", claims.getSubject())
                            .header("Authorization", authHeader) // Explicitly preserve Authorization
                            .build();
                    return chain.filter(exchange.mutate().request(modifiedRequest).build());
                } catch (Exception e) {
                    logger.error("JWT validation failed: {}", e.getMessage(), e);
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                }
            }

            logger.warn("No valid token found, rejecting with 401");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        };
    }

    public static class Config {
    }
}