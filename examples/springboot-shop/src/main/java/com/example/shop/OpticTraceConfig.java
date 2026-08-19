package com.example.shop;

import io.github.dwarkaprasad.optictrace.OpticTraceFilter;
import io.github.dwarkaprasad.optictrace.OpticTraceLogHandler;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * The only OpticTrace-aware code in this application.
 *
 * <p>Everything else — the controllers, their logging, their internal calls —
 * is ordinary Spring. That is the point: governance, correlation and log
 * shipping are wired once here rather than remembered at every call site.
 */
@Configuration
public class OpticTraceConfig {

    @Value("${optictrace.agent}")
    private String agentUrl;

    @Value("${optictrace.config}")
    private String configPath;

    @Value("${optictrace.service}")
    private String serviceName;

    /**
     * Registers the filter FIRST in the chain, so what it records is what the
     * client actually sent and received. A filter further down would see a
     * request other filters had already rewritten.
     */
    @Bean
    public FilterRegistrationBean<OpticTraceFilter> optictrace() throws IOException {
        FilterRegistrationBean<OpticTraceFilter> reg = new FilterRegistrationBean<>(
                new OpticTraceFilter(configPath, agentUrl, serviceName));
        reg.setOrder(Ordered.HIGHEST_PRECEDENCE);
        reg.addUrlPatterns("/*");
        return reg;
    }

    /**
     * Ships whatever the application logs to the agent, correlated to the span
     * being served.
     *
     * <p>Attached to the root JUL logger because Spring Boot routes its
     * logging through SLF4J to Logback by default; the jul-to-slf4j bridge in
     * spring-boot-starter-logging means the reverse handler here still sees
     * records from java.util.logging. Controllers in this app log through JUL
     * directly, which keeps the demo honest about what the handler receives.
     */
    @PostConstruct
    public void installLogShipping() {
        Logger parent = Logger.getLogger("com.example.shop");
        // JUL filters on the LOGGER level before a handler is ever consulted,
        // and its default is INFO — without this the masked FINE line in
        // PaymentsController would never be shipped, and the demo would look
        // like redaction worked when nothing had been sent.
        parent.setLevel(Level.FINE);
        parent.addHandler(new OpticTraceLogHandler(agentUrl, serviceName));
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}
