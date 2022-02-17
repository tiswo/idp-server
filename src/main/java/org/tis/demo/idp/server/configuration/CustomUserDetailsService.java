package org.tis.demo.idp.server.configuration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class CustomUserDetailsService implements AuthenticationUserDetailsService<CasAssertionAuthenticationToken> {
    private Logger LOGGER = LoggerFactory.getLogger(CustomUserDetailsService.class);

    @Override
    public UserDetails loadUserDetails(CasAssertionAuthenticationToken token) throws UsernameNotFoundException {
        String account = token.getName();
        try {
            StoryLoginUser user = new StoryLoginUser();
            user.setName("admin");
            user.setAccount("admin");
            return new StoryPrincipal(user, "admin");
        } catch (Exception e) {
            LOGGER.error("loadUserByUsername error, Account:{}", account, e);
            throw new UsernameNotFoundException("用户名[" + account + "]认证失败！", e);
        }
    }
}