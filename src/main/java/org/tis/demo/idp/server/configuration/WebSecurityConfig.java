package org.tis.demo.idp.server.configuration;

import org.jasig.cas.client.session.SingleSignOutFilter;
import org.jasig.cas.client.validation.Cas20ServiceTicketValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;

@Configuration
//@EnableGlobalMethodSecurity(prePostEnabled = false)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private CasProperties casProperties;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(casAuthenticationProvider());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()//配置安全策略
            .anyRequest().authenticated()//其余的所有请求都需要验证
            .and()
            .csrf().disable()
            .logout()
            .permitAll()
            .and().headers().frameOptions().disable()  //定义logout不需要验证
            .and()
        .formLogin();//使用form表单登录

        http.exceptionHandling().authenticationEntryPoint(casAuthenticationEntryPoint())
            .and()
            .addFilter(casAuthenticationFilter())
            .addFilterBefore(casLogoutFilter(), LogoutFilter.class)
            .addFilterBefore(singleSignOutFilter(), CasAuthenticationFilter.class);
    }

     /**
     * 认证的入口，即跳转至服务端的cas地址
     * Note:浏览器访问不可直接填客户端的login请求,若如此则会返回Error页面，无法被此入口拦截
     */
    @Bean
    public CasAuthenticationEntryPoint casAuthenticationEntryPoint() {
        CasAuthenticationEntryPoint casAuthenticationEntryPoint = new CasAuthenticationEntryPoint();
        //Cas Server的登录地址
        casAuthenticationEntryPoint.setLoginUrl(casProperties.getCasServerLoginUrl());
        //service相关的属性
        casAuthenticationEntryPoint.setServiceProperties(serviceProperties());
        return casAuthenticationEntryPoint;
    }

    /**
     * 指定service相关信息
     * 设置客户端service的属性
     * 主要设置请求cas服务端后的回调路径,一般为主页地址，不可为登录地址
     * @return
     */
    @Bean
    public ServiceProperties serviceProperties() {
        ServiceProperties serviceProperties = new ServiceProperties();
        // 设置回调的service路径，此为主页路径
        //Cas Server认证成功后的跳转地址，这里要跳转到我们的Spring Security应用，
        //之后会由CasAuthenticationFilter处理，默认处理地址为/j_spring_cas_security_check
        serviceProperties.setService(casProperties.getAppServerUrl() + casProperties.getAppLoginUrl());
        // 对所有的未拥有ticket的访问均需要验证
        serviceProperties.setAuthenticateAllArtifacts(true);
        return serviceProperties;
    }

    /**CAS认证过滤器*/
    @Bean
    public CasAuthenticationFilter casAuthenticationFilter() throws Exception {
        CasAuthenticationFilter casAuthenticationFilter = new CasAuthenticationFilter();
        casAuthenticationFilter.setAuthenticationManager(authenticationManager());
        //指定处理地址，不指定时默认将会是“/j_spring_cas_security_check”
        casAuthenticationFilter.setFilterProcessesUrl(casProperties.getAppLoginUrl());
        return casAuthenticationFilter;
    }

    /**
     * 创建CAS校验类
     * Notes:TicketValidator、AuthenticationUserDetailService属性必须设置;
     * serviceProperties属性主要应用于ticketValidator用于去cas服务端检验ticket
     * @return
     */
    @Bean
    public CasAuthenticationProvider casAuthenticationProvider() {
        CasAuthenticationProvider casAuthenticationProvider = new CasAuthenticationProvider();
        casAuthenticationProvider.setAuthenticationUserDetailsService(customUserDetailsService());
        casAuthenticationProvider.setServiceProperties(serviceProperties());
        casAuthenticationProvider.setTicketValidator(cas20ServiceTicketValidator());
        casAuthenticationProvider.setKey("casAuthenticationProviderKey");
        return casAuthenticationProvider;
    }

    /**用户自定义的AuthenticationUserDetailsService*/
    @Bean
    public AuthenticationUserDetailsService<CasAssertionAuthenticationToken> customUserDetailsService(){
        return new CustomUserDetailsService();
    }

    /**
     * 配置Ticket校验器
     * @return
     */
    @Bean
    public Cas20ServiceTicketValidator cas20ServiceTicketValidator() {
        // 配置上服务端的校验ticket地址
        return new Cas20ServiceTicketValidator(casProperties.getCasServerUrl());
    }

    /**
     * 单点注销，接受cas服务端发出的注销session请求
     * @see SingleLogout(SLO) Front or Back Channel
     * @return
     */
    @Bean
    public SingleSignOutFilter singleSignOutFilter() {
        SingleSignOutFilter singleSignOutFilter = new SingleSignOutFilter();
        singleSignOutFilter.setCasServerUrlPrefix(casProperties.getCasServerUrl());
        singleSignOutFilter.setIgnoreInitConfiguration(true);
        return singleSignOutFilter;
    }

    /**
     * 单点请求CAS客户端退出Filter类
     * 请求/logout，转发至CAS服务端进行注销
     */
    @Bean
    public LogoutFilter casLogoutFilter() {
        // 设置回调地址，以免注销后页面不再跳转
        LogoutFilter logoutFilter = new LogoutFilter(casProperties.getCasServerLogoutUrl(), new SecurityContextLogoutHandler());
        logoutFilter.setFilterProcessesUrl(casProperties.getAppLogoutUrl());
        return logoutFilter;
    }
}