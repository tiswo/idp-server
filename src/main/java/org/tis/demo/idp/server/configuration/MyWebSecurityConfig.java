//package com.nucc.demo.idp.server.configuration;
//
//import com.fasterxml.jackson.databind.ObjectMapper;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.authentication.*;
//import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.crypto.password.NoOpPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.web.authentication.AuthenticationFailureHandler;
//import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
//import org.springframework.security.web.authentication.logout.LogoutHandler;
//import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
//
//import javax.servlet.http.HttpServletRequest;
//import javax.servlet.http.HttpServletResponse;
//import java.io.IOException;
//import java.io.PrintWriter;
//import java.util.HashMap;
//import java.util.Map;
//
//@Configuration
//public class MyWebSecurityConfig extends WebSecurityConfigurerAdapter {
//    @Bean
//    PasswordEncoder passwordEncoder() {
//        return NoOpPasswordEncoder.getInstance();
//    }
//
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication()
//                .withUser("root").password("123").roles("ADMIN", "DBA")
//                .and()
//                .withUser("admin").password("123").roles("ADMIN", "USER")
//                .and()
//                .withUser("sang").password("123").roles("USER");
//    }
//
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.authorizeRequests()
//                .antMatchers("/admin/**")
//                .hasRole("ADMIN")
//                .antMatchers("/user/**")
//                .access("hasAnyRole('ADMIN','USER')")
//                .antMatchers("/db/**")
//                .access("hasRole('ADMIN') and hasRole('DBA')")
//                .anyRequest()
//                .authenticated()
//                .and()
//                .formLogin()
////                .loginPage("/login_page")                      //登陆页面
//                .loginProcessingUrl("/login")//登陆请求处理接口
//                .usernameParameter("name") //默认用户名，密码
//                .passwordParameter("passwd")
//                .successHandler(new AuthenticationSuccessHandler() {            //登陆成功后
//                    @Override
//                    public void onAuthenticationSuccess(HttpServletRequest req,
//                                                        HttpServletResponse resp,
//                                                        Authentication auth)    //当前用户登陆信息
//                            throws IOException {
//                        Object principal = auth.getPrincipal();
//                        resp.setContentType("application/json;charset=utf-8");
//                        PrintWriter out = resp.getWriter();
//                        resp.setStatus(200);
//                        Map<String, Object> map = new HashMap<>();
//                        map.put("status", 200);
//                        map.put("msg", principal);
//                        ObjectMapper om = new ObjectMapper();
//                        out.write(om.writeValueAsString(map));
//                        out.flush();
//                        out.close();
//                    }
//                })
//                .failureHandler(new AuthenticationFailureHandler() {         //登陆失败后
//                    @Override
//                    public void onAuthenticationFailure(HttpServletRequest req,
//                                                        HttpServletResponse resp,
//                                                        AuthenticationException e)  //获取登陆失败原因
//                            throws IOException {
//                        resp.setContentType("application/json;charset=utf-8");
//                        PrintWriter out = resp.getWriter();
//                        resp.setStatus(401);
//                        Map<String, Object> map = new HashMap<>();
//                        map.put("status", 401);
//                        if (e instanceof LockedException) {
//                            map.put("msg", "账户被锁定，登录失败!");
//                        } else if (e instanceof BadCredentialsException) {
//                            map.put("msg", "账户名或密码输入错误，登录失败!");
//                        } else if (e instanceof DisabledException) {
//                            map.put("msg", "账户被禁用，登录失败!");
//                        } else if (e instanceof AccountExpiredException) {
//                            map.put("msg", "账户已过期，登录失败!");
//                        } else if (e instanceof CredentialsExpiredException) {
//                            map.put("msg", "密码已过期，登录失败!");
//                        } else {
//                            map.put("msg", "登录失败!");
//                        }
//                        ObjectMapper om = new ObjectMapper();
//                        out.write(om.writeValueAsString(map));
//                        out.flush();
//                        out.close();
//                    }
//                })
//                .permitAll()
//                .and()
//                .logout()                    //开启注销登陆
//                .logoutUrl("/logout")         //注销登陆请求url
//                .clearAuthentication(true)    //清除身份信息
//                .invalidateHttpSession(true)   //session失效
//                .addLogoutHandler(new LogoutHandler() {//注销处理
//                    @Override
//                    public void logout(HttpServletRequest req,
//                                       HttpServletResponse resp,
//                                       Authentication auth) {
//
//                    }
//                })
//                .logoutSuccessHandler(new LogoutSuccessHandler() {     //注销成功处理
//                    @Override
//                    public void onLogoutSuccess(HttpServletRequest req,
//                                                HttpServletResponse resp,
//                                                Authentication auth)
//                            throws IOException {
//                        resp.sendRedirect("/login_page");              //跳转到自定义登陆页面
//                    }
//                })
//                .and()
//                .csrf()
//                .disable();
//    }
//}