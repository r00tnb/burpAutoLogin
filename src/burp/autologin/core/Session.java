package burp.autologin.core;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;
import java.util.Vector;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.JPanel;
import javax.swing.JProgressBar;

import burp.BurpExtender;
import burp.ICookie;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IResponseInfo;
import burp.Util.TempEntry;
import burp.Util.Util;
import burp.autologin.core.CookieJar.Cookie;
import burp.autologin.core.TokenReplaceModel.TokenReplace;

public class Session {
    public class Token {

        private String tokenName;
        private String tokenValue;

        private Token(String tokenName, String tokenValue) {
            this.tokenName = tokenName;
            this.tokenValue = tokenValue;
        }

        public boolean isValid() {
            return tokenValue != null;
        }

        public String getTokenName() {
            return tokenName;
        }

        public String getTokenValue() {
            return tokenValue;
        }

        public void setTokenValue(String tokenValue) {
            this.tokenValue = tokenValue;
        }

    }

    public class LoginProcessor {
        private Iterator<Message> iterator;
        /**
         * 存储登陆过程中发生302跳转时的跳转路径和参数，主要解决：浏览器发出多个请求时可能会使302跳转指定的请求滞后，导致无法更新下一个请求
         * <ul>
         * <li>
         * <b>Map</b>
         * <ul><li>key 指定302跳转到的url路径</li><li>value 指定302跳转到的url参数</li></ul>
         * </li>
         * </ul>
         * @see #step()
         * @see IParameter
         */
        private Map<String, List<IParameter>> redirectMap;

        private LoginProcessor(){
            this.iterator = loginMessageList.iterator();
            this.redirectMap = new ConcurrentHashMap<>();

            //更新之前清空cookie
            cookieJar.clear();
        }

        public boolean hasNext(){
            return iterator.hasNext();
        }

        public void step(){
            Message msg = iterator.next();
            // 更新请求
            updateRequest(msg);
            for(Entry<String, List<IParameter>> entry:redirectMap.entrySet()){
                if(msg.getUrlPath().equals(entry.getKey())){
                    msg.updateParams(entry.getValue());
                    redirectMap.remove(entry.getKey());
                    break;
                }
            }
            Message.refreshMessage(msg);

            // update token
            msg.getTokenSearchModel().searchToken();

            // update cookie
            for (String header:msg.getResponseInfo().getHeaders()) {
                if(header.toLowerCase().startsWith("set-cookie: ")){
                    cookieJar.updateOrAdd(header.substring(12));
                }
            }

            //如果是302跳转则保存跳转状态
            if(msg.getResponseInfo().getStatusCode() == 302){
                for (String header : msg.getResponseInfo().getHeaders()) {
                    if (header.startsWith("Location: ")) {
                        try {
                            URL url = new URL(header.substring(10));
                            String query = url.getQuery();
                            List<IParameter> paramList = new Vector<>();
                            if(query != null){
                                for(String param:query.split("&")){
                                    String[] paramArray=param.split("=");
                                    IParameter p = BurpExtender.helpers.buildParameter(paramArray[0], paramArray.length>1?paramArray[1]:"", IParameter.PARAM_URL);
                                    paramList.add(p);
                                }
                            }
                            redirectMap.put(url.getPath(), paramList);
                        } catch (MalformedURLException e) {
                            // TODO Auto-generated catch block
                            e.printStackTrace();
                        }
                        break;
                    }
                }
            }
        }
    }

    /**
     * 登录消息列表
     */
    private List<Message> loginMessageList;

    /**
     * 登录后需要更新请求中的token，该对象保存了相关信息
     */
    private TokenReplaceModel tokenReplaceModel;

    private CookieJar cookieJar;

    private String domain;

    /** 
     * 用于验证session是否有效， 只要匹配到列表中的任意一个都认为session无效
     * @see SessionValidator
     */
    private List<SessionValidator> validatorList;


    public Session(String domain) {
        this.tokenReplaceModel = new TokenReplaceModel();
        this.loginMessageList = new Vector<>();
        this.domain = domain;
        this.cookieJar = new CookieJar();
        this.validatorList = new Vector<>();
    }

    public TokenReplaceModel getTokenReplaceModel() {
        return tokenReplaceModel;
    }

    public List<Message> getLoginMessages() {
        return loginMessageList;
    }

    public void setLoginMessages(List<Message> loginMessages) {
        this.loginMessageList = new Vector<>(loginMessages);
    }

    public List<Token> getAllToken() {
        List<Token> result = new Vector<>();
        for (Iterator<Message> iterator = loginMessageList.iterator(); iterator.hasNext();) {
            for (Entry<Token, Pattern> entry : iterator.next().getTokenSearchModel().entrySet()) {
                result.add(entry.getKey());
            }
        }
        return result;
    }

    /**
     * 当token变动或message变动时更新TokenReplaceModel对象的内容
     */
    public void updateTokenReplaceModel() {
        for (Iterator<TokenReplace> iterator = tokenReplaceModel.iterator(); iterator.hasNext();) {
            TokenReplace tokenReplace = iterator.next();
            if (!hasToken(tokenReplace.getToken().getTokenName())) {
                iterator.remove();
            }
        }
    }

    /**
     * 根据token名获取token对象
     * 
     * @param tokenName token名
     * @return 如session中没有指定的token名则新建一个同名的token，否则返回指定名称的token对象
     */
    public Token getToken(String tokenName) {
        Token token;
        for (Iterator<Token> iterator = getAllToken().iterator(); iterator.hasNext();) {
            token = iterator.next();
            if (token.getTokenName().equals(tokenName)) {
                return token;
            }
        }
        token = new Token(tokenName, null);
        return token;
    }

    /**
     * 判断当前session中是否包含指定token
     * 
     * @param tokenName 指定token名称
     * @return 包含返回true，否则返回false
     */
    public boolean hasToken(String tokenName) {
        for (Iterator<Token> iterator = getAllToken().iterator(); iterator.hasNext();) {
            Token token = iterator.next();
            if (token.getTokenName().equals(tokenName)) {
                return true;
            }
        }
        return false;
    }

    public LoginProcessor loginProcessor(){
        return new LoginProcessor();
    }

    /**
     * 登录并更新session信息，包括cookie和token
     */
    public void login() {
        LoginProcessor loginProcess = new LoginProcessor();
        while (loginProcess.hasNext()) {
            loginProcess.step();
        }
    }

    /**
     * 更新请求中需要被替换的token值，更新cookie
     * 
     * @param msg 需要更新的消息
     */
    public void updateRequest(Message msg){
        //update token
        tokenReplaceModel.updateRequest(msg);

        //如果更新所有token的选项为true，则更新请求中的所有同名token
        if(tokenReplaceModel.isAllReplace()){
            for(Token token:getAllToken()){
                tokenReplaceModel.updateTokenInRequest(msg, token);
            }
        }

        //update cookie
        msg.setCookie(cookieJar);
    }

    /**
     * 为消息响应添加Set-Cookie头部，包括cookieJar中的所有cookie
     * @param msg 待添加头部的消息
     * @see #cookieJar
     */
    public void addSetCookieHeader(Message msg){
        List<String> headers = msg.getResponseInfo().getHeaders();
        for(Cookie cookie:cookieJar){
            headers.add("Set-Cookie: "+cookie.getName()+"="+cookie.getValue()+"; Path=/");
        }
        msg.setResponse(BurpExtender.helpers.buildHttpMessage(headers, Arrays.copyOfRange(msg.getResponse(),
            msg.getResponseInfo().getBodyOffset(), msg.getResponse().length)));
    }

    /**
     * 判断传入消息的登录状态是否有效
     * @param msg 已经完成请求响应的消息
     * @return 失效返回false， 否则返回true
     */
    public boolean isValid(Message msg){
        for(SessionValidator validator:validatorList){
            if(!validator.isValid(msg))
                return false;
        }

        return true;
    }

    public List<SessionValidator> getSessionValidatorList(){
        return validatorList;
    }

    /**清除当前的session信息,不包括登录序列 */
    public void clear(){
        //clear cookieJar
        cookieJar.clear();

        //clear token info
        for(Token token:getAllToken()){
            token.setTokenValue(null);
        }
    }
    
}