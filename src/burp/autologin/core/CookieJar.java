package burp.autologin.core;

import java.util.Date;
import java.util.List;
import java.util.Vector;

import burp.ICookie;

public class CookieJar extends Vector<CookieJar.Cookie> {
    public class Cookie {
        private String name;
        private String value;
        private String domain;
        private Date expiration;
        private String path;
        private boolean secure;
        private boolean HttpOnly;

        /** 记录来自Set-Cookie的原始字符串<br />
         * @example key=name; expires=Thu, 25 Feb 2016 04:18:00 GMT; domain=test.com; path=/; secure; HttpOnly
         */
        private String rawString;

        private Cookie(String rawString){
            this.rawString = rawString;
            this.domain = null;
            this.expiration = null;
            this.path = "/";
            this.secure = false;
            this.HttpOnly= false;

            String[] fields = rawString.split(";[ \\t]*");
            String[] values = fields[0].split("=");
            this.name = values[0];
            this.value = values.length < 2?"":values[1];

            for(int i=1;i<fields.length;i++){
                values = fields[i].split("=");
                switch (values[0].toLowerCase()) {
                    case "expires":
                        if(values.length>1){
                            this.expiration = new Date(values[1]);
                        }
                        break;
                    case "domain":
                        if(values.length>1){
                            this.domain = values[1];
                        }
                        break;
                    case "path":
                        if(values.length>1){
                            this.path = values[1];
                        }
                        break;
                    case "secure":
                        this.secure = true;
                        break;
                    case "httponly":
                        this.HttpOnly = true;
                        break;
                    default:
                        break;
                }
            }
        }

        /**
         * 判断cookie是否匹配传入的path
         * @param path 待匹配的path字符串
         * @return 匹配则返回true，否则返回false
         * @see #path
         */
        public boolean matches(String path){
            for(int i=0;i<this.path.length() && i<path.length();i++){
                if(this.path.charAt(i) != path.charAt(i)){
                    return false;
                }
            }
            return true;
        }

        public String getName() {
            return name;
        }

        public String getValue() {
            return value;
        }

        public String getDomain() {
            return domain;
        }

        public Date getExpiration() {
            return expiration;
        }

        public String getPath() {
            return path;
        }

        public boolean isHttpOnly() {
            return HttpOnly;
        }

        public boolean isSecure() {
            return secure;
        }

        public String getRawString() {
            return rawString;
        }
    }

    public CookieJar(){

    }

    /**
     * 从Set-Cookie头部字段更新当前cookie信息，存在同path、同名的cookie则更新，否则新增cookie
     * @tips 由于一个CookieJar对应一个登陆过程故认为所有cookie在同一个域
     * @param setCookieString 来自Set-Cookie头部的原始字符串
     * @see Cookie
     */
    public void updateOrAdd(String setCookieString){
        Cookie cookie = new Cookie(setCookieString);
        boolean update = false;
        for(Cookie c:this){
            if(cookie.getPath().equals(c.getPath()) && cookie.getName().equals(c.getName())){
                update = true;
                c.rawString = cookie.getRawString();
                c.value = cookie.getValue();
                c.domain = cookie.getDomain();
                c.expiration = cookie.getExpiration();
                c.secure = cookie.isSecure();
                c.HttpOnly = cookie.isHttpOnly();
                break;
            }
        }
        if(!update){
            add(cookie);
        }
    }
}