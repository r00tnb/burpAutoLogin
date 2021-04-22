package burp.autologin.core;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;
import java.util.regex.Pattern;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.Util.Util;
import burp.autologin.core.Session.Token;

public class TokenReplaceModel extends Vector<TokenReplaceModel.TokenReplace> {

    public class TokenReplace {
        private Token token;
        private Pattern pattern;
        private String tips;
        private boolean urlEncode;

        private TokenReplace(Token token, Pattern pattern, String tips, boolean urlEncode) {
            this.token = token;
            this.pattern = pattern;
            this.tips = tips;
            this.urlEncode = urlEncode;
        }

        @Override
        public boolean equals(Object obj) {
            // TODO Auto-generated method stub
            if (obj instanceof TokenReplace) {
                TokenReplace r = (TokenReplace) obj;
                if (this.pattern.pattern().equals(r.pattern.pattern())) {
                    return true;
                }
            }
            return false;
        }

        public void set(Token token, Pattern pattern, String tips, boolean urlEncode) {
            this.token = token;
            this.pattern = pattern;
            this.tips = tips;
            this.urlEncode = urlEncode;
        }

        public Token getToken() {
            return token;
        }

        public void setToken(Token token) {
            this.token = token;
        }

        public Pattern getPattern() {
            return pattern;
        }

        public void setPattern(Pattern pattern) {
            this.pattern = pattern;
        }

        public String getTips() {
            return tips;
        }

        public void setTips(String tips) {
            this.tips = tips;
        }

        public boolean isUseUrlEncode(){
            return urlEncode;
        }
    }

    /**为true时替换所有同名token */
    private boolean allReplace;

    public TokenReplaceModel() {
        this.allReplace = false;
    }

    /**
     * 更新请求中需要被替换的token值
     * 
     * @param requestResponse 需要更新的消息
     */
    public void updateRequest(Message msg) {
        String request = msg.getRequestString();
        for (Iterator<TokenReplace> iterator = iterator(); iterator.hasNext();) {
            TokenReplace tokenReplace = iterator.next();
            
            request = Util.replaceFirstGroup(tokenReplace.getPattern(), request, Util.urlEncode(tokenReplace.getToken().getTokenValue()));

        }
        msg.setRequest(request.getBytes());
    }

    public TokenReplace append(Token token, Pattern pattern, String tips, boolean urlEncode){
        TokenReplace r = new TokenReplace(token, pattern, tips, urlEncode);
        add(r);
        return r;
    }

    /**
     * 更新所有在msg中的同名token,包括GET请求参数、POST请求参数、请求头、请求体JSON格式的参数、cookie
     * @param msg 待更新的请求
     * @param token 查找的token
     */
    public void updateTokenInRequest(Message msg, Token token){
        String request = msg.getRequestString();
        TokenReplace a = new TokenReplace(token, 
            Pattern.compile("\\?(?:[\\S]+?&)?"+Util.normalString(token.getTokenName())+"=([^&\\s]*?)(?:&| )"), "替换请求字符串中的token", true);
        TokenReplace b = new TokenReplace(token, 
            Pattern.compile("\\r\\n"+Util.normalString(token.getTokenName())+":[ ]*([^ \\r\\n]*?)\\r\\n"), "替换请求头部中的token", true);
        TokenReplace c = new TokenReplace(token, 
            Pattern.compile("\\r\\n\\r\\n(?:[\\s\\S]+?&)?"+Util.normalString(token.getTokenName())+"=([^&]*?)(?:&[\\s\\S]+?)?$"), "替换普通POST请求体中的token", true);
        TokenReplace d = new TokenReplace(token, 
            Pattern.compile("\\r\\n\\r\\n(?:\\{|\\[)[\\s\\S]*?\""+Util.normalString(token.getTokenName())+"\"\\s*?:\\s*?\"(.*?[^\\\\])\""), "替换json请求体中的token", true);
        TokenReplace e = new TokenReplace(token, 
            Pattern.compile("\\r\\n\\r\\n[\\s\\S]+?Content-Disposition:.*?(?:name|filename)=\""+Util.normalString(token.getTokenName())+
                "\"[\\s\\S]*?\\r\\n\\r\\n([\\s\\S]*?)\\r\\n-+[\\s\\S]*$"), "替换上传请求体中的token", true);
        
        request = Util.replaceFirstGroup(a.getPattern(), request, Util.urlEncode(a.getToken().getTokenValue()));
        request = Util.replaceFirstGroup(b.getPattern(), request, Util.urlEncode(b.getToken().getTokenValue()));
        request = Util.replaceFirstGroup(c.getPattern(), request, Util.urlEncode(c.getToken().getTokenValue()));
        request = Util.replaceFirstGroup(d.getPattern(), request, Util.urlEncode(d.getToken().getTokenValue()));
        request = Util.replaceFirstGroup(e.getPattern(), request, Util.urlEncode(d.getToken().getTokenValue()));

        msg.setRequest(request.getBytes());

        //替换cookie中的同名token
        List<IParameter> l = new Vector<>();
        IParameter m = BurpExtender.helpers.buildParameter(token.getTokenName(), token.getTokenValue()==null?"":token.getTokenValue(), IParameter.PARAM_COOKIE);
        for(IParameter param:msg.getRequestInfo().getParameters()){
            if(param.getType() == m.getType() && param.getName().equals(m.getName())){
                l.add(m);
                break;
            }
        }
        msg.updateParams(l);
    }

    /**
     * 添加默认的替换分组用于token更新， 默认地会将请求中所有同名的token更新为新的token
     */
    public void appendDefault(Token token){
        
    }

    public boolean isAllReplace() {
        return allReplace;
    }

    public void setAllReplace(boolean allReplace) {
        this.allReplace = allReplace;
    }

}