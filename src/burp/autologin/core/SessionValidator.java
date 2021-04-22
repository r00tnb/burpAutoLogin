package burp.autologin.core;

import java.util.Iterator;
import java.util.List;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import burp.Util.TempEntry;
import burp.Util.Util;

public class SessionValidator extends Vector<SessionValidator.ValidatorItem> {
    public enum SessionValidatorType {
        EQUAL_STATUSCODE_SAMPLE(Util.l("status code equal")), CONTAIN_IN_HEADER_SAMPLE(Util.l("response header contains")), CONTAIN_IN_BODY_SAMPLE(Util.l("response body contains")),
        NOT_EQUAL_STATUSCODE_SAMPLE(Util.l("status code not equal")), NOT_CONTAIN_IN_HEADER_SAMPLE(Util.l("response header not contains")), NOT_CONTAIN_IN_BODY_SAMPLE(Util.l("response body not contains")),
        EQUAL_STATUSCODE(Util.l("status code equal")+"(regexp)"), CONTAIN_IN_HEADER(Util.l("response header contains")+"(regexp)"), CONTAIN_IN_BODY(Util.l("response body contains")+"(regexp)"),
        NOT_EQUAL_STATUSCODE(Util.l("status code not equal")+"(regexp)"), NOT_CONTAIN_IN_HEADER(Util.l("response header not contains")+"(regexp)"), NOT_CONTAIN_IN_BODY(Util.l("response body not contains")+"(regexp)"),
        CONTAIN_IN_REQUEST_SAMPLE(Util.l("request contains")), CONTAIN_IN_REQUEST(Util.l("request contains")+"(regexp)"),
        NOT_CONTAIN_IN_REQUEST_SAMPLE(Util.l("request not contains")), NOT_CONTAIN_IN_REQUEST(Util.l("request not contains")+"(regexp)");

        private String name;
        private SessionValidatorType(String name){
            this.name = name;
        }

        public String getName() {
            return name;
        }

        @Override
        public String toString() {
            // TODO Auto-generated method stub
            return name;
        }
    }

    public class ValidatorItem{
        private String pattern;
        private SessionValidatorType type;

        private ValidatorItem(String pattern, SessionValidatorType type){
            this.pattern = pattern;
            this.type = type;
        }

        public String getPattern() {
            return pattern;
        }

        public void setPattern(String pattern) {
            this.pattern = pattern;
        }

        public SessionValidatorType getType() {
            return type;
        }

        public void setType(SessionValidatorType type) {
            this.type = type;
        }

        @Override
        public String toString() {
            // TODO Auto-generated method stub
            return type.getName()+" "+pattern;
        }
        
    }

    public SessionValidator(){

    }

    public ValidatorItem add(String pattern, SessionValidatorType type){
        ValidatorItem item = new ValidatorItem(pattern, type);
        add(item);
        return item;
    }

    @Override
    public String toString() {
        // TODO Auto-generated method stub
        String result = "";
        for(ValidatorItem item:this){
            if(!result.contains(item.getType().toString())){
                result += item.toString() + "; ";
            }
        }
        return result;
    }

    /**
     * 按照已添加的搜索规则，判断消息是否是失效的登录状态，只有所有搜索规则都匹配时才认为登录失效。
     * @param msg 待判断的消息
     * @return 登录状态有效返回true，否则返回false
     */
    public boolean isValid(Message msg){
        for(ValidatorItem item:this){
            String pattern = item.getPattern();
            SessionValidatorType type = item.getType();
            Matcher matcher = null;
            boolean isFind = false;

            switch (type) {
                case EQUAL_STATUSCODE:
                    matcher = Pattern.compile(pattern).matcher(msg.getResponseInfo().getStatusCode()+"");
                    if(!matcher.find()) return true;
                    break;
                case NOT_EQUAL_STATUSCODE:
                    matcher = Pattern.compile(pattern).matcher(msg.getResponseInfo().getStatusCode()+"");
                    if(matcher.find()) return true;
                    break;
                case CONTAIN_IN_HEADER:
                    for(String header:msg.getResponseInfo().getHeaders()){
                        matcher = Pattern.compile(pattern).matcher(header);
                        if(matcher.find()){
                            isFind = true;
                            break;
                        }
                    }
                    if(!isFind) return true;
                    break;
                case NOT_CONTAIN_IN_HEADER:
                    for(String header:msg.getResponseInfo().getHeaders()){
                        matcher = Pattern.compile(pattern).matcher(header);
                        if(matcher.find()){
                            isFind = true;
                            break;
                        }
                    }
                    if(isFind) return true;
                    break;
                case CONTAIN_IN_BODY:
                    matcher = Pattern.compile(pattern).matcher(msg.getResponseBodyString());
                    if(!matcher.find()) return true;
                    break;
                case NOT_CONTAIN_IN_BODY:
                    matcher = Pattern.compile(pattern).matcher(msg.getResponseBodyString());
                    if(matcher.find()) return true;
                    break;
                case CONTAIN_IN_REQUEST:
                    matcher = Pattern.compile(pattern).matcher(msg.getRequestString());
                    if(!matcher.find()) return true;
                    break;
                case NOT_CONTAIN_IN_REQUEST:
                    matcher = Pattern.compile(pattern).matcher(msg.getRequestString());
                    if(matcher.find()) return true;
                    break;
                default:
                    break;
            }

            switch (type) {
                case EQUAL_STATUSCODE_SAMPLE:
                    if(!pattern.equals(msg.getResponseInfo().getStatusCode()+"")) return true;
                    break;
                case NOT_EQUAL_STATUSCODE_SAMPLE:
                    if(pattern.equals(msg.getResponseInfo().getStatusCode()+"")) return true;
                    break;
                case CONTAIN_IN_HEADER_SAMPLE:
                    for(String header:msg.getResponseInfo().getHeaders()){
                        if(header.contains(pattern)){
                            isFind = true;
                            break;
                        }
                    }
                    if(!isFind) return true;
                    break;
                case NOT_CONTAIN_IN_HEADER_SAMPLE:
                    for(String header:msg.getResponseInfo().getHeaders()){
                        if(header.contains(pattern)){
                            isFind = true;
                            break;
                        }
                    }
                    if(isFind) return true;
                    break;
                case CONTAIN_IN_BODY_SAMPLE:
                    if(!msg.getResponseBodyString().contains(pattern)) return true;
                    break;
                case NOT_CONTAIN_IN_BODY_SAMPLE:
                    if(msg.getResponseBodyString().contains(pattern)) return true;
                    break;
                case CONTAIN_IN_REQUEST_SAMPLE:
                    if(!msg.getRequestString().contains(pattern)) return true;
                    break;
                case NOT_CONTAIN_IN_REQUEST_SAMPLE:
                    if(msg.getRequestString().contains(pattern)) return true;
                    break;
                default:
                    break;
            }
        }
        return false;
    }
}