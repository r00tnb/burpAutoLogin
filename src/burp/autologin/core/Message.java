package burp.autologin.core;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.SwingWorker;

import burp.BurpExtender;
import burp.ICookie;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.autologin.core.CookieJar.Cookie;

/**
 * 用于分析请求和响应
 */
public class Message implements IHttpRequestResponse {

    final public static String defaultHttpResponse = "HTTP/1.1 200 OK\r\n"+
                                                "Content-Type: text/plain;charset=UTF-8"+
                                                "Connection: close\r\n"+
                                                "X-Powered-By: Servlet/3.0\r\n"+
                                                "Content-Language: zh-CN\r\n"+
                                                "Content-Length: 16\r\n"+
                                                "\r\n"+
                                                "<black response>";

    private IRequestInfo requestInfo;
    private IResponseInfo responseInfo;
    private byte[] request;
    private byte[] response;
    private String host;
    private int port;
    private boolean https;

    private TokenSearchModel tokenSearchModel;

    /**
     * 同步更新消息响应
     * 
     * @param msg 待更新的消息对象
     */
    public static void refreshMessage(Message msg) {
        SwingWorker<Void, Void> worker = new SwingWorker<Void, Void>() {

            @Override
            protected Void doInBackground() throws Exception {
                // TODO Auto-generated method stub
                IHttpRequestResponse requestResponse = BurpExtender.callbacks.makeHttpRequest(msg.getHttpService(),
                        msg.getRequest());
                msg.setResponse(requestResponse.getResponse());
                return null;
            }

        };
        worker.execute();
        try {
            worker.get(3000, TimeUnit.MILLISECONDS);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    /**
     * 异步更新消息响应
     * @param msg 待更新的消息对象
     * @return 返回SwingWorker对象
     */
    public static SwingWorker<Void, Void> asyncRefreshMessage(Message msg){
        SwingWorker<Void, Void> worker = new SwingWorker<Void, Void>() {

            @Override
            protected Void doInBackground() throws Exception {
                // TODO Auto-generated method stub
                IHttpRequestResponse requestResponse = BurpExtender.callbacks.makeHttpRequest(msg.getHttpService(),
                        msg.getRequest());
                msg.setResponse(requestResponse.getResponse());
                return null;
            }

        };
        worker.execute();

        return worker;
    }

    /**判断请求是否是正确的HTTP请求格式 */
    public static boolean isRightRequest(byte[] request){
        return new String(request).matches("\\w+ /\\S* HTTPS?/\\d+\\.\\d+\\r\\n([\\w\\-]+:[ ]*.*\\r\\n)+\\r\\n[\\s\\S]*$");
    }
    /**判断请求是否是正确的HTTP响应格式 */
    public static boolean isRightResponse(byte[] response){
        return new String(response).matches("HTTPS?/\\d+\\.\\d+ \\d+ \\S*\\r\\n([\\w\\-]+:[ ]*.*\\r\\n)+\\r\\n[\\s\\S]*$");
    }

    public Message(IHttpRequestResponse message) {

        setMessage(message);
        this.tokenSearchModel = new TokenSearchModel(this);
    }

    public Message(byte[] request, String host, int port, boolean useHttps){
        this.host = host;
        this.port = port;
        this.https = useHttps;
        setRequest(request);

        this.response = Message.defaultHttpResponse.getBytes();
        this.responseInfo = BurpExtender.helpers.analyzeResponse(this.response);
        this.tokenSearchModel = new TokenSearchModel(this);
    }

    private void setMessage(IHttpRequestResponse message) {
        this.request = Arrays.copyOf(message.getRequest(), message.getRequest().length);
        if(message.getResponse() == null || message.getResponse().length == 0){
            this.response = Message.defaultHttpResponse.getBytes();
        }else{
            this.response = Arrays.copyOf(message.getResponse(), message.getResponse().length);
        }
        
        setHttpService(message.getHttpService());
        this.requestInfo = BurpExtender.helpers.analyzeRequest(this);
        this.responseInfo = BurpExtender.helpers.analyzeResponse(response);
    }

    /**
     * 从参数列表更新请求的参数，如果请求中不存在指定参数则增加该参数
     * @param paramList 更新参数列表
     */
    public void updateOrAddParams(List<IParameter> paramList){
        for(IParameter param:paramList){
            this.request = BurpExtender.helpers.addParameter(BurpExtender.helpers.removeParameter(request, param), param);
        }
        this.requestInfo = BurpExtender.helpers.analyzeRequest(this);
    }
    /**
     * 从参数列表更新请求的参数
     * @param paramList 更新参数列表
     */
    public void updateParams(List<IParameter> paramList){
        for(IParameter param:paramList){
            this.request = BurpExtender.helpers.updateParameter(request, param);
        }
        this.requestInfo = BurpExtender.helpers.analyzeRequest(this);
    }

    /**
     * 从cookie列表设置cookie
     * @param cookieList cookie列表
     */
    public void setCookie(List<Cookie> cookieList){
        if(cookieList == null){
            cookieList = new Vector<Cookie>();
        }

        List<String> headers = requestInfo.getHeaders();
        //remove cookie header
        for(int i=0;i<headers.size();i++){
            if(headers.get(i).startsWith("Cookie")){
                headers.remove(i);
                break;
            }
        }

        //make cookie header
        StringBuilder builder = new StringBuilder();
        builder.append("Cookie: ");
        for(Cookie cookie:cookieList){
            if(cookie.matches(getUrlPath())){
                builder.append(cookie.getName()+"="+cookie.getValue());
                builder.append("; ");
            }
        }
        if(!builder.toString().equals("Cookie: ")){
            builder.deleteCharAt(builder.length()-1);
            builder.deleteCharAt(builder.length()-1);
            headers.add(builder.toString());
        }
        
        setRequest(BurpExtender.helpers.buildHttpMessage(headers, Arrays.copyOfRange(request, requestInfo.getBodyOffset(), request.length)));
    }

    /**
     * 判断该消息是否是静态消息，如以.css, .js, .png为后缀的请求，以及响应体能识别为图片或脚本类型的消息，若响应头中包含Set-Cookie等session相关头部则不认为静态消息
     * @return 是静态消息返回true，否则返回false
     */
    public boolean isStaticMessage(){
        for(String header:responseInfo.getHeaders()){
            if(header.toLowerCase().startsWith("set-cookie")) return false;
        }

        if(getUrlPath().matches(".*(?i)(\\.css|\\.js|\\.png|\\.jpg|\\.jpeg|\\.xslx|\\.svg|\\.ico|\\.woff2|\\.gif|\\.woff)$")) return true;
        if(getMIMEType().toLowerCase().matches("script|css")) return true;
        return false;
    }

    public TokenSearchModel getTokenSearchModel() {
        return tokenSearchModel;
    }

    public int getPort() {
        return port;
    }

    public String getProtocol() {
        return https?"HTTPS":"HTTP";
    }

    public boolean isHttps() {
        return https;
    }

    public String getHost() {
        return host;
    }

    public String getDomain() {
        return getProtocol().toLowerCase()+"://"+getHost() + (!isNormal() ? ":" + getPort() : "")+"/";
    }

    public String getMethod() {
        return requestInfo.getMethod();
    }

    public String getUrlPath() {
        return requestInfo.getUrl().getPath();
    }

    public String getUrl() {
        return requestInfo.getUrl().toString();
    }

    public String getMIMEType() {
        String type = responseInfo.getInferredMimeType();
        return type.equals("") ? responseInfo.getStatedMimeType() : type;
    }

    public String getStatusInfo() {
        String result = "";
        Matcher matcher = Pattern.compile(" (\\d+ .*?)\\r\\n").matcher(getResponseString());
        if (matcher.find()) {
            result = matcher.group(1);
        }
        return result.equals("") ? responseInfo.getStatusCode() + "" : result;
    }

    public boolean isRequest(){
        if(response.length == 0){
            return true;
        }

        return false;
    }

    public String getResponseCharset() {
        Iterator<String> iterator = getResponseInfo().getHeaders().iterator();
        Pattern pattern = Pattern.compile("charset=([\\w-]+)");
        while (iterator.hasNext()) {
            String header = iterator.next();
            Matcher matcher = pattern.matcher(header);
            if (matcher.find()) {
                return matcher.group(1);
            }
        }
        return "UTF-8";
    }

    public String getRequestCharset() {
        Iterator<String> iterator = getRequestInfo().getHeaders().iterator();
        Pattern pattern = Pattern.compile("charset=([\\w-]+)");
        while (iterator.hasNext()) {
            String header = iterator.next();
            Matcher matcher = pattern.matcher(header);
            if (matcher.find()) {
                return matcher.group(1);
            }
        }
        return "UTF-8";
    }

    public String getResponseString() {
        String result = "";
        try {
            result = new String(response, getResponseCharset());
        } catch (UnsupportedEncodingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return result;
    }

    public String getResponseBodyString(){
        String result = "";
        byte[] body = Arrays.copyOfRange(response, responseInfo.getBodyOffset(), response.length);
        try {
            result = new String(body, getResponseCharset());
        } catch (UnsupportedEncodingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return result;
    }

    public String getRequestString() {
        String result = "";
        try {
            result = new String(request, getRequestCharset());
        } catch (UnsupportedEncodingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return result;
    }

    @Override
    public String toString() {
        // TODO Auto-generated method stub
        return getDomain();
    }

    public IRequestInfo getRequestInfo() {
        return requestInfo;
    }

    public IResponseInfo getResponseInfo() {
        return responseInfo;
    }

    /**
     * 判断该消息是否是常见端口协议的消息
     * @return 是返回true，否则返回false
     */
    public boolean isNormal() {
        if (getPort() == 80 && getProtocol().equals("HTTP") || getPort() == 443 && getProtocol().equals("HTTPS")) {
            return true;
        }

        return false;
    }

    @Override
    public byte[] getRequest() {
        // TODO Auto-generated method stub
        return request;
    }

    @Override
    public void setRequest(byte[] message) {
        // TODO Auto-generated method stub
        if(message == null || !Message.isRightRequest(message)) return;
        this.request = Arrays.copyOf(message, message.length);
        this.requestInfo = BurpExtender.helpers.analyzeRequest(this);
    }

    @Override
    public byte[] getResponse() {
        // TODO Auto-generated method stub
        return response;
    }

    @Override
    public void setResponse(byte[] message) {
        // TODO Auto-generated method stub
        if(message == null || !Message.isRightResponse(message)) return;
        this.response = Arrays.copyOf(message, message.length);
        this.responseInfo = BurpExtender.helpers.analyzeResponse(this.response);
    }

    @Override
    public String getComment() {
        // TODO Auto-generated method stub
        return "";
    }

    @Override
    public void setComment(String comment) {
        // TODO Auto-generated method stub

    }

    @Override
    public String getHighlight() {
        // TODO Auto-generated method stub
        return "";
    }

    @Override
    public void setHighlight(String color) {
        // TODO Auto-generated method stub

    }

    @Override
    public IHttpService getHttpService() {
        // TODO Auto-generated method stub
        return BurpExtender.helpers.buildHttpService(host, port, https);
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        // TODO Auto-generated method stub
        this.host = httpService.getHost();
        this.port = httpService.getPort();
        this.https = httpService.getProtocol().toLowerCase().equals("https");
    }
}