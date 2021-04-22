package burp.Util;

import java.awt.Dimension;
import java.util.Base64;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.JDialog;

import burp.BurpExtender;
import burp.autologin.resources.Text_zh_cn;

import java.awt.Toolkit;
import java.io.InputStream;
import java.io.InputStreamReader;

public class Util {
    private static Text_zh_cn text_zh_cn = new Text_zh_cn();

    public static String base64Encode(String data){
        return Base64.getEncoder().encodeToString(data.getBytes());
    }
    public static String base64Decode(String data){
        return new String(Base64.getDecoder().decode(data));
    }
    public static String base64Encode(byte[] data){
        return Base64.getEncoder().encodeToString(data);
    }
    public static String base64Decode(byte[] data){
        return new String(Base64.getDecoder().decode(data));
    }

    public static String urlEncode(String data){
        if(data == null) return "";
        return BurpExtender.helpers.urlEncode(data);
    }
    public static String urlDecode(String data){
        if(data == null) return "";
        return BurpExtender.helpers.urlDecode(data);
    }

    public static void setToCenter(JDialog dialog){
        Dimension size = dialog.getSize();
        Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();

        dialog.setLocation((int)(screenSize.getWidth()-size.getWidth())/2, (int)(screenSize.getHeight()-size.getHeight())/2);
    }

    /**
     * 将字符串转义为普通字符串用于正则匹配
     * @param data 可能包含特殊正则表达式的字符串 
     * @return 转义后的字符串
     */
    public static String normalString(String data){
        StringBuilder builder = new StringBuilder();
        String key = "?.*{}[]()$^\\+|";
        for(char c : data.toCharArray()){
            builder.append(c);
            for(char cc:key.toCharArray()){
                if(cc == c){
                    builder.deleteCharAt(builder.length()-1);
                    builder.append("\\"+c);
                    break;
                }
            }
        }
        return builder.toString();
    }

    /**
     * 将对字符串特殊字符进行转义，以便作为json字段用于存储。或从json字符串恢复正常的字符串
     * @param data 待处理字符串
     * @param isJson 传入字符串是否取自json数据
     * @return 处理后的字符串
     */
    public static String jsonString(String data, boolean isJson){
        if(isJson){
            data = data.replaceAll("\\\\\"", "\"");
            data = data.replaceAll("\\\\\\\\", "\\\\");
        }else{
            data = data.replaceAll("\\\\", "\\\\\\\\");
            data = data.replaceAll("\"", "\\\\\"");
        }

        return data;
    }

    /**
     * 返回可视化的字符串，对不可打印或空白字符进行转义
     * @param data
     * @return 返回可视化的字符串
     */
    public static String viewString(String data){
        StringBuilder builder = new StringBuilder();
        for(char c : data.toCharArray()){
            switch (c) {
                case '\f':
                    builder.append("\\f");
                    break;
                case '\n':
                    builder.append("\\n");
                    break;
                case '\b':
                    builder.append("\\b");
                    break;
                case '\t':
                    builder.append("\\t");
                    break;
                case '\r':
                    builder.append("\\r");
                    break;
                default:
                    if((c<30 && c >= -128) || c == 127){
                        builder.append("\\x"+normalHexForChar(c));
                    }else if(c<-128 || c>127) {
                        builder.append("\\u"+normalHexForChar(c));
                    }else{
                        builder.append(c);
                    }
                    break;
            }
        }
        return builder.toString();
    }

    static public String normalHexForChar(char c){
        String result = Integer.toHexString(c);
        int i = 2;
        if(c<-128 || c>127){
            i=4;
        }
        while(result.length()<i--) result = "0"+result;
        return result;
    }

    /**
     * 生成随机字符串， keywords = "0123456789abcdefABCEDF";
     * @param len 指定随机字符串位数
     * @return 返回指定位数的随机字符串
     */
    static public String randomString(int len){
        StringBuilder builder = new StringBuilder();
        len = len>0?len:1;
        String keywords = "0123456789abcdefABCEDF";
        for(int i=0, c=0;i<len;i++){
            c = (int)(Math.random()*keywords.length());
            builder.append(keywords.charAt(c));
        }
        return builder.toString();
    }

    /**
     * 替换给定字符串data中按pattern模式查找到的第一个分组的字符串为replacement
     * @param pattern 查找的正则表达式对象
     * @param data 被替换的字符串
     * @param replacement 用于替换第一个匹配分组的字符串
     * @return 匹配成功则返回替换后的字符串， 否则返回原字符串
     */
    static public String replaceFirstGroup(Pattern pattern, String data, String replacement){
        String result = data;
        Matcher matcher = pattern.matcher(data);
        if(matcher.find()){
            result = data.substring(0, matcher.start(1))+replacement+data.substring(matcher.end(1));
        }
        return result;
    }

    /**
     * 获取国际化字符串
     * @param key 关联国际化字符串的键
     * @return 国际化字符串
     */
    public static String l(String key){
        if(Locale.getDefault().getLanguage().equals("zh")){
            return text_zh_cn.getString(key);
        }else{
            return key.substring(0,1).toUpperCase()+key.substring(1);
        }
    }

    public static String getStringFromFile(String fileName) {//读取resource文件下的资源
        StringBuffer content = new StringBuffer();
        try {
            InputStream input = Util.class.getResourceAsStream(fileName);
            InputStreamReader reader = new InputStreamReader(input, "UTF8");
            char[] temp = new char[1024];
            while (reader.read(temp) != -1) {
                content.append(temp);
                temp = new char[1024];
            }
            input.close();
            reader.close();
        } catch (Exception e) {
            // TODO: handle exception
            e.printStackTrace();
        }
        return content.toString().trim();
    }

    /**
     * 对给定范围的字符串，生成搜索正则表达式。<br>
     * start，end指定字符串data的起始偏移，将生成正则表达式用于匹配范围内的子串
     * @param data 指定字符串
     * @param start 开始偏移
     * @param end 结束偏移
     * @return 用于匹配范围内子串的正则表达式,第一次匹配到分组为目标分组
     */
    public static Pattern getPatternFromSelectedBounds(String data, int start, int end){
        if(start == end || start>end || start<0 || data==null || end>data.length()) return null;
        String text = "", left = "", right = "";
        text = data.substring(start, end);
        if(text.charAt(text.length()-1) == '\r'){
            text = text.substring(0, text.length()-1);
            end = end-1;
        }
        left = data.substring(0, start);
        right = data.substring(end, data.length());
        
        int len = 5/* 目标子串两边边界的初始大小 */, step = 3;// 每次边界增加的大小
        while(len < data.length()){
            StringBuilder leftStr = new StringBuilder(), rightStr = new StringBuilder();
            for(int i=len, endIndex=0;i>0;i-=step){
                endIndex = left.length()-i+step;
                endIndex = endIndex>left.length()?left.length():endIndex;
                if(left.length()-i >= 0)
                    leftStr.append(left.substring(left.length()-i, endIndex));
                endIndex = len-i+step;
                endIndex = endIndex>right.length()?right.length():endIndex;
                if(len-i<right.length()){
                    rightStr.append(right.substring(len-i, endIndex));
                }
                    
            }
            Pattern pattern = Pattern.compile(Util.viewString(Util.normalString(leftStr.toString())+"([\\s\\S]*?)"+(end==data.length()?"$":"")+Util.normalString(rightStr.toString())));
            Matcher matcher = pattern.matcher(data);
            if(matcher.find() && matcher.start(1) == start && matcher.end(1) == end){//保证第一次匹配到分组为目标分组
                return pattern;
            }
            len += step;
        }
        return null;
    }
}