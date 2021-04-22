package burp.autologin.core;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import burp.Util.TempEntry;
import burp.autologin.core.Session.Token;

public class TokenSearchModel extends ConcurrentHashMap<Token, Pattern> {

    private Message message;

    public TokenSearchModel(Message message){
        this.message = message;
    }

    public boolean isExist(String tokenName){
        for(Entry<Token, Pattern>  entry:entrySet()){
            if(entry.getKey().getTokenName().equals(tokenName)){
                return true;
            }
        }
        return false;
    }

    public void remove(String tokenName){
        for(Entry<Token, Pattern>  entry:entrySet()){
            if(entry.getKey().getTokenName().equals(tokenName)){
                remove(entry.getKey());
                return;
            }
        }
    }

    /**
     * 搜索数据message中匹配的token
     * @return 返回Map对象， 键为搜索匹配后的token对象， 值为TempEntry对象（键为第一个匹配分组的开始索引， 值为第一个匹配分组的结束偏移）
     * @see TempEntry
     * @see Token
     */
    private Map<Token, TempEntry<Integer, Integer>> __searchToken(){
        String data = message.getResponseString();
        Map<Token, TempEntry<Integer, Integer>> result = new HashMap<>();
        for(Entry<Token, Pattern>  entry:entrySet()){
            Matcher matcher = entry.getValue().matcher(data);
            if(matcher.find() && matcher.groupCount()>0){
                TempEntry<Integer, Integer> indexs = new TempEntry<>();
                Token token = entry.getKey();
                token.setTokenValue(matcher.group(1));
                indexs.set(matcher.start(1), matcher.end(1));
                result.put(token, indexs);
            }
        }
        return result;
    }

    public List<Token> searchToken(){
        List<Token> result = new Vector<>();
        for(Entry<Token, TempEntry<Integer, Integer>> entry:__searchToken().entrySet()){
            result.add(entry.getKey());
        }
        return result;
    }

    public TempEntry<Integer, Integer> getMatchedTokenIndexs(String tokenName){
        for(Entry<Token, TempEntry<Integer, Integer>> entry:__searchToken().entrySet()){
            if(entry.getKey().getTokenName().equals(tokenName)){
                return entry.getValue();
            }
        }
        return new TempEntry<>();
    }

    public Map<Integer, Integer> searchTokenIndexs(){
        Map<Integer, Integer> result = new HashMap<>();
        for(Entry<Token, TempEntry<Integer, Integer>> entry:__searchToken().entrySet()){
            result.put(entry.getValue().getKey(), entry.getValue().getValue());
        }
        return result;
    }

}