package burp.autologin.core;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.Vector;
import java.util.Map.Entry;
import java.util.regex.Pattern;

import burp.IHttpRequestResponse;
import burp.Util.Util;
import burp.autologin.core.Session.Token;
import burp.autologin.core.SessionValidator.SessionValidatorType;
import burp.autologin.core.SessionValidator.ValidatorItem;
import burp.autologin.core.TokenReplaceModel.TokenReplace;
import jsoncomp.json.jsonstyle.JsonArray;
import jsoncomp.json.jsonstyle.JsonObject;

public class AutoLoginItem {
    private String domain;
    private boolean isEnabled;
    private String name;
    private Session session;

    /**
     * 通过jsonObject构造一个AutoLoginItem对象
     * @param itemObject 能被解析的jsonObject
     * @return 构造好的AutoLoginItem对象
     */
    public static AutoLoginItem fromJsonObject(JsonObject itemObject){
        AutoLoginItem item = new AutoLoginItem(Util.jsonString((String)itemObject.get("name"), true), 
            Util.jsonString((String)itemObject.get("domain"), true), (Boolean)itemObject.get("enabled"));

        //set session
        Session session = item.getSession();
        JsonObject sessionObject = (JsonObject)itemObject.get("session");

        //set session validator list
        JsonArray validatorListArray = (JsonArray)sessionObject.get("session_validator_list");
        if(validatorListArray != null){
            for(Iterator<Object> iterator=validatorListArray.iterator();iterator.hasNext();){
                JsonArray validatorItemListArray = (JsonArray)iterator.next();
                SessionValidator validator = new SessionValidator();
                for(Iterator<Object> iterator2=validatorItemListArray.iterator();iterator2.hasNext();){
                    JsonObject validatorItemObject = (JsonObject)iterator2.next();
                    validator.add(Util.jsonString((String)validatorItemObject.get("pattern"), true), 
                        SessionValidatorType.values()[(Integer)validatorItemObject.get("type")]);
                }
                session.getSessionValidatorList().add(validator);
            }
        }

        //set token replace model
        TokenReplaceModel tokenReplaceModel = session.getTokenReplaceModel();
        JsonArray tokenReplaceModelArray = (JsonArray)sessionObject.get("token_replace_model");
        if(tokenReplaceModelArray != null){
            for(Iterator<Object> iterator=tokenReplaceModelArray.iterator();iterator.hasNext();){
                JsonObject tokenReplaceObject = (JsonObject)iterator.next();
                if(tokenReplaceObject.get("default") != null){
                    tokenReplaceModel.setAllReplace(true);
                    continue;
                }
                tokenReplaceModel.append(session.getToken(Util.jsonString((String)tokenReplaceObject.get("token_name"), true)), 
                    Pattern.compile(Util.jsonString((String)tokenReplaceObject.get("pattern"), true)),
                        Util.jsonString((String)tokenReplaceObject.get("tips"), true), (Boolean)tokenReplaceObject.get("use_url_encode"));
            }
        }
        
        //set message
        List<Message> loginMessages = session.getLoginMessages();
        JsonArray loginMessagesArray = (JsonArray)sessionObject.get("message_list");
        if(loginMessagesArray != null){
            for(Iterator<Object> iterator=loginMessagesArray.iterator();iterator.hasNext();){
                JsonObject messageObject = (JsonObject)iterator.next();
                JsonArray tokenSearchModelArray = (JsonArray)messageObject.get("token_search_model");
                Message msg = new Message(Util.base64Decode((String)messageObject.get("request")).getBytes(),
                    Util.jsonString((String)messageObject.get("host"), true), (Integer)messageObject.get("port"), (Boolean)messageObject.get("https"));
                msg.setResponse(Util.base64Decode((String)messageObject.get("response")).getBytes());
                loginMessages.add(msg);
                TokenSearchModel tokenSearchModel = msg.getTokenSearchModel();
                //set token search model
                if(tokenSearchModelArray != null){
                    for(Iterator<Object> iterator2 = tokenSearchModelArray.iterator();iterator2.hasNext();){
                        JsonObject tokenSearchObject = (JsonObject)iterator2.next();
                        tokenSearchModel.put(session.getToken(Util.jsonString((String)tokenSearchObject.get("token_name"), true)), 
                            Pattern.compile(Util.jsonString((String)tokenSearchObject.get("pattern"), true)));
                    }
                }
            }
        }
        
        return item;
    }

    /**
     * 存储AutoLoginItem对象为jsonObject
     * @param item 被存储的AutoLoginItem对象
     * @return 处理后的jsonObject
     */
    public static JsonObject toJsonObject(AutoLoginItem item){
        JsonObject itemObject = new JsonObject();
        JsonObject sessionObject = new JsonObject();
        itemObject.put("name", Util.jsonString(item.getName(), false));
        itemObject.put("domain", Util.jsonString(item.getDomain(), false));
        itemObject.put("enabled", item.isEnabled());
        itemObject.put("session", sessionObject);

        // save session
        JsonArray tokenReplaceModelArray = new JsonArray();
        JsonArray messageArray = new JsonArray();
        JsonArray validatorListArray = new JsonArray();
        sessionObject.put("token_replace_model", tokenReplaceModelArray);
        sessionObject.put("message_list", messageArray);
        sessionObject.put("session_validator_list", validatorListArray);

        // save session validator list
        for(SessionValidator validator:item.getSession().getSessionValidatorList()){
            JsonArray validatorItemListArray = new JsonArray();
            for(ValidatorItem validatorItem:validator){
                JsonObject validatorItemObject = new JsonObject();
                validatorItemObject.put("pattern", Util.jsonString(validatorItem.getPattern(), false));
                validatorItemObject.put("type", validatorItem.getType().ordinal());

                validatorItemListArray.push(validatorItemObject);
            }

            validatorListArray.push(validatorItemListArray);
        }

        // save token replace model
        for (TokenReplace tokenReplace : item.getSession().getTokenReplaceModel()) {
            JsonObject tokenReplaceObject = new JsonObject();
            tokenReplaceObject.put("token_name", Util.jsonString(tokenReplace.getToken().getTokenName(), false));
            tokenReplaceObject.put("tips", Util.jsonString(tokenReplace.getTips(), false));
            tokenReplaceObject.put("pattern", Util.jsonString(tokenReplace.getPattern().pattern(), false));
            tokenReplaceObject.put("use_url_encode", tokenReplace.isUseUrlEncode());

            tokenReplaceModelArray.push(tokenReplaceObject);
        }
        if(item.getSession().getTokenReplaceModel().isAllReplace()){
            JsonObject tokenReplaceObject = new JsonObject();
            tokenReplaceObject.put("default", true);
            tokenReplaceModelArray.push(tokenReplaceObject);
        }

        // save message
        for (Message message : item.getSession().getLoginMessages()) {
            JsonObject messageObject = new JsonObject();
            JsonArray tokenSearchModelArray = new JsonArray();
            // save token search model
            for (Entry<Token, Pattern> entry : message.getTokenSearchModel().entrySet()) {
                JsonObject tokenSearchObject = new JsonObject();
                tokenSearchObject.put("token_name", Util.jsonString(entry.getKey().getTokenName(), false));
                tokenSearchObject.put("pattern", Util.jsonString(entry.getValue().pattern(), false));

                tokenSearchModelArray.push(tokenSearchObject);
            }

            messageObject.put("token_search_model", tokenSearchModelArray);
            messageObject.put("request", Util.base64Encode(message.getRequest()));
            messageObject.put("response", Util.base64Encode(message.getResponse()));
            messageObject.put("host", Util.jsonString(message.getHost(), false));
            messageObject.put("port", message.getPort());
            messageObject.put("https", message.isHttps());

            messageArray.push(messageObject);
        }

        return itemObject;
    }

    
    public AutoLoginItem(String name, String domain, boolean isEnabled){
        this.domain = domain;
        this.name = name;
        this.isEnabled = isEnabled;
        this.session = new Session(domain);
    }

    public AutoLoginItem(){
        this("test", "test.com", false);
    }

    @Override
    public String toString() {
        // TODO Auto-generated method stub
        return name;
    }

    public void setEnabled(boolean isEnabled) {
        this.isEnabled = isEnabled;
    }
    public void setDomain(String domain) {
        this.domain = domain;
    }

    public boolean isEnabled() {
        return isEnabled;
    }

    public void setName(String name) {
        this.name = name;
    }
    public String getName() {
        return name;
    }
    public String getDomain() {
        return domain;
    }

    public Session getSession() {
        return session;
    }
}