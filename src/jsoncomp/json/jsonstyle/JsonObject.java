package jsoncomp.json.jsonstyle;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import jsoncomp.json.exception.JsonTypeException;
import jsoncomp.json.util.FormatUtil;

public class JsonObject {
    private Map<String, Object> map = new HashMap<String, Object>();

    public void put(String key, Object value) {
        map.put(key, value);
    }

    public Object get(String key) {
        return map.get(key);
    }

    public void remove(String key){
        map.remove(key);
    }

    public int size(){
        return map.size();
    }

    public List<Map.Entry<String, Object>> getAllKeyValue() {
        ArrayList<Map.Entry<String, Object>> ret = new ArrayList<Map.Entry<String, Object>>(map.entrySet());
        ret.sort(new Comparator<Map.Entry<String, Object>>() {

            @Override
            public int compare(Entry<String, Object> o1, Entry<String, Object> o2) {
                // TODO Auto-generated method stub
                Object v1 = o1.getValue(), v2 = o2.getValue();
                int count1 = -1, count2 = -1;
                if(v1 instanceof JsonObject){
                    count1 = ((JsonObject)v1).size();
                }else if(v1 instanceof JsonArray){
                    count1 = ((JsonArray)v1).size();
                }
                if(v2 instanceof JsonObject){
                    count2 = ((JsonObject)v2).size();
                }else if(v2 instanceof JsonArray){
                    count2 = ((JsonArray)v2).size();
                }
                if(count1 > count2){
                    return 1;
                }else if (count1 < count2){
                    return -1;
                }
                return 0;
            }

        });
        return ret;
    }

    public JsonObject getJsonObject(String key) {
        if (!map.containsKey(key)) {
            throw new IllegalArgumentException("Invalid key");
        }

        Object obj = map.get(key);
        if (!(obj instanceof JsonObject)) {
            throw new JsonTypeException("Type of value is not JsonObject");
        }

        return (JsonObject) obj;
    }

    public JsonArray getJsonArray(String key) {
        if (!map.containsKey(key)) {
            throw new IllegalArgumentException("Invalid key");
        }

        Object obj = map.get(key);
        if (!(obj instanceof JsonArray)) {
            throw new JsonTypeException("Type of value is not JsonArray");
        }

        return (JsonArray) obj;
    }

    @Override
    public String toString() {
        return FormatUtil.beautify(this);
    }
}
