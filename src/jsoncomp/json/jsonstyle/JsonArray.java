package jsoncomp.json.jsonstyle;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;

import jsoncomp.json.exception.JsonTypeException;
import jsoncomp.json.util.FormatUtil;


/**
 * JSON的数组形式
 * 数组是值（value）的有序集合。一个数组以“[”（左中括号）开始，“]”（右中括号）结束。值之间使用“,”（逗号）分隔。
 */
public class JsonArray {
    private List<Object> list = new ArrayList<>();

    /**
     * 添加元素并根据添加对象中的元素个数排序（个数多的在后面）,使用该方法会改变元素的位置
     * @param obj
     */
    public void add(Object obj) {
        list.add(obj);
        list.sort(new Comparator<Object>(){

            @Override
            public int compare(Object o1, Object o2) {
                // TODO Auto-generated method stub
                int count1 = -1, count2 = -1;
                if(o1 instanceof JsonObject){
                    count1 = ((JsonObject)o1).size();
                }else if(o1 instanceof JsonArray){
                    count1 = ((JsonArray)o1).size();
                }
                if(o2 instanceof JsonObject){
                    count2 = ((JsonObject)o2).size();
                }else if(o2 instanceof JsonArray){
                    count2 = ((JsonArray)o2).size();
                }
                if(count1 > count2){
                    return 1;
                }else if (count1 < count2){
                    return -1;
                }
                return 0;
            }
            
        });
    }

    /**
     * 在对象末尾添加元素
     * @param obj
     */
    public void push(Object obj){
        list.add(obj);
    }

    public Object get(int index) {
        return list.get(index);
    }

    public int size() {
        return list.size();
    }

    public void remove(Object obj){
        list.remove(obj);
    }

    public JsonObject getJsonObject(int index) {
        Object obj = list.get(index);
        if (!(obj instanceof JsonObject)) {
            throw new JsonTypeException("Type of value is not JsonObject");
        }

        return (JsonObject) obj;
    }

    public JsonArray getJsonArray(int index) {
        Object obj = list.get(index);
        if (!(obj instanceof JsonArray)) {
            throw new JsonTypeException("Type of value is not JsonArray");
        }

        return (JsonArray) obj;
    }

    @Override
    public String toString() {
        return FormatUtil.beautify(this);
    }

    public Iterator<Object> iterator() {
        return list.iterator();
    }
}
