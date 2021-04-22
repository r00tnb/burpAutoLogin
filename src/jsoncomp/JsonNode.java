package jsoncomp;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Stack;
import java.util.Vector;

import javax.swing.tree.TreeNode;
import javax.swing.tree.TreePath;

import jsoncomp.json.jsonstyle.JsonArray;
import jsoncomp.json.jsonstyle.JsonObject;

public class JsonNode implements TreeNode {
    private String key;
    private Object value;
    JsonNode parent;
    JsonNode leftChild;
    JsonNode rightBro;

    public JsonNode(Map.Entry<String, Object> entry, JsonNode parent, JsonNode leftChild, JsonNode rightBro) {
        this.key = entry.getKey();
        this.value = entry.getValue();
        this.parent = parent;
        this.leftChild = leftChild;
        this.rightBro = rightBro;
    }

    public JsonNode(String key, Object value, JsonNode parent, JsonNode leftChild, JsonNode rightBro) {
        this.key = key;
        this.value = value;
        this.parent = parent;
        this.leftChild = leftChild;
        this.rightBro = rightBro;
    }

    static public String randomKey(){
        String keyString = "0123456789abcdefghijklmnopqrstuvwxyz";
        String ret = "key_";
        for(int i=0;i<4;i++){
            ret += keyString.charAt((int)(Math.random()*keyString.length()));
        }
        return ret;
    }

    public boolean isRoot() {
        if (parent == null) {
            return true;
        }
        return false;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public void setValue(Object value) {
        this.value = value;
    }

    public boolean valueIsList() {
        if (value instanceof JsonArray) {
            return true;
        }
        return false;
    }

    public boolean valueIsObject() {
        if (value instanceof JsonObject) {
            return true;
        }
        return false;
    }

    public boolean valueIsNumber() {
        if (value instanceof Number) {
            return true;
        }
        return false;
    }

    public boolean valueIsString() {
        if (value instanceof String) {
            return true;
        }
        return false;
    }

    public boolean valueIsBoolean() {
        if (value instanceof Boolean) {
            return true;
        }
        return false;
    }

    public boolean valueIsNull() {
        if (value == null) {
            return true;
        }
        return false;
    }

    public String getkey() {
        return this.key;
    }

    public Object getValue() {
        return this.value;
    }

    public void removeSelf() {
        if(isRoot()) return;
        JsonNode bro = getLeftBrother();
        if(bro != null){
            bro.rightBro = this.rightBro;
        }else{
            parent.leftChild = this.rightBro;
        }
    }

    public JsonNode getLeftBrother(){
        if(isRoot()) return null;

        Enumeration<? extends JsonNode> e = parent.children();
        JsonNode temp;
        while(e.hasMoreElements()){
            temp = e.nextElement();
            if(temp.rightBro == this){
                return temp;
            }
        }
        return null;
    }

    public void append(String key, Object value) {
        JsonNode node = new JsonNode(key, value, null, null, null);
        if(isLeaf()){
            //在叶节点后面插入
            node.rightBro = this.rightBro;
            this.rightBro = node;
            node.parent = this.parent;
        }else{
            //非叶节点插入到第一个子节点
            node.rightBro = this.leftChild;
            this.leftChild = node;
            node.parent = this;
        }

        // if(valueIsList()){
        //     node.setKey("0");
        // }else if(!isRoot() && parent.valueIsList()){
        //     node.setKey(parent.getIndex(node)+"");
        // }
    }

    public JsonNode[] getPath(){// 获取根节点到该处节点所途径的节点数组
        JsonNode[] ret;
        Stack<JsonNode> nodes = new Stack<>();
        JsonNode temp = this;
        int c = 0;
        while(!temp.isRoot()){
            c++;
            nodes.push(temp);
            temp = temp.parent;
        }
        c++;
        nodes.push(temp);
        ret = new JsonNode[c];
        for(int i=0;i<c;i++){
            ret[i] = nodes.pop();
        }

        return ret;
    }

    @Override
    public JsonNode getChildAt(int index) {// index从0开始
        int i = 0;
        for(Enumeration<? extends JsonNode> e = children();e.hasMoreElements();){
            if(index == i){
                return e.nextElement();
            }else{
                e.nextElement();
                i++;
            }
        }
        return null;
    }

    @Override
    public int getChildCount() {
        int ret = 0;
        for(Enumeration<? extends JsonNode> e = children();e.hasMoreElements();e.nextElement()){
            ret++;
        }
        return ret;
    }

    @Override
    public int getIndex(TreeNode childNode) {
        if(!(childNode instanceof JsonNode)) return -1;
        JsonNode child = (JsonNode)childNode;
        int i = 0;
        for(Enumeration<? extends JsonNode> e = children();e.hasMoreElements();i++){
            if(child == e.nextElement()){
                return i;
            }
        }

        return -1;
    }

    @Override
    public boolean isLeaf() {
        if (leftChild == null && !valueIsList() && !valueIsObject()) {
            return true;
        }
        return false;
    }

    @Override
    public String toString() {
        // TODO Auto-generated method stub
        if(isRoot()){
            return valueIsString() ? "\"" + value + "\"" : (valueIsNull() ? "null" : value.toString());
        }else{
            return String.format("\"%s\": %s", key,
                valueIsString() ? "\"" + value + "\"" : (valueIsNull() ? "null" : value.toString()));
        }
        
    }

    @Override
    public boolean getAllowsChildren() {
        // TODO Auto-generated method stub
        return true;
    }

    @Override
    public Enumeration<? extends JsonNode> children() {
        // TODO Auto-generated method stub
        Vector<JsonNode> ret = new Vector<>();
        JsonNode temp = this.leftChild;
        while(temp != null){
            ret.add(temp);
            temp = temp.rightBro;
        }
        return ret.elements();
    }

    @Override
    public JsonNode getParent() {
        // TODO Auto-generated method stub
        return parent;
    }
}