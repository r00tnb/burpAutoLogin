package jsoncomp;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Stack;
import java.util.Vector;
import java.util.Map.Entry;

import javax.swing.UIManager;
import javax.swing.event.EventListenerList;
import javax.swing.event.TreeModelEvent;
import javax.swing.event.TreeModelListener;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeModel;
import javax.swing.tree.TreePath;

import jsoncomp.json.JSONParser;
import jsoncomp.json.jsonstyle.JsonArray;
import jsoncomp.json.jsonstyle.JsonObject;

public class JsonModel implements TreeModel {

    JsonNode root;
    EventListenerList listenerList;

    public JsonModel(String jsonString) {
        this.listenerList = new EventListenerList();
        JSONParser parser = new JSONParser();
        Object json = null;
        try {
            json = parser.fromJSON(jsonString);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        this.root = createJsonTree("(ROOT)", json);
    }

    public JsonNode createJsonTree(String key, Object json){
        //构造树
        JsonNode node = new JsonNode(key, json, null, null, null);
        JsonNode temp = node;
        List<JsonNode> nodes = new Vector<>();
        if(json instanceof JsonObject){
            for(Map.Entry<String, Object> entry:((JsonObject)json).getAllKeyValue()){
                if(temp == node){
                    temp.leftChild = createJsonTree(entry.getKey(), entry.getValue());
                    temp.leftChild.parent = node;
                    temp = temp.leftChild;
                }else{
                    temp.rightBro = createJsonTree(entry.getKey(), entry.getValue());
                    temp.rightBro.parent = node;
                    temp = temp.rightBro;
                }
                nodes.add(temp);
            }
            for(int i=0;i<nodes.size()-1;i++){
                nodes.get(i).rightBro = nodes.get(i+1);
            }
        }else if(json instanceof JsonArray){
            Iterator<Object> iterator = ((JsonArray)json).iterator();
            int index = 0;
            while(iterator.hasNext()){
                if(temp == node){
                    temp.leftChild = createJsonTree(index+"", iterator.next());
                    temp.leftChild.parent = node;
                    temp = temp.leftChild;
                }else{
                    temp.rightBro = createJsonTree(index+"", iterator.next());
                    temp.rightBro.parent = node;
                    temp = temp.rightBro;
                }
                index++;
                nodes.add(temp);
            }
            for(int i=0;i<nodes.size()-1;i++){
                nodes.get(i).rightBro = nodes.get(i+1);
            }
        }
        return node;
    }

    @Override
    public Object getRoot() {
        // TODO Auto-generated method stub
        return root;
    }

    @Override
    public Object getChild(Object parent, int index) {
        // TODO Auto-generated method stub
        return ((JsonNode)parent).getChildAt(index);
    }

    @Override
    public int getChildCount(Object parent) {
        // TODO Auto-generated method stub
        return ((JsonNode)parent).getChildCount();
    }

    @Override
    public boolean isLeaf(Object node) {
        // TODO Auto-generated method stub
        return ((JsonNode)node).isLeaf();
    }

    @Override
    public void valueForPathChanged(TreePath path, Object newValue) {
        // TODO Auto-generated method stub
        //System.out.println(path.getLastPathComponent());
    }

    @Override
    public int getIndexOfChild(Object parent, Object child) {
        // TODO Auto-generated method stub
        if(!(child instanceof JsonNode)||!(parent instanceof JsonNode)) return -1;
        return ((JsonNode)parent).getIndex((JsonNode)child);
    }

    @Override
    public void addTreeModelListener(TreeModelListener l) {
        // TODO Auto-generated method stub
        listenerList.add(TreeModelListener.class, l);
    }

    @Override
    public void removeTreeModelListener(TreeModelListener l) {
        // TODO Auto-generated method stub
        listenerList.remove(TreeModelListener.class, l);
    }

    public void reload(){
        reload(root);
    }

    public void reload(JsonNode node){
        Object[] listeners = listenerList.getListenerList();
        TreeModelEvent e = null;
        JsonNode[] path = node.getPath();
        if(path.length == 0) return;
        for (int i = listeners.length-2; i>=0; i-=2) {
            if (listeners[i]==TreeModelListener.class) {
                // Lazily create the event:
                if (e == null)
                    e = new TreeModelEvent(this, path,null, null);
                ((TreeModelListener)listeners[i+1]).treeStructureChanged(e);
            }
        }
    }
    
}