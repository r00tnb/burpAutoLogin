package burp.Util;

import java.util.Map.Entry;

public class TempEntry<K, V> implements Entry<K, V> {

    private K key;
    private V value;

    public TempEntry(K key, V value){
        this.key = key;
        this.value = value;
    }

    public TempEntry(){
        this.key = null;
        this.value = null;
    }

    public void set(K key, V value){
        this.key = key;
        this.value = value;
    }

    public boolean isEmpty(){
        return key == null;
    }

    @Override
    public K getKey() {
        // TODO Auto-generated method stub
        return key;
    }

    public void setKey(K key) {
        this.key = key;
    }

    @Override
    public V getValue() {
        // TODO Auto-generated method stub
        return value;
    }

    @Override
    public V setValue(V value) {
        // TODO Auto-generated method stub
        this.value = value;
        return value;
    }
    
}