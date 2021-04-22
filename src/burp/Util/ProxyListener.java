package burp.Util;

import java.util.List;
import java.util.Vector;

import burp.BurpExtender;
import burp.IInterceptedProxyMessage;
import burp.IProxyListener;

public final class ProxyListener implements IProxyListener {

    private static ProxyListener proxyListener = null;

    public static ProxyListener getProxyListener(){
        if(ProxyListener.proxyListener == null){
            ProxyListener.proxyListener = new ProxyListener();
        }
        
        return ProxyListener.proxyListener;
    }

    private List<ProxyHandler> handlerList;

    private ProxyListener(){
        this.handlerList = new Vector<>();
    }

    public void addHandler(ProxyHandler handler){
        if(handlerList.indexOf(handler) != -1) return;// handler不重复添加
        this.handlerList.add(handler);
    }
    public void removeHandler(ProxyHandler handler){
        this.handlerList.remove(handler);
    }
    public void removeHandler(int index){
        this.handlerList.remove(index);
    }
    public ProxyHandler pop(){
        return this.handlerList.remove(handlerList.size()-1);
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        // TODO Auto-generated method stub
        synchronized(handlerList){
            for(ProxyHandler handler:this.handlerList){
                handler.handle(messageIsRequest, message);
            }
        }
    }
    
}